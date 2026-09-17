//! 受管网关的本地分流 HTTP 代理。
//!
//! 存在理由：发出模型与 OpenAI 请求的是 codex 引擎（`codex.exe app-server`，reqwest），
//! 它不认 Chromium 的 `--proxy-pac-url`，只认代理环境变量。本模块提供一个仅绑回环的
//! HTTP 代理，把原 PAC 脚本里的域名判定搬到进程内执行：
//!
//! - 命中 OpenAI 域名规则 → 经上游 SOCKS5 建隧道
//! - 网关与其他目标 → 直连转发
//! - 命中规则但上游不可用 → 502，**绝不回退直连**
//!
//! 两种代理语义都必须支持：CONNECT（HTTPS 目标）与绝对 URI（网关是明文 HTTP）。

/// 代理请求的两种形态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyRequestKind {
    /// `CONNECT host:443 HTTP/1.1`，建隧道后不解密。
    Connect,
    /// `GET http://host:8080/path HTTP/1.1`，绝对 URI 明文转发。
    Plain,
}

/// 解析出的目标。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyTarget {
    pub host: String,
    pub port: u16,
    pub kind: ProxyRequestKind,
}

/// 解析代理请求首行。无法识别时返回 `None`，由调用方回 400。
///
/// 只看首行：不解析请求头，也不碰 body。
pub fn parse_proxy_request_line(line: &str) -> Option<ProxyTarget> {
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;
    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_host_port(target, 443)?;
        return Some(ProxyTarget {
            host,
            port,
            kind: ProxyRequestKind::Connect,
        });
    }
    // 明文代理只接受绝对 URI；origin-form 说明对方把我们当普通服务器，不属代理语义。
    let rest = strip_http_scheme(target)?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    if authority.is_empty() {
        return None;
    }
    let (host, port) = split_host_port(authority, 80)?;
    Some(ProxyTarget {
        host,
        port,
        kind: ProxyRequestKind::Plain,
    })
}

fn strip_http_scheme(target: &str) -> Option<&str> {
    let lower = target.to_ascii_lowercase();
    if lower.starts_with("http://") {
        return Some(&target["http://".len()..]);
    }
    // 引擎对 HTTPS 目标一律用 CONNECT，这里不接受 https 绝对 URI。
    None
}

/// 拆主机与端口，兼容 IPv6 字面量 `[::1]:443`。
fn split_host_port(input: &str, default_port: u16) -> Option<(String, u16)> {
    let input = input.trim();
    if input.is_empty() {
        return None;
    }
    if let Some(rest) = input.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        if host.is_empty() {
            return None;
        }
        let port = match tail.strip_prefix(':') {
            Some(port_text) => port_text.parse().ok()?,
            None => default_port,
        };
        return Some((host.to_ascii_lowercase(), port));
    }
    match input.rsplit_once(':') {
        // 带端口：主机不得为空，也不得含冗余冒号（裸写 IPv6 必须带方括号）。
        Some((host, port_text)) => {
            if host.is_empty() || host.contains(':') {
                return None;
            }
            let port = port_text.parse().ok()?;
            Some((host.to_ascii_lowercase(), port))
        }
        None => Some((input.to_ascii_lowercase(), default_port)),
    }
}

/// 分流结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteDecision {
    /// 经上游 SOCKS5。失败时必须 502，不得降级直连。
    Socks5,
    /// 直连转发。
    Direct,
}

/// 主机分流判定。直接复用 PAC 规则函数，不弄第二份真相。
pub fn route_for_host(host: &str) -> RouteDecision {
    let normalized = crate::managed_gateway::normalize_pac_host(host);
    if is_never_proxied(&normalized) {
        return RouteDecision::Direct;
    }
    if crate::managed_gateway::pac_result_for_host(&normalized)
        == crate::managed_gateway::MANAGED_GATEWAY_SOCKS5_RESULT
    {
        RouteDecision::Socks5
    } else {
        RouteDecision::Direct
    }
}

/// 网关自身与回环地址永不进代理上游，否则会把模型请求推进 SOCKS5 绕一大圈。
fn is_never_proxied(host: &str) -> bool {
    host == crate::managed_gateway::MANAGED_GATEWAY_SOCKS5_HOST
        || host == "127.0.0.1"
        || host == "localhost"
        || host == "::1"
}

/// SOCKS5 无认证握手问候：VER=5, NMETHODS=1, METHOD=0x00。
pub fn build_socks5_greeting() -> [u8; 3] {
    [0x05, 0x01, 0x00]
}

/// SOCKS5 CONNECT 请求，固定用域名寻址（ATYP=0x03）。
///
/// 不在本地解析 DNS：交由上游解析，与 PAC 时代的行为一致，也避开本地 DNS 污染。
pub fn build_socks5_connect_request(host: &str, port: u16) -> anyhow::Result<Vec<u8>> {
    let host_bytes = host.as_bytes();
    if host_bytes.is_empty() {
        anyhow::bail!("SOCKS5 目标主机为空");
    }
    let host_len = u8::try_from(host_bytes.len())
        .map_err(|_| anyhow::anyhow!("SOCKS5 目标主机过长：{} 字节", host_bytes.len()))?;
    let mut request = Vec::with_capacity(7 + host_bytes.len());
    request.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host_len]);
    request.extend_from_slice(host_bytes);
    request.extend_from_slice(&port.to_be_bytes());
    Ok(request)
}

/// 校验方法协商应答。只接受无认证；要求认证就当失败处理（不降级直连）。
pub fn parse_socks5_method_reply(bytes: &[u8]) -> anyhow::Result<()> {
    if bytes.len() < 2 {
        anyhow::bail!("SOCKS5 方法应答长度不足");
    }
    if bytes[0] != 0x05 {
        anyhow::bail!("SOCKS5 版本不支持：0x{:02x}", bytes[0]);
    }
    if bytes[1] != 0x00 {
        anyhow::bail!("SOCKS5 上游要求认证方法 0x{:02x}", bytes[1]);
    }
    Ok(())
}

/// 校验 CONNECT 应答。REP≠0x00 一律视为上游失败。
pub fn parse_socks5_connect_reply(bytes: &[u8]) -> anyhow::Result<()> {
    if bytes.len() < 2 {
        anyhow::bail!("SOCKS5 CONNECT 应答长度不足");
    }
    if bytes[0] != 0x05 {
        anyhow::bail!("SOCKS5 版本不支持：0x{:02x}", bytes[0]);
    }
    match bytes[1] {
        0x00 => Ok(()),
        code => anyhow::bail!("SOCKS5 上游拒绍：{}", socks5_reply_message(code)),
    }
}

fn socks5_reply_message(code: u8) -> &'static str {
    match code {
        0x01 => "上游一般性故障",
        0x02 => "规则不允许",
        0x03 => "网络不可达",
        0x04 => "主机不可达",
        0x05 => "连接被拒绝",
        0x06 => "TTL 过期",
        0x07 => "不支持的命令",
        0x08 => "不支持的地址类型",
        _ => "未知错误",
    }
}

/// SOCKS5 CONNECT 应答的总长度（含绑定地址）。用于知道该读多少字节。
///
/// 返回 `None` 表示目前字节还不够判定。
pub fn socks5_connect_reply_len(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 5 {
        return None;
    }
    let addr_len = match bytes[3] {
        0x01 => 4,
        0x03 => 1 + usize::from(bytes[4]),
        0x04 => 16,
        _ => return None,
    };
    Some(4 + addr_len + 2)
}

/// 上游连接与握手的超时。宁可快失败，不拖死调用方。
const UPSTREAM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// 自识端点路径与标识，用于判定已占用的端口是不是本工具自己的旧实例。
pub const MANAGED_PROXY_ID_PATH: &str = "/__managed_proxy_id";
pub const MANAGED_PROXY_ID_BODY: &str = "codex-plus-plus-managed-proxy";

/// 经上游 SOCKS5 建立到目标的隧道。失败则返回错误，**调用方不得回退直连**。
pub async fn connect_via_socks5(host: &str, port: u16) -> anyhow::Result<tokio::net::TcpStream> {
    connect_via_socks5_at(
        crate::managed_gateway::MANAGED_GATEWAY_SOCKS5_HOST,
        crate::managed_gateway::MANAGED_GATEWAY_SOCKS5_PORT,
        host,
        port,
    )
    .await
}

/// 指定上游地址的版本，供测试注入假 SOCKS5 服务器。
pub async fn connect_via_socks5_at(
    upstream_host: &str,
    upstream_port: u16,
    host: &str,
    port: u16,
) -> anyhow::Result<tokio::net::TcpStream> {
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    let mut stream = tokio::time::timeout(
        UPSTREAM_TIMEOUT,
        tokio::net::TcpStream::connect((upstream_host, upstream_port)),
    )
    .await
    .map_err(|_| anyhow::anyhow!("SOCKS5 上游连接超时"))??;

    tokio::time::timeout(UPSTREAM_TIMEOUT, async {
        stream.write_all(&build_socks5_greeting()).await?;
        let mut method_reply = [0u8; 2];
        stream.read_exact(&mut method_reply).await?;
        parse_socks5_method_reply(&method_reply)?;

        stream
            .write_all(&build_socks5_connect_request(host, port)?)
            .await?;
        let mut head = [0u8; 5];
        stream.read_exact(&mut head).await?;
        parse_socks5_connect_reply(&head)?;
        let total = socks5_connect_reply_len(&head)
            .ok_or_else(|| anyhow::anyhow!("SOCKS5 应答地址类型未知"))?;
        let mut rest = vec![0u8; total.saturating_sub(head.len())];
        if !rest.is_empty() {
            stream.read_exact(&mut rest).await?;
        }
        Ok::<(), anyhow::Error>(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("SOCKS5 握手超时"))??;

    Ok(stream)
}

/// 代理运行参数。上游可注入，否则用固定的受管 SOCKS5 地址。
#[derive(Debug, Clone)]
pub struct ManagedProxyConfig {
    pub socks5_host: String,
    pub socks5_port: u16,
}

impl Default for ManagedProxyConfig {
    fn default() -> Self {
        Self {
            socks5_host: crate::managed_gateway::MANAGED_GATEWAY_SOCKS5_HOST.to_string(),
            socks5_port: crate::managed_gateway::MANAGED_GATEWAY_SOCKS5_PORT,
        }
    }
}

/// 已启动的代理句柄。持有它就等于保活监听任务。
#[derive(Debug)]
pub struct ManagedProxyHandle {
    pub port: u16,
    task: tokio::task::JoinHandle<()>,
}

impl ManagedProxyHandle {
    /// 仅供测试：主动停掉监听，验证 fail-closed 行为。
    pub fn abort(&self) {
        self.task.abort();
    }
}

/// 在固定回环端口上启动分流代理。
///
/// 只绑 `127.0.0.1`：不对外暴露，也不做鉴权（与本机代理工具同类风险面）。
pub async fn spawn_managed_proxy(port: u16) -> anyhow::Result<ManagedProxyHandle> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .map_err(|error| anyhow::anyhow!("受管代理无法监听 127.0.0.1:{port}：{error}"))?;
    Ok(spawn_managed_proxy_with(
        listener,
        ManagedProxyConfig::default(),
    ))
}

/// 用现成监听器与自定义上游启动，供集成测试使用。
pub fn spawn_managed_proxy_with(
    listener: tokio::net::TcpListener,
    config: ManagedProxyConfig,
) -> ManagedProxyHandle {
    let port = listener.local_addr().map(|addr| addr.port()).unwrap_or(0);
    let _ = crate::diagnostic_log::append_diagnostic_log(
        "managed_proxy.listening",
        serde_json::json!({ "port": port }),
    );
    let task = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let config = config.clone();
                    tokio::spawn(async move {
                        if let Err(error) = handle_connection(stream, &config).await {
                            let _ = crate::diagnostic_log::append_diagnostic_log(
                                "managed_proxy.connection_failed",
                                serde_json::json!({ "message": error.to_string() }),
                            );
                        }
                    });
                }
                Err(error) => {
                    let _ = crate::diagnostic_log::append_diagnostic_log(
                        "managed_proxy.accept_failed",
                        serde_json::json!({ "message": error.to_string() }),
                    );
                    break;
                }
            }
        }
    });
    ManagedProxyHandle { port, task }
}

/// 读到空行为止的请求头上限。超过就当畸形请求拒接。
const MAX_HEADER_BYTES: usize = 32 * 1024;

async fn handle_connection(
    mut client: tokio::net::TcpStream,
    config: &ManagedProxyConfig,
) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;

    let started = std::time::Instant::now();
    let header = read_header_block(&mut client).await?;
    let first_line = header
        .split("\r\n")
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();

    // 自识端点：用 origin-form 请求，不进代理路径。
    if is_self_identify_request(&first_line) {
        let body = MANAGED_PROXY_ID_BODY;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        client.write_all(response.as_bytes()).await?;
        return Ok(());
    }

    let Some(target) = parse_proxy_request_line(&first_line) else {
        client
            .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await?;
        anyhow::bail!("无法识别的代理请求首行");
    };

    let decision = route_for_host(&target.host);
    let upstream = match decision {
        RouteDecision::Socks5 => {
            connect_via_socks5_at(
                &config.socks5_host,
                config.socks5_port,
                &target.host,
                target.port,
            )
            .await
        }
        RouteDecision::Direct => tokio::time::timeout(
            UPSTREAM_TIMEOUT,
            tokio::net::TcpStream::connect((target.host.as_str(), target.port)),
        )
        .await
        .map_err(|_| anyhow::anyhow!("目标连接超时"))
        .and_then(|result| result.map_err(anyhow::Error::from)),
    };

    let mut upstream = match upstream {
        Ok(stream) => stream,
        Err(error) => {
            // 命中规则却连不上上游时，只能 502；回退直连会泄露流量。
            log_route(&target, decision, false, started);
            let _ = client
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            return Err(error);
        }
    };

    log_route(&target, decision, true, started);

    match target.kind {
        ProxyRequestKind::Connect => {
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
        }
        ProxyRequestKind::Plain => {
            let rewritten = rewrite_to_origin_form(&header)?;
            upstream.write_all(rewritten.as_bytes()).await?;
        }
    }

    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Ok(())
}

fn is_self_identify_request(first_line: &str) -> bool {
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    method.eq_ignore_ascii_case("GET") && path == MANAGED_PROXY_ID_PATH
}

/// 诊断日志只记主机、端口、决策与耗时。**不记请求头、URL query 与 body**，
/// 避免把 Authorization 或会话内容写进日志。
fn log_route(
    target: &ProxyTarget,
    decision: RouteDecision,
    upstream_ok: bool,
    started: std::time::Instant,
) {
    let _ = crate::diagnostic_log::append_diagnostic_log(
        "managed_proxy.route",
        serde_json::json!({
            "host": target.host,
            "port": target.port,
            "kind": match target.kind {
                ProxyRequestKind::Connect => "connect",
                ProxyRequestKind::Plain => "plain",
            },
            "decision": match decision {
                RouteDecision::Socks5 => "socks5",
                RouteDecision::Direct => "direct",
            },
            "upstream_ok": upstream_ok,
            "duration_ms": started.elapsed().as_millis(),
        }),
    );
}

/// 读至空行。返回包含结尾 `\r\n\r\n` 的完整头块。
async fn read_header_block(stream: &mut tokio::net::TcpStream) -> anyhow::Result<String> {
    use tokio::io::AsyncReadExt;

    let mut buffer = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let read = stream.read(&mut byte).await?;
        if read == 0 {
            anyhow::bail!("客户端在请求头完成前关闭");
        }
        buffer.push(byte[0]);
        if buffer.ends_with(b"\r\n\r\n") {
            break;
        }
        if buffer.len() > MAX_HEADER_BYTES {
            anyhow::bail!("请求头超过 {MAX_HEADER_BYTES} 字节");
        }
    }
    Ok(String::from_utf8_lossy(&buffer).to_string())
}

/// 把绝对 URI 首行改写成 origin-form，其余头原样保留。
fn rewrite_to_origin_form(header: &str) -> anyhow::Result<String> {
    let (first_line, rest) = header
        .split_once("\r\n")
        .ok_or_else(|| anyhow::anyhow!("请求头缺少首行结尾"))?;
    let mut parts = first_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("请求首行缺少方法"))?;
    let uri = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("请求首行缺少 URI"))?;
    let version = parts.next().unwrap_or("HTTP/1.1");
    let path = origin_form_path(uri);
    Ok(format!("{method} {path} {version}\r\n{rest}"))
}

/// 从绝对 URI 取 path + query，保留查询串。
fn origin_form_path(uri: &str) -> String {
    let without_scheme = uri.strip_prefix("http://").unwrap_or(uri);
    match without_scheme.find('/') {
        Some(index) => without_scheme[index..].to_string(),
        None => "/".to_string(),
    }
}

/// 受管代理的默认固定端口。
///
/// 固定而非动态：`.env` 是持久文件，而 codex 进程的寿命与本工具不一致，
/// 动态端口会让文件里的地址与实际监听对不上。
pub const DEFAULT_MANAGED_PROXY_PORT: u16 = 17891;

/// 解析受管代理端口，允许环境变量覆盖。非法值退回默认值。
pub fn managed_proxy_port() -> u16 {
    std::env::var("CODEX_PLUS_MANAGED_PROXY_PORT")
        .ok()
        .and_then(|value| value.trim().parse::<u16>().ok())
        .filter(|port| *port != 0)
        .unwrap_or(DEFAULT_MANAGED_PROXY_PORT)
}

/// 探测已占用的端口是否是本工具自己的受管代理旧实例。
///
/// 命中则可直接复用；不命中就报错阻断启动，而不是默默换端口（换端口会与 `.env` 不一致）。
pub async fn probe_existing_managed_proxy(port: u16) -> bool {
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    let probe = async {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.ok()?;
        let request =
            format!("GET {MANAGED_PROXY_ID_PATH} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.ok()?;
        let mut response = String::new();
        stream.read_to_string(&mut response).await.ok()?;
        Some(response.contains(MANAGED_PROXY_ID_BODY))
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), probe)
        .await
        .ok()
        .flatten()
        .unwrap_or(false)
}

/// 进程内唯一的代理实例。保活监听任务，并防止重复启动。
static RUNNING_PROXY: std::sync::OnceLock<ManagedProxyHandle> = std::sync::OnceLock::new();

/// 确保受管代理已就绪，返回实际生效的端口。
///
/// 三种情形：本进程已启→直接复用；端口上是旧实例→复用；否则新建。
/// 端口被无关进程占用时直接报错，由调用方阻断启动。
pub async fn ensure_managed_proxy_running() -> anyhow::Result<u16> {
    if let Some(handle) = RUNNING_PROXY.get() {
        return Ok(handle.port);
    }
    let port = managed_proxy_port();
    if probe_existing_managed_proxy(port).await {
        let _ = crate::diagnostic_log::append_diagnostic_log(
            "managed_proxy.reused_existing",
            serde_json::json!({ "port": port }),
        );
        return Ok(port);
    }
    let handle = spawn_managed_proxy(port).await.map_err(|error| {
        let _ = crate::diagnostic_log::append_diagnostic_log(
            "managed_proxy.port_conflict",
            serde_json::json!({ "port": port, "message": error.to_string() }),
        );
        anyhow::anyhow!(
            "受管代理端口 {port} 不可用（且不是本工具的旧实例）：{error}。\
             请释放该端口，或用 CODEX_PLUS_MANAGED_PROXY_PORT 指定其他端口"
        )
    })?;
    let port = handle.port;
    let _ = RUNNING_PROXY.set(handle);
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect_with_explicit_port() {
        let target = parse_proxy_request_line("CONNECT chatgpt.com:443 HTTP/1.1").expect("parsed");
        assert_eq!(target.host, "chatgpt.com");
        assert_eq!(target.port, 443);
        assert_eq!(target.kind, ProxyRequestKind::Connect);
    }

    #[test]
    fn connect_without_port_defaults_to_443() {
        let target = parse_proxy_request_line("CONNECT auth.openai.com HTTP/1.1").expect("parsed");
        assert_eq!(target.port, 443);
    }

    #[test]
    fn parses_absolute_uri_with_port_and_query() {
        let line = "GET http://10.20.30.61:8080/models?client_version=0.154.0 HTTP/1.1";
        let target = parse_proxy_request_line(line).expect("parsed");
        assert_eq!(target.host, "10.20.30.61");
        assert_eq!(target.port, 8080);
        assert_eq!(target.kind, ProxyRequestKind::Plain);
    }

    #[test]
    fn absolute_uri_without_port_defaults_to_80() {
        let target =
            parse_proxy_request_line("POST http://example.com/api HTTP/1.1").expect("parsed");
        assert_eq!(target.port, 80);
    }

    #[test]
    fn parses_ipv6_literal() {
        let target = parse_proxy_request_line("CONNECT [::1]:8443 HTTP/1.1").expect("parsed");
        assert_eq!(target.host, "::1");
        assert_eq!(target.port, 8443);
    }

    #[test]
    fn method_is_case_insensitive() {
        let target = parse_proxy_request_line("connect chatgpt.com:443 HTTP/1.1").expect("parsed");
        assert_eq!(target.kind, ProxyRequestKind::Connect);
    }

    #[test]
    fn rejects_origin_form_and_garbage() {
        assert!(parse_proxy_request_line("GET /models HTTP/1.1").is_none());
        assert!(parse_proxy_request_line("GET").is_none());
        assert!(parse_proxy_request_line("").is_none());
        assert!(parse_proxy_request_line("CONNECT :443 HTTP/1.1").is_none());
    }

    #[test]
    fn openai_hosts_route_through_socks5() {
        for host in [
            "chatgpt.com",
            "auth.openai.com",
            "api.openai.com",
            "cdn.oaistatic.com",
        ] {
            assert_eq!(
                route_for_host(host),
                RouteDecision::Socks5,
                "host should be proxied: {host}"
            );
        }
    }

    #[test]
    fn gateway_and_loopback_always_direct() {
        for host in ["10.20.30.61", "127.0.0.1", "localhost", "::1"] {
            assert_eq!(
                route_for_host(host),
                RouteDecision::Direct,
                "host must never be proxied: {host}"
            );
        }
    }

    #[test]
    fn unrelated_hosts_go_direct() {
        for host in ["github.com", "registry.npmjs.org", "example.com"] {
            assert_eq!(route_for_host(host), RouteDecision::Direct);
        }
    }

    #[test]
    fn routing_is_case_insensitive() {
        assert_eq!(route_for_host("ChatGPT.com"), RouteDecision::Socks5);
    }

    #[test]
    fn builds_no_auth_greeting() {
        assert_eq!(build_socks5_greeting(), [0x05, 0x01, 0x00]);
    }

    #[test]
    fn builds_domain_connect_request() {
        let request = build_socks5_connect_request("chatgpt.com", 443).expect("built");
        assert_eq!(&request[..5], &[0x05, 0x01, 0x00, 0x03, 11]);
        assert_eq!(&request[5..16], b"chatgpt.com");
        assert_eq!(&request[16..], &[0x01, 0xbb]); // 443 大端
    }

    #[test]
    fn rejects_empty_and_overlong_host() {
        assert!(build_socks5_connect_request("", 443).is_err());
        let long_host = "a".repeat(256);
        assert!(build_socks5_connect_request(&long_host, 443).is_err());
        let max_host = "a".repeat(255);
        assert!(build_socks5_connect_request(&max_host, 443).is_ok());
    }

    #[test]
    fn accepts_no_auth_method_reply_only() {
        assert!(parse_socks5_method_reply(&[0x05, 0x00]).is_ok());
        assert!(parse_socks5_method_reply(&[0x05, 0x02]).is_err());
        assert!(parse_socks5_method_reply(&[0x04, 0x00]).is_err());
        assert!(parse_socks5_method_reply(&[0x05]).is_err());
    }

    #[test]
    fn maps_connect_reply_codes() {
        assert!(parse_socks5_connect_reply(&[0x05, 0x00, 0x00, 0x01]).is_ok());
        let refused = parse_socks5_connect_reply(&[0x05, 0x05, 0x00, 0x01]).expect_err("refused");
        assert!(refused.to_string().contains("连接被拒绝"));
        let unreachable =
            parse_socks5_connect_reply(&[0x05, 0x03, 0x00, 0x01]).expect_err("unreachable");
        assert!(unreachable.to_string().contains("网络不可达"));
    }

    #[test]
    fn computes_connect_reply_length_per_address_type() {
        assert_eq!(
            socks5_connect_reply_len(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]),
            Some(10)
        );
        assert_eq!(
            socks5_connect_reply_len(&[0x05, 0x00, 0x00, 0x03, 3, b'a', b'b', b'c', 0, 0]),
            Some(10)
        );
        assert_eq!(socks5_connect_reply_len(&[0x05, 0x00]), None);
    }
}
