//! Windows 受管模型网关与 OpenAI PAC 分流。
//! 设计文档：docs/superpowers/specs/2026-09-16-windows-managed-gateway-pac-design.md
//!
//! 本模块承载：
//! - OpenAI 域名规则快照与 PAC 匹配纯函数
//! - 受管 provider 配置校正（model_providers.managed_gateway）
//! - 外部 model_catalog_json 指针检测与移除
//! - 网关 API Key 验证与凭据保存编排

pub const MANAGED_GATEWAY_BASE_URL: &str = "http://10.20.30.61:8080";
pub const MANAGED_GATEWAY_SOCKS5_HOST: &str = "10.20.30.61";
pub const MANAGED_GATEWAY_SOCKS5_PORT: u16 = 7891;
pub const MANAGED_GATEWAY_SOCKS5_RESULT: &str = "SOCKS5 10.20.30.61:7891";

/// 精确域名（来自 BlackMatrix7 OpenAI Clash 规则 2025-06-06 域名类快照）。
const EXACT_DOMAINS: &[&str] = &[
    "browser-intake-datadoghq.com",
    "chat.openai.com.cdn.cloudflare.net",
    "openai-api.arkoselabs.com",
    "openaicom-api-bdcpf8c6d2e9atf6.z01.azurefd.net",
    "openaicomproductionae4b.blob.core.windows.net",
    "production-openaicom-storage.azureedge.net",
    "static.cloudflareinsights.com",
];

/// 域名后缀（匹配根域名及其所有子域名，按 DNS 标签边界）。
const DOMAIN_SUFFIXES: &[&str] = &[
    "ai.com",
    "algolia.net",
    "api.statsig.com",
    "auth0.com",
    "chatgpt.com",
    "chatgpt.livekit.cloud",
    "client-api.arkoselabs.com",
    "events.statsigapi.net",
    "featuregates.org",
    "host.livekit.cloud",
    "identrust.com",
    "intercom.io",
    "intercomcdn.com",
    "launchdarkly.com",
    "oaistatic.com",
    "oaiusercontent.com",
    "observeit.net",
    "openai.com",
    "openaiapi-site.azureedge.net",
    "openaicom.imgix.net",
    "segment.io",
    "sentry.io",
    "stripe.com",
    "turn.livekit.cloud",
];

/// 域名关键字（只匹配规范化后的主机名，不匹配 URL/路径/查询参数）。
const KEYWORDS: &[&str] = &["openai"];

/// 主机名规范化：转小写并移除末尾的点。
pub fn normalize_pac_host(host: &str) -> String {
    let mut host = host.trim().to_lowercase();
    while host.ends_with('.') {
        host.pop();
    }
    host
}

/// 判断后缀是否按 DNS 标签边界匹配（`openai.com` 匹配 `api.openai.com`，不匹配 `notopenai.com`）。
fn suffix_matches_label_boundary(host: &str, suffix: &str) -> bool {
    host == suffix || (host.len() > suffix.len() && host.ends_with(suffix) && host.as_bytes()[host.len() - suffix.len() - 1] == b'.')
}

/// 按精确域名 → 后缀 → 关键字顺序匹配；回环与网关 IP 在任何规则之前恒 DIRECT。
pub fn pac_result_for_host(host: &str) -> &'static str {
    let host = normalize_pac_host(host);
    if host == MANAGED_GATEWAY_SOCKS5_HOST
        || host == "localhost"
        || host == "127.0.0.1"
        || host == "::1"
    {
        return "DIRECT";
    }
    if EXACT_DOMAINS.contains(&host.as_str()) {
        return MANAGED_GATEWAY_SOCKS5_RESULT;
    }
    if DOMAIN_SUFFIXES
        .iter()
        .any(|suffix| suffix_matches_label_boundary(&host, suffix))
    {
        return MANAGED_GATEWAY_SOCKS5_RESULT;
    }
    if KEYWORDS.iter().any(|keyword| host.contains(keyword)) {
        return MANAGED_GATEWAY_SOCKS5_RESULT;
    }
    "DIRECT"
}

fn js_string_array(values: &[&str]) -> String {
    values
        .iter()
        .map(|value| format!("\"{value}\""))
        .collect::<Vec<_>>()
        .join(", ")
}

/// 生成固定 PAC 文本。内容完全由本模块规则快照决定，不接收任何用户输入。
pub fn build_pac_script() -> String {
    let exact = js_string_array(EXACT_DOMAINS);
    let suffixes = js_string_array(DOMAIN_SUFFIXES);
    let keywords = js_string_array(KEYWORDS);
    format!(
        r#"// Codex++ managed gateway PAC. Generated content; do not edit.
var EXACT_DOMAINS = {exact};
var DOMAIN_SUFFIXES = {suffixes};
var KEYWORDS = {keywords};
var SOCKS5_RESULT = "SOCKS5 10.20.30.61:7891";
var DIRECT_RESULT = "DIRECT";
var DIRECT_HOSTS = ["10.20.30.61", "localhost", "127.0.0.1", "::1"];
function normalizeHost(host) {{
  var h = String(host).toLowerCase();
  while (h.length > 0 && h.charAt(h.length - 1) === ".") h = h.substring(0, h.length - 1);
  return h;
}}
function FindProxyForURL(url, host) {{
  var h = normalizeHost(host);
  for (var i = 0; i < DIRECT_HOSTS.length; i++) {{
    if (h === DIRECT_HOSTS[i]) return DIRECT_RESULT;
  }}
  for (var i = 0; i < EXACT_DOMAINS.length; i++) {{
    if (h === EXACT_DOMAINS[i]) return SOCKS5_RESULT;
  }}
  for (var i = 0; i < DOMAIN_SUFFIXES.length; i++) {{
    var s = DOMAIN_SUFFIXES[i];
    if (h === s) return SOCKS5_RESULT;
    if (h.length > s.length && h.charAt(h.length - s.length - 1) === "." && h.substring(h.length - s.length) === s) return SOCKS5_RESULT;
  }}
  for (var i = 0; i < KEYWORDS.length; i++) {{
    if (h.indexOf(KEYWORDS[i]) !== -1) return SOCKS5_RESULT;
  }}
  return DIRECT_RESULT;
}}
"#
    )
}

/// helper 服务上的 PAC 端点路径。
pub fn is_proxy_pac_path(path: &str) -> bool {
    path == "/proxy.pac"
}

/// 受管 PAC 启动参数（指向本次启动的本地 helper 端口）。
pub fn managed_proxy_pac_url_arg(helper_port: u16) -> String {
    format!("--proxy-pac-url=http://127.0.0.1:{helper_port}/proxy.pac")
}

/// 清理冲突的用户代理参数后，追加唯一的受管 PAC 参数。
pub fn inject_managed_pac_arg(args: &[String], helper_port: u16) -> Vec<String> {
    let mut out: Vec<String> = args
        .iter()
        .filter(|arg| {
            let arg = arg.trim();
            !arg.starts_with("--proxy-pac-url=") && !arg.starts_with("--proxy-server")
        })
        .cloned()
        .collect();
    out.push(managed_proxy_pac_url_arg(helper_port));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_domain_only_matches_identical_host() {
        assert_eq!(
            pac_result_for_host("chat.openai.com.cdn.cloudflare.net"),
            MANAGED_GATEWAY_SOCKS5_RESULT
        );
        // 精确域名的子域名不命中精确规则；选不含关键字的例子验证不回退到后缀/关键字
        assert_eq!(pac_result_for_host("x.static.cloudflareinsights.com"), "DIRECT");
        assert_eq!(pac_result_for_host("browser-intake-datadoghq.com"), MANAGED_GATEWAY_SOCKS5_RESULT);
        assert_eq!(pac_result_for_host("x.browser-intake-datadoghq.com"), "DIRECT");
    }

    #[test]
    fn suffix_matches_root_and_subdomains_with_label_boundary() {
        assert_eq!(pac_result_for_host("openai.com"), MANAGED_GATEWAY_SOCKS5_RESULT);
        assert_eq!(pac_result_for_host("api.openai.com"), MANAGED_GATEWAY_SOCKS5_RESULT);
        assert_eq!(pac_result_for_host("deep.sub.auth0.com"), MANAGED_GATEWAY_SOCKS5_RESULT);
        // 无标签边界的相似域名不命中后缀规则（选不含 openai 关键字的域名验证）
        assert_eq!(pac_result_for_host("notauth0.com"), "DIRECT");
        assert_eq!(pac_result_for_host("auth0.company"), "DIRECT");
        // notopenai.com 含关键字 openai，仍按关键字规则命中 SOCKS5（spec 语义）
        assert_eq!(pac_result_for_host("notopenai.com"), MANAGED_GATEWAY_SOCKS5_RESULT);
    }

    #[test]
    fn keyword_is_case_insensitive_on_host_only() {
        assert_eq!(pac_result_for_host("OpenAI.example"), MANAGED_GATEWAY_SOCKS5_RESULT);
        assert_eq!(pac_result_for_host("my-openai-proxy.internal"), MANAGED_GATEWAY_SOCKS5_RESULT);
    }

    #[test]
    fn trailing_dot_and_case_normalize_consistently() {
        assert_eq!(pac_result_for_host("API.OpenAI.com."), MANAGED_GATEWAY_SOCKS5_RESULT);
        assert_eq!(pac_result_for_host("api.openai.com"), pac_result_for_host("API.OPENAI.COM."));
    }

    #[test]
    fn gateway_ip_and_loopback_always_direct() {
        for host in ["10.20.30.61", "localhost", "127.0.0.1", "::1"] {
            assert_eq!(pac_result_for_host(host), "DIRECT");
        }
        // IP 不含关键字，也不会被后缀规则命中
        assert_eq!(pac_result_for_host("10.20.30.61.example"), "DIRECT");
    }

    #[test]
    fn normal_non_openai_host_is_direct() {
        assert_eq!(pac_result_for_host("github.com"), "DIRECT");
        assert_eq!(pac_result_for_host("example.com"), "DIRECT");
    }

    #[test]
    fn matched_result_has_no_direct_fallback() {
        assert!(!MANAGED_GATEWAY_SOCKS5_RESULT.contains("DIRECT"));
    }

    #[test]
    fn pac_script_contains_findproxy_and_both_results() {
        let pac = build_pac_script();
        assert!(pac.contains("FindProxyForURL"));
        assert!(pac.contains("SOCKS5 10.20.30.61:7891"));
        assert!(pac.contains("\"DIRECT\""));
    }

    #[test]
    fn pac_script_embeds_rule_snapshots() {
        let pac = build_pac_script();
        assert!(pac.contains("chat.openai.com.cdn.cloudflare.net"));
        assert!(pac.contains("chatgpt.livekit.cloud"));
    }

    #[test]
    fn proxy_pac_path_matcher_is_exact() {
        assert!(is_proxy_pac_path("/proxy.pac"));
        assert!(!is_proxy_pac_path("/proxy.pac/other"));
        assert!(!is_proxy_pac_path("/other"));
    }

    #[test]
    fn managed_pac_url_arg_shape() {
        assert_eq!(
            managed_proxy_pac_url_arg(57321),
            "--proxy-pac-url=http://127.0.0.1:57321/proxy.pac"
        );
    }

    #[test]
    fn injects_unique_managed_pac_arg_replacing_conflicts() {
        let args = vec![
            "--remote-debugging-port=9229".to_string(),
            "--proxy-pac-url=http://evil.example/proxy.pac".to_string(),
            "--proxy-server=socks5://evil:1".to_string(),
            "--remote-allow-origins=http://127.0.0.1:9229".to_string(),
        ];
        let out = inject_managed_pac_arg(&args, 57321);
        assert_eq!(
            out.iter()
                .filter(|arg| arg.starts_with("--proxy-pac-url="))
                .count(),
            1
        );
        assert!(out.contains(&managed_proxy_pac_url_arg(57321)));
        assert!(out.iter().all(|arg| !arg.starts_with("--proxy-server")));
        assert!(out.contains(&"--remote-debugging-port=9229".to_string()));
    }

    #[test]
    fn inject_appends_when_no_existing_pac_args() {
        let out = inject_managed_pac_arg(&[], 9);
        assert_eq!(out, vec!["--proxy-pac-url=http://127.0.0.1:9/proxy.pac"]);
    }
}
