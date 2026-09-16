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

use std::path::Path;

/// 受管 provider 在 config.toml 中的固定标识。
pub const MANAGED_GATEWAY_PROVIDER_ID: &str = "managed_gateway";
/// 凭据在 Windows Credential Manager 中的固定 target。
pub const MANAGED_GATEWAY_CREDENTIAL_TARGET: &str = "managed-gateway";

/// 原子写校正受管内容：`model_provider` 与 `[model_providers.managed_gateway]`。
///
/// 只校正受管键，其他 Codex 配置与官方登录数据保留。写入前备份、写入失败时恢复。
pub fn apply_managed_gateway_to_config(home: &Path, credential_command: &str) -> anyhow::Result<()> {
    std::fs::create_dir_all(home)?;
    let config_path = home.join("config.toml");
    let contents = std::fs::read_to_string(&config_path).unwrap_or_default();
    // 损坏或缺失的 config 视为空配置；原文保留在备份里可恢复。
    let mut doc = contents
        .parse::<toml_edit::DocumentMut>()
        .unwrap_or_default();
    doc["model_provider"] = toml_edit::value(MANAGED_GATEWAY_PROVIDER_ID);
    let root = doc.as_table_mut();
    let providers = root
        .entry("model_providers")
        .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()));
    let Some(table) = providers.as_table_mut() else {
        anyhow::bail!("model_providers 不是 table，无法写入受管 provider");
    };
    let provider = table
        .entry(MANAGED_GATEWAY_PROVIDER_ID)
        .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()));
    let Some(provider) = provider.as_table_mut() else {
        anyhow::bail!("model_providers.managed_gateway 不是 table");
    };
    provider["name"] = toml_edit::value("Managed Gateway");
    provider["base_url"] = toml_edit::value(MANAGED_GATEWAY_BASE_URL);
    provider["wire_api"] = toml_edit::value("responses");
    // 命令鉴权与 env_key / experimental_bearer_token / requires_openai_auth 互斥
    for key in ["env_key", "experimental_bearer_token", "requires_openai_auth"] {
        provider.remove(key);
    }
    let auth = provider
        .entry("auth")
        .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()));
    let Some(auth) = auth.as_table_mut() else {
        anyhow::bail!("model_providers.managed_gateway.auth 不是 table");
    };
    auth["command"] = toml_edit::value(credential_command);
    let mut args = toml_edit::Array::new();
    args.push("get");
    args.push(MANAGED_GATEWAY_CREDENTIAL_TARGET);
    auth["args"] = toml_edit::value(args);
    let updated = doc.to_string();
    if contents != updated && config_path.exists() {
        let backup = config_path.with_extension("toml.managed-gateway-bak");
        std::fs::copy(&config_path, &backup)?;
    }
    if let Err(error) = crate::settings::atomic_write(&config_path, updated.as_bytes()) {
        let backup = config_path.with_extension("toml.managed-gateway-bak");
        if backup.exists() {
            let _ = std::fs::copy(&backup, &config_path);
        }
        return Err(error);
    }
    Ok(())
}

/// 检测现有 config.toml 中的外部 `model_catalog_json` 指针（会影响内置模型目录目标）。
pub fn managed_gateway_config_conflicts(home: &Path) -> Option<String> {
    let contents = std::fs::read_to_string(home.join("config.toml")).ok()?;
    let doc = contents.parse::<toml_edit::DocumentMut>().ok()?;
    doc.get("model_catalog_json")
        .and_then(|value| value.as_str())
        .map(str::to_string)
}

/// 备份后仅移除 `model_catalog_json` 根键，不删除外部 catalog 文件本身。
/// 返回备份路径；无指针时返回 None。
pub fn remove_external_model_catalog_pointer(home: &Path) -> anyhow::Result<Option<String>> {
    if managed_gateway_config_conflicts(home).is_none() {
        return Ok(None);
    }
    let config_path = home.join("config.toml");
    let contents = std::fs::read_to_string(&config_path)?;
    let mut doc = contents.parse::<toml_edit::DocumentMut>()?;
    doc.as_table_mut().remove("model_catalog_json");
    let backup_dir = crate::paths::default_app_state_dir().join("managed-gateway-backups");
    std::fs::create_dir_all(&backup_dir)?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis();
    let backup = backup_dir.join(format!("config-{stamp}.toml"));
    std::fs::write(&backup, &contents)?;
    crate::settings::atomic_write(&config_path, doc.to_string().as_bytes())?;
    Ok(Some(backup.to_string_lossy().to_string()))
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

    #[test]
    fn apply_writes_provider_command_auth_and_preserves_unrelated_fields() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        std::fs::write(
            home.join("config.toml"),
            "model = \"gpt-5.2-codex\"\n# 用户注释\n[model_providers.custom]\nname = \"Custom\"\n",
        )
        .unwrap();
        apply_managed_gateway_to_config(
            home,
            "C:\\Program Files\\Codex++\\codex-plus-credential.exe",
        )
        .unwrap();
        let text = std::fs::read_to_string(home.join("config.toml")).unwrap();
        assert!(text.contains("model_provider = \"managed_gateway\""));
        assert!(text.contains("[model_providers.managed_gateway]"));
        assert!(text.contains("base_url = \"http://10.20.30.61:8080\""));
        assert!(text.contains("wire_api = \"responses\""));
        assert!(text.contains("args = [\"get\", \"managed-gateway\"]"));
        assert!(text.contains("model = \"gpt-5.2-codex\""));
        assert!(text.contains("# 用户注释"));
        assert!(text.contains("[model_providers.custom]"));
        assert!(!text.contains("env_key"));
        assert!(!text.contains("experimental_bearer_token"));
        assert!(!text.contains("requires_openai_auth = true"));
    }

    #[test]
    fn apply_corrects_drift_on_every_launch() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        apply_managed_gateway_to_config(home, "C:\\x\\codex-plus-credential.exe").unwrap();
        let text = std::fs::read_to_string(home.join("config.toml"))
            .unwrap()
            .replace("http://10.20.30.61:8080", "http://evil:1");
        std::fs::write(home.join("config.toml"), text).unwrap();
        apply_managed_gateway_to_config(home, "C:\\x\\codex-plus-credential.exe").unwrap();
        let text = std::fs::read_to_string(home.join("config.toml")).unwrap();
        assert!(text.contains("http://10.20.30.61:8080"));
        assert!(text.contains("model_provider = \"managed_gateway\""));
    }

    #[test]
    fn apply_creates_config_when_missing_and_tolerates_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        apply_managed_gateway_to_config(home, "C:\\x\\codex-plus-credential.exe").unwrap();
        assert!(home.join("config.toml").exists());
        // 损坏的 config.toml：备份保留原文后重置为受管配置（可从 .bak 恢复）
        std::fs::write(home.join("config.toml"), "<<<not toml>>>").unwrap();
        apply_managed_gateway_to_config(home, "C:\\x\\codex-plus-credential.exe").unwrap();
        let text = std::fs::read_to_string(home.join("config.toml")).unwrap();
        assert!(text.contains("[model_providers.managed_gateway]"));
        assert!(std::fs::read_to_string(
            home.join("config.toml.managed-gateway-bak")
        )
        .unwrap()
        .contains("<<<not toml>>"));
    }

    #[test]
    fn detects_and_removes_external_catalog_pointer_only() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let catalog = dir.path().join("external-catalog.json");
        std::fs::write(&catalog, "[]").unwrap();
        std::fs::write(
            home.join("config.toml"),
            "model_catalog_json = \"C:\\\\tmp\\\\external-catalog.json\"\nmodel = \"gpt-5.2\"\n",
        )
        .unwrap();
        assert_eq!(
            managed_gateway_config_conflicts(home).as_deref(),
            Some("C:\\tmp\\external-catalog.json")
        );
        let backup = remove_external_model_catalog_pointer(home).unwrap().unwrap();
        assert!(std::path::Path::new(&backup).exists());
        let text = std::fs::read_to_string(home.join("config.toml")).unwrap();
        assert!(!text.contains("model_catalog_json"));
        assert!(text.contains("model = \"gpt-5.2\""));
        assert!(catalog.exists());
    }

    #[test]
    fn no_conflict_returns_none_and_removal_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        std::fs::write(home.join("config.toml"), "model = \"gpt-5.2\"\n").unwrap();
        assert!(managed_gateway_config_conflicts(home).is_none());
        assert!(remove_external_model_catalog_pointer(home).unwrap().is_none());
    }
}
