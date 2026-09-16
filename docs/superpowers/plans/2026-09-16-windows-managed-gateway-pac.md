# Windows 受管模型网关与 OpenAI PAC 分流实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Windows 上为 Codex 提供受管封装：模型请求固定走 `http://10.20.30.61:8080`，OpenAI 域名规则命中流量固定走 SOCKS5 `10.20.30.61:7891`，其余直连；API Key 存 Windows Credential Manager。

**Architecture:** 本地 helper 服务新增 `/proxy.pac` 固定内容端点；启动器为 packaged activation 追加唯一 `--proxy-pac-url`；codex-plus-core 新增 `managed_gateway` 模块（规则/PAC/受管 config.toml 校正/网关 Key 校验）与 `credential` 模块（Credential Manager 读写）；新增 `codex-plus-credential` 二进制供 Codex 命令鉴权读取凭据；manager 新增初始化 UI 与 Tauri 命令。

**Tech Stack:** Rust（codex-plus-core、tokio、toml_edit、windows crate、reqwest/wiremock）、React+TS（manager 前端、node --test）、NSIS。

**Spec:** `docs/superpowers/specs/2026-09-16-windows-managed-gateway-pac-design.md`

## Global Constraints

- 网关固定 `http://10.20.30.61:8080`；SOCKS5 固定 `10.20.30.61:7891`；PAC 结果只有 `SOCKS5 10.20.30.61:7891` 与 `DIRECT`，禁止 `DIRECT` 回退追加。
- `10.20.30.61`、`localhost`、`127.0.0.1`、`::1` 在任何规则之前恒返回 `DIRECT`。
- 后缀规则按 DNS 标签边界匹配（`openai.com` 匹配 `api.openai.com`，不匹配 `notopenai.com`）；关键字 `openai` 只匹配规范化主机名。
- PAC 仅绑定回环；内容为固定生成，不接收用户输入。
- API Key 不写入 settings、config.toml、auth.json、日志、错误对象；UI 不回显完整 Key。
- 命令鉴权与 `env_key`、`experimental_bearer_token`、`requires_openai_auth` 互斥。
- 不为本功能生成 `model_catalog_json`；初始化完成时对外部 catalog 指针「备份 + 只移除指针，不删目标文件」。
- 受管配置写入失败必须恢复启动前备份，且不启动 Codex。
- 特性 Windows-only 且 opt-in：设置字段 `windowsManagedGatewayEnabled` 默认 `false`；非 Windows 与未开启时行为零变化。
- 不修改 Windows 系统代理；不代理 Shell/MCP 子进程。
- 网关 `401/403` → 提示重录、不动已有凭据；超时/`5xx` → 保留凭据、提供重试。
- 提交信息末尾带 `Co-Authored-By: Pi`；不执行 push。
- 验证命令：`cargo test --workspace`、`cd apps/codex-plus-manager && npm test`、`npm run check`、`node tools/i18n-verify.mjs`。

## 文件结构总览

- 新建 `crates/codex-plus-core/src/managed_gateway.rs` — 规则、PAC、启动参数、受管 config 校正、外部 catalog 检测/移除、网关 Key 校验。
- 新建 `crates/codex-plus-core/src/credential.rs` — Credential Manager 读写（windows 实现 + 非 windows stub）。
- 新建 `apps/codex-plus-credential/src/main.rs` + `Cargo.toml` — 凭据读取二进制。
- 修改 `crates/codex-plus-core/src/launcher.rs` — `/proxy.pac` 路由、`launch_codex` 增加 `helper_port` 参数、受管启动编排。
- 修改 `crates/codex-plus-core/src/settings.rs` — 新设置字段。
- 修改 `crates/codex-plus-core/src/lib.rs`、根 `Cargo.toml` — 模块与 workspace 成员。
- 修改 `crates/codex-plus-core/Cargo.toml` — windows crate 增加 `Win32_Security_Credentials` feature（任务必需）。
- 修改 `crates/codex-plus-core/src/manager_navigation.rs` — 允许 `settings/managedGateway` 导航。
- 修改 `apps/codex-plus-manager/src-tauri/src/commands.rs`、`lib.rs` — 新 Tauri 命令。
- 新建 `apps/codex-plus-manager/src/managed-gateway.ts(+.test.ts)` — 前端状态映射。
- 修改 `apps/codex-plus-manager/src/App.tsx`、`i18n-en.ts` — 设置页初始化区块。
- 修改 `scripts/installer/windows/CodexPlusPlus.nsi`、`.github/workflows/pr-build.yml`、`release-assets.yml` — 打包 credential 二进制。
- 测试：`crates/codex-plus-core/src/managed_gateway.rs` 内嵌 `#[cfg(test)]`、`crates/codex-plus-core/tests/launcher.rs`、`tests/relay_config.rs`（如需）、manager node 测试。

---

### Task 1: managed_gateway 规则与 PAC 引擎（纯函数 + 单测）

**Files:**
- Create: `crates/codex-plus-core/src/managed_gateway.rs`
- Modify: `crates/codex-plus-core/src/lib.rs`（加 `pub mod managed_gateway;`）

**Interfaces:**
- Produces:
  - `pub const MANAGED_GATEWAY_BASE_URL: &str = "http://10.20.30.61:8080"`
  - `pub const MANAGED_GATEWAY_SOCKS5_HOST: &str = "10.20.30.61"`
  - `pub const MANAGED_GATEWAY_SOCKS5_PORT: u16 = 7891`
  - `pub const MANAGED_GATEWAY_SOCKS5_RESULT: &str = "SOCKS5 10.20.30.61:7891"`
  - `pub fn normalize_pac_host(host: &str) -> String`（小写 + 去末尾点）
  - `pub fn pac_result_for_host(host: &str) -> &'static str`（回环/网关 IP → "DIRECT"，其余按规则）
  - `pub fn build_pac_script() -> String`（固定 PAC 文本，内嵌规则）
  - `pub fn is_proxy_pac_path(path: &str) -> bool`（`path == "/proxy.pac"`）
  - `pub fn managed_proxy_pac_url_arg(helper_port: u16) -> String`（`--proxy-pac-url=http://127.0.0.1:{port}/proxy.pac`）
  - `pub fn inject_managed_pac_arg(args: &[String], helper_port: u16) -> Vec<String>`（清理既有 `--proxy-pac-url=` / `--proxy-server` 前缀冲突后追加唯一受管参数）

- [ ] **Step 1: 写失败测试**

在 `crates/codex-plus-core/src/managed_gateway.rs` 中先写模块骨架与测试（规则快照数据来自 spec「OpenAI 域名规则」全表）：

```rust
//! Windows 受管模型网关与 OpenAI PAC 分流（设计见 docs/superpowers/specs/2026-09-16-...md）。

pub const MANAGED_GATEWAY_BASE_URL: &str = "http://10.20.30.61:8080";
pub const MANAGED_GATEWAY_SOCKS5_HOST: &str = "10.20.30.61";
pub const MANAGED_GATEWAY_SOCKS5_PORT: u16 = 7891;
pub const MANAGED_GATEWAY_SOCKS5_RESULT: &str = "SOCKS5 10.20.30.61:7891";

const EXACT_DOMAINS: &[&str] = &[
    "browser-intake-datadoghq.com",
    "chat.openai.com.cdn.cloudflare.net",
    "openai-api.arkoselabs.com",
    "openaicom-api-bdcpf8c6d2e9atf6.z01.azurefd.net",
    "openaicomproductionae4b.blob.core.windows.net",
    "production-openaicom-storage.azureedge.net",
    "static.cloudflareinsights.com",
];
const DOMAIN_SUFFIXES: &[&str] = &[
    "ai.com", "algolia.net", "api.statsig.com", "auth0.com", "chatgpt.com",
    "chatgpt.livekit.cloud", "client-api.arkoselabs.com", "events.statsigapi.net",
    "featuregates.org", "host.livekit.cloud", "identrust.com", "intercom.io",
    "intercomcdn.com", "launchdarkly.com", "oaistatic.com", "oaiusercontent.com",
    "observeit.net", "openai.com", "openaiapi-site.azureedge.net",
    "openaicom.imgix.net", "segment.io", "sentry.io", "stripe.com",
    "turn.livekit.cloud",
];
const KEYWORDS: &[&str] = &["openai"];

pub fn normalize_pac_host(host: &str) -> String {
    let mut host = host.trim().to_lowercase();
    while host.ends_with('.') {
        host.pop();
    }
    host
}
```

测试（同文件 `#[cfg(test)] mod tests`，至少覆盖）：

```rust
#[test]
fn exact_domain_only_matches_identical_host() {
    assert_eq!(pac_result_for_host("chat.openai.com.cdn.cloudflare.net"), MANAGED_GATEWAY_SOCKS5_RESULT);
    assert_eq!(pac_result_for_host("x.chat.openai.com.cdn.cloudflare.net"), "DIRECT");
}

#[test]
fn suffix_matches_root_and_subdomains_with_label_boundary() {
    assert_eq!(pac_result_for_host("openai.com"), MANAGED_GATEWAY_SOCKS5_RESULT);
    assert_eq!(pac_result_for_host("api.openai.com"), MANAGED_GATEWAY_SOCKS5_RESULT);
    assert_eq!(pac_result_for_host("notopenai.com"), "DIRECT");
}

#[test]
fn keyword_is_case_insensitive_on_host_only() {
    assert_eq!(pac_result_for_host("OpenAI.example"), MANAGED_GATEWAY_SOCKS5_RESULT);
}

#[test]
fn trailing_dot_and_case_normalize_consistently() {
    assert_eq!(pac_result_for_host("API.OpenAI.com."), MANAGED_GATEWAY_SOCKS5_RESULT);
}

#[test]
fn gateway_ip_and_loopback_always_direct() {
    for host in ["10.20.30.61", "localhost", "127.0.0.1", "::1"] {
        assert_eq!(pac_result_for_host(host), "DIRECT");
    }
    assert_eq!(pac_result_for_host("sub.10.20.30.61"), "DIRECT"); // 关键字不匹配 IP
}

#[test]
fn matched_result_has_no_direct_fallback() {
    assert!(!MANAGED_GATEWAY_SOCKS5_RESULT.contains("DIRECT"));
}

#[test]
fn pac_script_contains_findproxy_and_both_results() {
    let pac = build_pac_script();
    assert!(pac.contains("FindProxyForURL"));
    assert!(pac.contains(MANAGED_GATEWAY_SOCKS5_RESULT));
    assert!(pac.contains("\"DIRECT\""));
}

#[test]
fn injects_unique_managed_pac_arg_replacing_conflicts() {
    let args = vec![
        "--remote-debugging-port=9229".to_string(),
        "--proxy-pac-url=http://evil.example/proxy.pac".to_string(),
        "--proxy-server=socks5://evil:1".to_string(),
    ];
    let out = inject_managed_pac_arg(&args, 57321);
    assert_eq!(out.iter().filter(|a| a.starts_with("--proxy-pac-url=")).count(), 1);
    assert!(out.contains(&managed_proxy_pac_url_arg(57321)));
    assert!(out.iter().all(|a| !a.starts_with("--proxy-server")));
}
```

- [ ] **Step 2: 运行验证失败**

Run: `cargo test -p codex-plus-core managed_gateway`
Expected: 编译失败（`pac_result_for_host` 等未定义）。

- [ ] **Step 3: 实现纯函数**

```rust
pub fn pac_result_for_host(host: &str) -> &'static str {
    let host = normalize_pac_host(host);
    if host == MANAGED_GATEWAY_SOCKS5_HOST
        || host == "localhost" || host == "127.0.0.1" || host == "::1"
    {
        return "DIRECT";
    }
    if EXACT_DOMAINS.contains(&host.as_str()) {
        return MANAGED_GATEWAY_SOCKS5_RESULT;
    }
    if DOMAIN_SUFFIXES.iter().any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}"))) {
        return MANAGED_GATEWAY_SOCKS5_RESULT;
    }
    if KEYWORDS.iter().any(|kw| host.contains(kw)) {
        return MANAGED_GATEWAY_SOCKS5_RESULT;
    }
    "DIRECT"
}

pub fn build_pac_script() -> String {
    // 用 JS 数组字面量内嵌规则；生成固定文本（含中文注释不必要，保持 ASCII）。
    let exact = js_string_array(EXACT_DOMAINS);
    let suffixes = js_string_array(DOMAIN_SUFFIXES);
    let keywords = js_string_array(KEYWORDS);
    format!(r#"// Codex++ managed gateway PAC. Generated content; do not edit.
var EXACT_DOMAINS = {exact};
var DOMAIN_SUFFIXES = {suffixes};
var KEYWORDS = {keywords};
var SOCKS5_RESULT = "SOCKS5 10.20.30.61:7891";
var DIRECT_RESULT = "DIRECT";
var DIRECT_HOSTS = ["10.20.30.61", "localhost", "127.0.0.1", "::1"];
function normalizeHost(host) {{
  var h = String(host).toLowerCase();
  while (h.charAt(h.length - 1) === ".") h = h.substring(0, h.length - 1);
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
    if (h === s || h.length > s.length && h.charAt(h.length - s.length - 1) === "." && h.substring(h.length - s.length) === s) return SOCKS5_RESULT;
  }}
  for (var i = 0; i < KEYWORDS.length; i++) {{
    if (h.indexOf(KEYWORDS[i]) !== -1) return SOCKS5_RESULT;
  }}
  return DIRECT_RESULT;
}}
"#
    )
}

fn js_string_array(values: &[&str]) -> String {
    values.iter().map(|v| format!("\"{v}\"")).collect::<Vec<_>>().join(", ")
}

pub fn is_proxy_pac_path(path: &str) -> bool {
    path == "/proxy.pac"
}

pub fn managed_proxy_pac_url_arg(helper_port: u16) -> String {
    format!("--proxy-pac-url=http://127.0.0.1:{helper_port}/proxy.pac")
}

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
```

同时把测试里 `sub.10.20.30.61` 的断言修正：它含 `openai`? 否——它不含关键字，走 DIRECT，断言成立。保留。

- [ ] **Step 4: 运行验证通过**

Run: `cargo test -p codex-plus-core managed_gateway`
Expected: PASS（全部新测试）。

- [ ] **Step 5: Commit**

```bash
git add crates/codex-plus-core/src/managed_gateway.rs crates/codex-plus-core/src/lib.rs
git commit -m "feat(managed-gateway): OpenAI 规则与 PAC 引擎纯函数

Co-Authored-By: Pi"
```

---

### Task 2: 受管 config.toml 校正（provider + 命令鉴权 + 外部 catalog 处理）

**Files:**
- Modify: `crates/codex-plus-core/src/managed_gateway.rs`

**Interfaces:**
- Consumes: Task 1 常量。
- Produces:
  - `pub const MANAGED_GATEWAY_PROVIDER_ID: &str = "managed_gateway"`
  - `pub const MANAGED_GATEWAY_CREDENTIAL_TARGET: &str = "managed-gateway"`
  - `pub fn apply_managed_gateway_to_config(home: &Path, credential_command: &str) -> anyhow::Result<()>` — 原子写校正 `model_provider` 与 `[model_providers.managed_gateway]`（name/base_url/wire_api/auth.command+args），移除互斥键，其他字段与注释保留；写入前备份、失败回滚。
  - `pub fn managed_gateway_config_conflicts(home: &Path) -> Option<String>` — 检测现有 config.toml 的外部 `model_catalog_json` 指针。
  - `pub fn remove_external_model_catalog_pointer(home: &Path) -> anyhow::Result<Option<String>>` — 备份后仅移除 `model_catalog_json` 根键，不删目标文件，返回备份路径。

- [ ] **Step 1: 写失败测试**

`managed_gateway.rs` tests 模块追加（tempfile）：

```rust
#[test]
fn apply_writes_provider_command_auth_and_preserves_unrelated_fields() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    std::fs::write(
        home.join("config.toml"),
        "model = \"gpt-5.2-codex\"\n# 用户注释\n[model_providers.custom]\nname = \"Custom\"\n",
    )
    .unwrap();
    apply_managed_gateway_to_config(home, "C:\\Program Files\\Codex++\\codex-plus-credential.exe").unwrap();
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
    let text = std::fs::read_to_string(home.join("config.toml")).unwrap()
        .replace("http://10.20.30.61:8080", "http://evil:1");
    std::fs::write(home.join("config.toml"), text).unwrap();
    apply_managed_gateway_to_config(home, "C:\\x\\codex-plus-credential.exe").unwrap();
    let text = std::fs::read_to_string(home.join("config.toml")).unwrap();
    assert!(text.contains("http://10.20.30.61:8080"));
    assert!(text.contains("model_provider = \"managed_gateway\""));
}

#[test]
fn detects_and_removes_external_catalog_pointer_only() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let catalog = dir.path().join("external-catalog.json");
    std::fs::write(&catalog, "[]").unwrap();
    std::fs::write(
        home.join("config.toml"),
        "model_catalog_json = \"C:\\tmp\\external-catalog.json\"\n",
    )
    .unwrap();
    assert_eq!(managed_gateway_config_conflicts(home).as_deref(), Some("C:\\tmp\\external-catalog.json"));
    let backup = remove_external_model_catalog_pointer(home).unwrap().unwrap();
    assert!(std::path::Path::new(&backup).exists());
    let text = std::fs::read_to_string(home.join("config.toml")).unwrap();
    assert!(!text.contains("model_catalog_json"));
    assert!(catalog.exists());
}
```

说明：`apply_managed_gateway_to_config` 读不到 config.toml 时视为空配置（不报错）；`remove_external_model_catalog_pointer` 的备份目录用 `crate::paths::default_app_state_dir().join("managed-gateway-backups")`，测试对该目录的依赖通过只验证返回路径存在即可（默认 app state 目录在测试环境可写）。

- [ ] **Step 2: 运行验证失败**

Run: `cargo test -p codex-plus-core managed_gateway`
Expected: 编译失败（函数未定义）。

- [ ] **Step 3: 实现**

```rust
use std::path::Path;

pub const MANAGED_GATEWAY_PROVIDER_ID: &str = "managed_gateway";
pub const MANAGED_GATEWAY_CREDENTIAL_TARGET: &str = "managed-gateway";

pub fn apply_managed_gateway_to_config(home: &Path, credential_command: &str) -> anyhow::Result<()> {
    std::fs::create_dir_all(home)?;
    let config_path = home.join("config.toml");
    let contents = std::fs::read_to_string(&config_path).unwrap_or_default();
    let mut doc = contents.parse::<toml_edit::DocumentMut>().unwrap_or_default();
    doc["model_provider"] = toml_edit::value(MANAGED_GATEWAY_PROVIDER_ID);
    let root = doc.as_table_mut();
    let providers = root
        .entry("model_providers")
        .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()));
    let Some(table) = providers.as_table_mut() else {
        anyhow::bail!("model_providers 不是 table，无法写入受管 provider");
    };
    let provider = table.entry(MANAGED_GATEWAY_PROVIDER_ID)
        .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()));
    let Some(provider) = provider.as_table_mut() else {
        anyhow::bail!("model_providers.managed_gateway 不是 table");
    };
    provider["name"] = toml_edit::value("Managed Gateway");
    provider["base_url"] = toml_edit::value(MANAGED_GATEWAY_BASE_URL);
    provider["wire_api"] = toml_edit::value("responses");
    for key in ["env_key", "experimental_bearer_token", "requires_openai_auth"] {
        provider.remove(key);
    }
    let auth = provider.entry("auth")
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
    if config_path.exists() {
        let backup = config_path.with_extension("toml.managed-gateway-bak");
        std::fs::copy(&config_path, &backup)?;
        if let Err(error) = crate::settings::atomic_write(&config_path, updated.as_bytes()) {
            let _ = std::fs::copy(&backup, &config_path);
            return Err(error);
        }
    } else {
        crate::settings::atomic_write(&config_path, updated.as_bytes())?;
    }
    Ok(())
}

pub fn managed_gateway_config_conflicts(home: &Path) -> Option<String> {
    let contents = std::fs::read_to_string(home.join("config.toml")).ok()?;
    let doc = contents.parse::<toml_edit::DocumentMut>().ok()?;
    doc.get("model_catalog_json").and_then(|v| v.as_str()).map(str::to_string)
}

pub fn remove_external_model_catalog_pointer(home: &Path) -> anyhow::Result<Option<String>> {
    let Some(_pointer) = managed_gateway_config_conflicts(home) else {
        return Ok(None);
    };
    let config_path = home.join("config.toml");
    let contents = std::fs::read_to_string(&config_path)?;
    let mut doc = contents.parse::<toml_edit::DocumentMut>()?;
    doc.as_table_mut().remove("model_catalog_json");
    let backup_dir = crate::paths::default_app_state_dir().join("managed-gateway-backups");
    std::fs::create_dir_all(&backup_dir)?;
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis();
    let backup = backup_dir.join(format!("config-{stamp}.toml"));
    std::fs::write(&backup, &contents)?;
    crate::settings::atomic_write(&config_path, doc.to_string().as_bytes())?;
    Ok(Some(backup.to_string_lossy().to_string()))
}
```

若 `auth["args"] = toml_edit::value(args)` 因 Item 类型不符编译报错，改用 `auth.insert("args", toml_edit::value(args))`。

- [ ] **Step 4: 运行验证通过**

Run: `cargo test -p codex-plus-core managed_gateway`
Expected: PASS。

- [ ] **Step 5: Commit**

```bash
git add crates/codex-plus-core/src/managed_gateway.rs
git commit -m "feat(managed-gateway): 受管 provider 配置校正与外部 catalog 处理

Co-Authored-By: Pi"
```

---

### Task 3: Credential Manager 读写模块

**Files:**
- Create: `crates/codex-plus-core/src/credential.rs`
- Modify: `crates/codex-plus-core/src/lib.rs`（加 `pub mod credential;`）
- Modify: `crates/codex-plus-core/Cargo.toml`（windows crate features 追加 `"Win32_Security_Credentials"`）

**Interfaces:**
- Produces:
  - `pub fn read_credential(target: &str) -> anyhow::Result<Option<String>>`
  - `pub fn write_credential(target: &str, token: &str) -> anyhow::Result<()>`（CRED_PERSIST = CRED_PERSIST_ENTERPRISE；写入前不回显）
  - 非 Windows 平台 stub 返回 `Err(anyhow!("Credential Manager 仅支持 Windows"))`；`read_credential` 在非 Windows 返回 `Ok(None)`。

- [ ] **Step 1: 写测试（非 Windows 可运行的部分）**

由于 CI 的 macOS 也要过，非 Windows stub 也要有测试：

```rust
#[cfg(not(windows))]
#[test]
fn non_windows_stubs_fail_clearly() {
    assert!(write_credential("managed-gateway", "sk-test").is_err());
    assert_eq!(read_credential("managed-gateway").unwrap(), None);
}
```

Windows 实机测试（`#[cfg(windows)]`）使用临时 target（`CodexPlusPlus/test-{uuid}`）验证写入、读取、覆盖、删除（CredDeleteW 由 `delete_credential` 提供，同样加入模块）。

- [ ] **Step 2: 实现（windows 部分）**

```rust
//! Windows Credential Manager 读写。只读写固定 target，不日志化凭据内容。

use anyhow::Context;

#[cfg(windows)]
use windows::core::PWSTR;
#[cfg(windows)]
use windows::Win32::Security::Credentials::{
    CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_ENTERPRISE,
    CRED_TYPE_GENERIC,
};

pub fn read_credential(target: &str) -> anyhow::Result<Option<String>> {
    #[cfg(windows)]
    { read_credential_windows(target) }
    #[cfg(not(windows))]
    { let _ = target; Ok(None) }
}

pub fn write_credential(target: &str, token: &str) -> anyhow::Result<()> {
    #[cfg(windows)]
    { write_credential_windows(target, token) }
    #[cfg(not(windows))]
    { let _ = (target, token); anyhow::bail!("Credential Manager 仅支持 Windows") }
}

pub fn delete_credential(target: &str) -> anyhow::Result<()> {
    #[cfg(windows)]
    { delete_credential_windows(target) }
    #[cfg(not(windows))]
    { let _ = target; anyhow::bail!("Credential Manager 仅支持 Windows") }
}

#[cfg(windows)]
fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn read_credential_windows(target: &str) -> anyhow::Result<Option<String>> {
    let mut credential_ptr: *mut CREDENTIALW = std::ptr::null_mut();
    let target_wide = to_wide(target);
    let result = unsafe {
        CredReadW(
            PCWSTR(target_wide.as_ptr()),
            CRED_TYPE_GENERIC,
            0,
            &mut credential_ptr,
        )
    };
    if !result.as_bool() {
        let code = unsafe { windows::Win32::Foundation::GetLastError() };
        if code == windows::Win32::Foundation::WIN32_ERROR(1168) {
            return Ok(None); // ERROR_NOT_FOUND
        }
        anyhow::bail!("读取凭据失败（code={code}）");
    }
    let credential = unsafe { &*credential_ptr };
    let bytes = unsafe {
        std::slice::from_raw_parts(
            credential.CredentialBlob as *const u8,
            credential.CredentialBlobSize as usize,
        )
    };
    let token = String::from_utf8(bytes.to_vec())
        .with_context(|| "凭据内容不是有效 UTF-8")?;
    unsafe { CredFree(credential_ptr as *const std::ffi::c_void) };
    Ok(Some(token))
}

#[cfg(windows)]
fn write_credential_windows(target: &str, token: &str) -> anyhow::Result<()> {
    let target_wide = to_wide(target);
    let mut credential = CREDENTIALW {
        Flags: Default::default(),
        Type: CRED_TYPE_GENERIC,
        TargetName: PWSTR(target_wide.as_ptr() as *mut u16),
        Comment: PWSTR::null(),
        LastWritten: Default::default(),
        CredentialBlobSize: token.len() as u32,
        CredentialBlob: token.as_ptr() as *mut std::ffi::c_void,
        Persist: CRED_PERSIST_ENTERPRISE,
        AttributeCount: 0,
        Attributes: std::ptr::null_mut(),
        TargetAlias: PWSTR::null(),
        UserName: PWSTR::null(),
    };
    let result = unsafe { CredWriteW(&mut credential, 0) };
    if !result.as_bool() {
        let code = unsafe { windows::Win32::Foundation::GetLastError() };
        anyhow::bail!("写入凭据失败（code={code}）");
    }
    Ok(())
}

#[cfg(windows)]
fn delete_credential_windows(target: &str) -> anyhow::Result<()> {
    let target_wide = to_wide(target);
    let result = unsafe { CredDeleteW(PCWSTR(target_wide.as_ptr()), CRED_TYPE_GENERIC, 0) };
    if !result.as_bool() {
        let code = unsafe { windows::Win32::Foundation::GetLastError() };
        if code == windows::Win32::Foundation::WIN32_ERROR(1168) {
            return Ok(());
        }
        anyhow::bail!("删除凭据失败（code={code}）");
    }
    Ok(())
}
```

注意：需要 `use windows::core::PCWSTR;`；错误码 1168 = ERROR_NOT_FOUND。若 windows crate API 名称有出入（如 `GetLastError` 路径），按编译器提示修正，保持「缺失返回 Ok(None)」的语义。UserName 建议设为 `PWSTR(to_wide("CodexPlusPlus").as_ptr() as *mut u16)`，避免空 UserName 的兼容问题。

- [ ] **Step 3: 验证**

Run: `cargo test -p codex-plus-core credential`
Expected: macOS 上 stub 测试 PASS；`cargo check -p codex-plus-core --target x86_64-pc-windows-msvc` 若本机无目标工具链则跳过，由 CI Windows job 兜底。

- [ ] **Step 4: Commit**

```bash
git add crates/codex-plus-core/src/credential.rs crates/codex-plus-core/src/lib.rs crates/codex-plus-core/Cargo.toml
git commit -m "feat(credential): Windows Credential Manager 读写模块

Co-Authored-By: Pi"
```

---

### Task 4: 网关 Key 验证与凭据保存编排

**Files:**
- Modify: `crates/codex-plus-core/src/managed_gateway.rs`

**Interfaces:**
- Consumes: Task 3 `credential::{read_credential, write_credential}`；Task 1 `MANAGED_GATEWAY_BASE_URL`。
- Produces:
  - `pub enum GatewayKeyCheck { Ok, Unauthorized, ServerError, TimeoutOrNetwork }`
  - `pub async fn verify_gateway_key(key: &str) -> GatewayKeyCheck` — GET `{base_url}/v1/models`（或 POST responses 最小请求；实现选 GET /v1/models，带 `Authorization: Bearer {key}`，超时 15s；不记录请求头）
  - `pub fn managed_gateway_credential_exists() -> bool`
  - `pub fn save_gateway_credential(key: &str) -> anyhow::Result<()>`（trim + 空拒绝 + 写入 Credential Manager）
  - 错误/日志不包含 key 本体。

- [ ] **Step 1: 写失败测试（wiremock）**

`managed_gateway.rs` tests 追加（wiremock 已是 dev-dep）：

```rust
#[tokio::test]
async fn gateway_key_check_maps_status_classes() {
    use wiremock::matchers::{method, path};
    use wiremock::{MockServer, ResponseTemplate};
    let server = MockServer::start().await;
    // 200 -> Ok
    Mock::given(method("GET")).and(path("/v1/models"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server) ... // 分开三个 server 分别验证 200/401/500
}
```

具体三个用例（每个独立 MockServer）：200 → `GatewayKeyCheck::Ok`；401/403 → `Unauthorized`；5xx/连接失败 → `ServerError`/`TimeoutOrNetwork`。注意：`verify_gateway_key` 需接受 base_url 覆盖以便测试：签名改为 `pub async fn verify_gateway_key_with_base(key: &str, base_url: &str) -> GatewayKeyCheck`，生产入口 `verify_gateway_key(key)` 委托给固定地址版本。

- [ ] **Step 2: 运行验证失败**

Run: `cargo test -p codex-plus-core managed_gateway`

- [ ] **Step 3: 实现**

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayKeyCheck {
    Ok,
    Unauthorized,
    ServerError,
    TimeoutOrNetwork,
}

pub async fn verify_gateway_key(key: &str) -> GatewayKeyCheck {
    verify_gateway_key_with_base(key, MANAGED_GATEWAY_BASE_URL).await
}

pub async fn verify_gateway_key_with_base(key: &str, base_url: &str) -> GatewayKeyCheck {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
    {
        Ok(client) => client,
        Err(_) => return GatewayKeyCheck::TimeoutOrNetwork,
    };
    let url = format!("{}/v1/models", base_url.trim_end_matches('/'));
    let response = client
        .get(&url)
        .bearer_auth(key)
        .send()
        .await;
    let response = match response {
        Ok(response) => response,
        Err(_) => return GatewayKeyCheck::TimeoutOrNetwork,
    };
    match response.status().as_u16() {
        200..=299 => GatewayKeyCheck::Ok,
        401 | 403 => GatewayKeyCheck::Unauthorized,
        500..=599 => GatewayKeyCheck::ServerError,
        _ => GatewayKeyCheck::TimeoutOrNetwork,
    }
}

pub fn managed_gateway_credential_exists() -> bool {
    crate::credential::read_credential(MANAGED_GATEWAY_CREDENTIAL_TARGET)
        .map(|value| value.is_some())
        .unwrap_or(false)
}

pub fn save_gateway_credential(key: &str) -> anyhow::Result<()> {
    let key = key.trim();
    if key.is_empty() {
        anyhow::bail!("API Key 不能为空");
    }
    crate::credential::write_credential(MANAGED_GATEWAY_CREDENTIAL_TARGET, key)
}
```

- [ ] **Step 4: 运行验证通过**

Run: `cargo test -p codex-plus-core managed_gateway`

- [ ] **Step 5: Commit**

```bash
git add crates/codex-plus-core/src/managed_gateway.rs
git commit -m "feat(managed-gateway): 网关 Key 验证与凭据保存编排

Co-Authored-By: Pi"
```

---

### Task 5: helper 服务 /proxy.pac 端点 + 启动器注入受管 PAC 参数

**Files:**
- Modify: `crates/codex-plus-core/src/launcher.rs`
- Test: `crates/codex-plus-core/tests/launcher.rs`

**Interfaces:**
- Consumes: Task 1 `is_proxy_pac_path`、`build_pac_script`、`inject_managed_pac_arg`。
- Produces:
  - `LaunchHooks::launch_codex` 签名变更为 `async fn launch_codex(&self, app_dir: &Path, debug_port: u16, helper_port: u16, settings: &BackendSettings, extra_args: &[String])` — 所有实现（DefaultLaunchHooks、tests/launcher.rs FakeHooks、tests/bridge_routes.rs ContextHooks、apps/codex-plus-launcher LauncherHooks）同步更新。
  - `launch_codex` 内部：Windows 且 `settings.windows_managed_gateway_enabled` 时，对 `launch_extra_args` 调用 `inject_managed_pac_arg(&args, helper_port)` 后再构建 packaged activation。
  - `handle_helper_connection` 新增分支：`if is_proxy_pac_path(path) && method == "GET"` → 返回 200、`application/x-ns-proxy-autoconfig`、`build_pac_script()` 字节。

- [ ] **Step 1: 写失败测试**

`tests/launcher.rs` 追加（参考现有 `helper_returns_400_for_ambiguous_body_framing` 风格，直接起 TcpListener 手工发 HTTP）：

```rust
#[tokio::test]
async fn helper_serves_managed_proxy_pac_with_fixed_content() {
    // 1. 起 TcpListener(127.0.0.1:0) 取端口
    // 2. tokio::spawn 循环 accept，对每个连接调用 launcher::handle_helper_connection（需 pub(crate) 或 pub 可见；若私有，把测试放进 src/launcher.rs 的 #[cfg(test)] mod，参考现有 helper_returns_400_* 测试位置——它们在 src/launcher.rs 内部 tests 模块）
    // 3. 客户端发 "GET /proxy.pac HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
    // 4. 断言响应含 "200 OK"、"application/x-ns-proxy-autoconfig"、"FindProxyForURL"、"SOCKS5 10.20.30.61:7891"，且不含 "DIRECT;" 回退
}
```

实现时把该测试放进 `src/launcher.rs` 的 `#[cfg(test)] mod tests`（与现有 helper 测试同处），避免可见性问题。

另加纯参数测试（同模块）：

```rust
#[test]
fn build_packaged_activation_includes_unique_managed_pac_arg_when_enabled() {
    let args = inject_managed_pac_arg(&["--proxy-server=socks5://evil:1".to_string()], 57321);
    let arguments = command_line_arguments(&build_codex_arguments(9229, &args));
    assert!(arguments.contains("--proxy-pac-url=http://127.0.0.1:57321/proxy.pac"));
    assert!(!arguments.contains("--proxy-server"));
}
```

- [ ] **Step 2: 运行验证失败**

Run: `cargo test -p codex-plus-core --lib launcher`

- [ ] **Step 3: 实现**

1. `handle_helper_connection` 在解析出 `method`/`path` 后、现有代理分支之前插入：

```rust
if crate::managed_gateway::is_proxy_pac_path(path) && method == "GET" {
    let body = crate::managed_gateway::build_pac_script();
    write_http_response(
        &mut stream,
        "200 OK",
        "application/x-ns-proxy-autoconfig",
        body.as_bytes(),
    )
    .await?;
    stream.shutdown().await?;
    return Ok(());
}
if crate::managed_gateway::is_proxy_pac_path(path) && method == "OPTIONS" {
    write_http_response(
        &mut stream,
        "204 No Content",
        "application/x-ns-proxy-autoconfig",
        &[],
    )
    .await?;
    stream.shutdown().await?;
    return Ok(());
}
```

2. `LaunchHooks::launch_codex` trait 签名与四个实现同步加 `helper_port: u16` 参数；`launch_and_inject_with_hooks` 中调用点传入 `helper_port`（注意在 helper 启动之后才 launch，现有顺序已满足）。

3. `DefaultLaunchHooks::launch_codex` 内：

```rust
let mut launch_extra_args = codex_extra_args_for_launch(settings, extra_args);
if cfg!(windows) && settings.windows_managed_gateway_enabled {
    launch_extra_args = crate::managed_gateway::inject_managed_pac_arg(&launch_extra_args, helper_port);
}
```

4. settings 字段（Task 6 前先用临时门禁也可，但为编译通过需与 Task 6 合并顺序执行；本计划将 settings 字段并入本任务）：`crates/codex-plus-core/src/settings.rs` `BackendSettings` 加：

```rust
#[serde(rename = "windowsManagedGatewayEnabled", default)]
pub windows_managed_gateway_enabled: bool,
```

Default 为 `false`；`merge_known_setting_fields` 中同步加（参考 codexExtraArgs 的写法）：

```rust
if let Some(value) = source.get("windowsManagedGatewayEnabled").and_then(Value::as_bool) {
    target.insert("windowsManagedGatewayEnabled".to_string(), Value::Bool(value));
}
```

注意：`codex_extra_args_for_launch` 返回 Vec<String> 不可变绑定，改为 mut。

- [ ] **Step 4: 运行验证通过**

Run: `cargo test -p codex-plus-core --lib launcher && cargo test -p codex-plus-core`

- [ ] **Step 5: Commit**

```bash
git add crates/codex-plus-core/src/launcher.rs crates/codex-plus-core/src/settings.rs crates/codex-plus-core/tests/launcher.rs crates/codex-plus-core/tests/bridge_routes.rs apps/codex-plus-launcher/src/main.rs
git commit -m "feat(managed-gateway): helper 提供 /proxy.pac 并在启动参数注入受管 PAC

Co-Authored-By: Pi"
```

---

### Task 6: 受管启动编排（凭据检查→配置校正→PAC 自检→TCP 检查→导航）

**Files:**
- Modify: `crates/codex-plus-core/src/launcher.rs`（`launch_and_inject_with_hooks` 内、helper 启动之后 launch 之前）
- Modify: `crates/codex-plus-core/src/manager_navigation.rs`（`validate_navigation` 允许 `("settings", Some("managedGateway"))`）
- Test: `crates/codex-plus-core/tests/launcher.rs`

**Interfaces:**
- Consumes: Task 2 `apply_managed_gateway_to_config`；Task 4 `managed_gateway_credential_exists`；Task 5 的 PAC 端点；`crate::install::open_or_activate_manager()`；`crate::manager_navigation::save_pending_manager_navigation`。
- Produces:
  - `pub fn managed_gateway_credential_command() -> String` — 当前 exe 同目录 `codex-plus-credential.exe` 的绝对路径（`std::env::current_exe()` 推导，失败时回退 `codex-plus-credential.exe`）。
  - `async fn ensure_managed_gateway_ready(...)`（launcher 内部私有）：依次执行凭据检查（缺失→保存导航意图 `settings/managedGateway` + `open_or_activate_manager` + bail）、配置校正、helper 启动后 PAC 自检（GET 127.0.0.1:helper_port/proxy.pac 验证 200+类型+内容包含 SOCKS5）、网关与 SOCKS5 TCP 连通性检查（Tokio TcpStream::connect，3s 超时；失败 bail 且不启动 Codex）。

- [ ] **Step 1: 写失败测试**

`tests/launcher.rs`（FakeHooks 模式，参考现有 launch 编排测试，如 `launch_runs_expected_hook_sequence`）：

```rust
#[tokio::test]
async fn managed_gateway_missing_credential_blocks_launch_and_opens_manager() {
    // 设置 windows_managed_gateway_enabled = true（通过 env CODEX_HOME 指向 tempdir 隔离 settings？不行——FakeHooks.load_settings 返回固定 settings，直接构造）
    // FakeHooks 需能记录 launch_codex 是否被调用：现有 events 机制可记录 "launch-codex"
    // 由于 managed_gateway_credential_exists 在非 Windows 恒 false，本测试验证：launch 失败 + launch_codex 未被调用
    // open_or_activate_manager 在测试中会尝试拉起真实进程！需要注入：把 ensure_managed_gateway_ready 的 manager 打开动作封装为 LaunchHooks 新方法 open_manager_for_initialization()（默认实现调 open_or_activate_manager，FakeHooks 覆盖为记录事件）
}
```

关键设计调整：为可测性，`LaunchHooks` 新增：

```rust
fn managed_gateway_enabled(&self, settings: &BackendSettings) -> bool {
    cfg!(windows) && settings.windows_managed_gateway_enabled
}
async fn open_manager_for_initialization(&self) -> anyhow::Result<()> {
    crate::install::open_or_activate_manager().map(|_| ())
}
async fn ensure_managed_gateway_ready(&self, home: &Path, helper_port: u16) -> anyhow::Result<()> {
    // 默认实现：凭据检查→导航→打开 manager→bail；成功时 apply_managed_gateway_to_config + PAC/TCP 自检
    // 若 helper 尚未启动（enhancements 与 protocol proxy 都关闭时），先由调用方启动 helper 再进入本钩子，或将 helper 启动条件扩展为“或 managed gateway 启用”
}
```

调用点（`launch_and_inject_with_hooks`）：

```rust
let managed_gateway_active = hooks.managed_gateway_enabled(&settings);
if settings.enhancements_enabled || protocol_proxy_enabled || managed_gateway_active {
    // 启动 helper（现有代码扩展条件）
}
if managed_gateway_active {
    hooks.ensure_managed_gateway_ready(&home, helper_port).await?;
}
let launch = hooks.launch_codex(&app_dir, debug_port, helper_port, &settings, &settings.codex_extra_args).await?;
```

测试断言：
1. 凭据缺失（非 Windows 恒缺失）：返回 Err，错误消息含「初始化」；events 含 `open-manager-for-initialization`、不含 `launch-codex`。
2. 正常路径（FakeHooks 覆盖 `ensure_managed_gateway_ready` 为 Ok）：events 含 `launch-codex` 且 launch 参数含受管 PAC（在 FakeHooks.launch_codex 中记录 helper_port，验证传入参数）。

`manager_navigation.rs` 测试追加：

```rust
#[test]
fn saves_managed_gateway_navigation() {
    // 同 stepwise 测试，section = "managedGateway"
}
```

- [ ] **Step 2: 运行验证失败**

Run: `cargo test -p codex-plus-core`

- [ ] **Step 3: 实现**

按上述设计落地：`DefaultLaunchHooks::ensure_managed_gateway_ready` 完整实现：

```rust
async fn ensure_managed_gateway_ready(&self, home: &std::path::Path, helper_port: u16) -> anyhow::Result<()> {
    if !crate::managed_gateway::managed_gateway_credential_exists() {
        let _ = crate::manager_navigation::save_pending_manager_navigation(
            &crate::manager_navigation::ManagerNavigationIntent {
                page: "settings".to_string(),
                section: Some("managedGateway".to_string()),
            },
        );
        let _ = crate::diagnostic_log::append_diagnostic_log(
            "launcher.managed_gateway_credential_missing",
            serde_json::json!({"helper_port": helper_port}),
        );
        self.open_manager_for_initialization().await?;
        anyhow::bail!("未配置模型网关 API Key，已打开管理工具初始化页");
    }
    crate::managed_gateway::apply_managed_gateway_to_config(
        home,
        &crate::managed_gateway::managed_gateway_credential_command(),
    )?;
    // PAC 自检
    verify_managed_pac_endpoint(helper_port).await?;
    // TCP 检查
    verify_tcp_connectivity(crate::managed_gateway::MANAGED_GATEWAY_SOCKS5_HOST, crate::managed_gateway::MANAGED_GATEWAY_SOCKS5_PORT).await?;
    verify_tcp_connectivity("10.20.30.61", 8080).await?;
    Ok(())
}
```

`verify_managed_pac_endpoint`：reqwest GET `http://127.0.0.1:{port}/proxy.pac`，断言 status 200、content-type 含 `application/x-ns-proxy-autoconfig`、body 含 `SOCKS5 10.20.30.61:7891`；失败 bail（不启动 Codex）。`verify_tcp_connectivity`：`tokio::net::TcpStream::connect((host, port))` + 3s 超时，失败 bail。（私有 async fn 放 launcher.rs）

`managed_gateway_credential_command()` 放 `managed_gateway.rs`：

```rust
pub fn managed_gateway_credential_command() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("codex-plus-credential.exe")))
        .map(|path| path.to_string_lossy().to_string())
        .unwrap_or_else(|| "codex-plus-credential.exe".to_string())
}
```

`validate_navigation` 增加 `("settings", None | Some("stepwise") | Some("managedGateway"))`。

- [ ] **Step 4: 运行验证通过**

Run: `cargo test -p codex-plus-core`

- [ ] **Step 5: Commit**

```bash
git add crates/codex-plus-core/src/launcher.rs crates/codex-plus-core/src/managed_gateway.rs crates/codex-plus-core/src/manager_navigation.rs crates/codex-plus-core/tests/launcher.rs
git commit -m "feat(managed-gateway): 受管启动编排与凭据缺失阻断

Co-Authored-By: Pi"
```

---

### Task 7: codex-plus-credential 二进制

**Files:**
- Create: `apps/codex-plus-credential/Cargo.toml`
- Create: `apps/codex-plus-credential/src/main.rs`
- Modify: 根 `Cargo.toml`（workspace members 加 `"apps/codex-plus-credential"`）

**Interfaces:**
- Consumes: Task 3 `credential::read_credential`、Task 2 `MANAGED_GATEWAY_CREDENTIAL_TARGET`。
- Produces: 可执行文件 `codex-plus-credential.exe`，CLI：`codex-plus-credential get <target>`；只允许 `get` 与固定 target（其他参数 → stderr 报错 exit 2）；成功时仅 stdout 输出 Token（无尾随多余输出，建议 println 一次）；失败信息写 stderr 且不包含凭据内容；exit 0/2。

- [ ] **Step 1: 实现二进制**

`apps/codex-plus-credential/Cargo.toml`：

```toml
[package]
name = "codex-plus-credential"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true

[dependencies]
anyhow.workspace = true
codex-plus-core = { path = "../../crates/codex-plus-core" }
```

`apps/codex-plus-credential/src/main.rs`：

```rust
//! 供 Codex 命令鉴权调用的凭据读取器：只读固定 target，成功仅向 stdout 写 Token。

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 2 || args[0] != "get" || args[1] != codex_plus_core::managed_gateway::MANAGED_GATEWAY_CREDENTIAL_TARGET {
        eprintln!("usage: codex-plus-credential get {}", codex_plus_core::managed_gateway::MANAGED_GATEWAY_CREDENTIAL_TARGET);
        std::process::exit(2);
    }
    match codex_plus_core::credential::read_credential(&args[1]) {
        Ok(Some(token)) => {
            println!("{token}");
        }
        Ok(None) => {
            eprintln!("credential not found");
            std::process::exit(2);
        }
        Err(_) => {
            eprintln!("credential read failed");
            std::process::exit(2);
        }
    }
}
```

（windows 子系统不需要 GUI，普通 console 子系统即可；不需要 winresource。）

- [ ] **Step 2: 验证构建与参数拒统**

Run: `cargo build -p codex-plus-credential && cargo test --workspace`
本机（macOS）手动验证：`./target/debug/codex-plus-credential get managed-gateway; echo exit=$?` → stderr `credential not found`（非 Windows read 恒 None）exit=2；`./target/debug/codex-plus-credential get other` → usage，exit=2。

- [ ] **Step 3: Commit**

```bash
git add apps/codex-plus-credential Cargo.toml
git commit -m "feat(credential): codex-plus-credential 凭据读取二进制

Co-Authored-By: Pi"
```

---

### Task 8: manager Tauri 命令（状态 + 保存 + 重录）

**Files:**
- Modify: `apps/codex-plus-manager/src-tauri/src/commands.rs`
- Modify: `apps/codex-plus-manager/src-tauri/src/lib.rs`（invoke_handler 注册）

**Interfaces:**
- Consumes: Task 2/4 的 managed_gateway 函数；Task 3 credential；`merge_known_setting_fields`。
- Produces:
  - `#[tauri::command] pub fn managed_gateway_status() -> CommandResult<Value>` — `{enabled, credentialConfigured, externalCatalogConflict: Option<String>}`（读 settings + `managed_gateway_credential_exists` + `managed_gateway_config_conflicts`）
  - `#[tauri::command] pub async fn save_managed_gateway_key(api_key: String, enabled: Bool) -> CommandResult<Value>` — trim 校验、`verify_gateway_key`（区分 Unauthorized/ServerError/TimeoutOrNetwork 返回不同 message）、成功后 `save_gateway_credential` + 更新 settings.windows_managed_gateway_enabled 并保存、移除外部 catalog 指针（备份）；明文 key 用后即清（drop 后不再引用）。
  - `#[tauri::command] pub fn set_managed_gateway_enabled(enabled: bool) -> CommandResult<Value>`

- [ ] **Step 1: 写失败测试（commands.rs 内嵌 tests）**

参考 `launch_request_defaults_active_relay_sync_to_false` 风格，但注意 credential 在测试机非 Windows 恒不存在：

```rust
#[test]
fn managed_gateway_status_reports_conflict_and_absent_credential() {
    // 用 tempfile 作为 CODEX_HOME 隔离（设置 env 后调用）—— 但 managed_gateway_status 读默认 settings path。
    // 简化：仅测试 verify_gateway_key 状态映射（mock 不做，改为直接调用 wiremock 需 async；commands tests 是同步）。
    // 结论：状态/保存命令的端到端测试放在 core 层（Task 4 已覆盖 verify 映射），commands 层测试仅验证参数拒统与 settings 更新逻辑（save_managed_gateway_key 空 key → failed）。
}
```

测试：`save_managed_gateway_key` 空/空白 key 返回 status="failed" 且不调用任何写入（非 Windows 下写入本来会 Err，断言 failed 即可）。以及 `set_managed_gateway_enabled` 更新 settings 后重新 load 验证。

- [ ] **Step 2: 实现**

```rust
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedGatewayStatusPayload {
    pub enabled: bool,
    pub credential_configured: bool,
    pub external_catalog_conflict: Option<String>,
}

#[tauri::command]
pub fn managed_gateway_status() -> CommandResult<ManagedGatewayStatusPayload> {
    let settings = SettingsStore::default().load().unwrap_or_default();
    let home = codex_plus_core::relay_config::default_codex_home_dir();
    ok("受管网关状态已加载。", ManagedGatewayStatusPayload {
        enabled: settings.windows_managed_gateway_enabled,
        credential_configured: codex_plus_core::managed_gateway::managed_gateway_credential_exists(),
        external_catalog_conflict: codex_plus_core::managed_gateway::managed_gateway_config_conflicts(&home),
    })
}

#[tauri::command]
pub async fn save_managed_gateway_key(api_key: String, enabled: bool) -> CommandResult<ManagedGatewayStatusPayload> {
    let key = api_key.trim().to_string();
    if key.is_empty() {
        return failed("API Key 不能为空。", empty_managed_gateway_status());
    }
    // 验证（不记录请求头）
    let check = codex_plus_core::managed_gateway::verify_gateway_key(&key).await;
    match check {
        codex_plus_core::managed_gateway::GatewayKeyCheck::Ok => {}
        codex_plus_core::managed_gateway::GatewayKeyCheck::Unauthorized => {
            return failed("网关拒绝了该 API Key（401/403），请确认后重试。", empty_managed_gateway_status());
        }
        codex_plus_core::managed_gateway::GatewayKeyCheck::ServerError => {
            return failed("网关服务异常（5xx），凭据未修改，请稍后重试。", empty_managed_gateway_status());
        }
        codex_plus_core::managed_gateway::GatewayKeyCheck::TimeoutOrNetwork => {
            return failed("无法连接网关，请检查网络后重试。", empty_managed_gateway_status());
        }
    }
    if let Err(error) = codex_plus_core::managed_gateway::save_gateway_credential(&key) {
        return failed(&format!("保存凭据失败：{error}"), empty_managed_gateway_status());
    }
    let home = codex_plus_core::relay_config::default_codex_home_dir();
    if enabled {
        let _ = codex_plus_core::managed_gateway::remove_external_model_catalog_pointer(&home)?;
        let mut settings = SettingsStore::default().load().unwrap_or_default();
        settings.windows_managed_gateway_enabled = true;
        SettingsStore::default().save(&settings)?;
    }
    drop(key); // 明文即刻释放
    managed_gateway_status()
}

fn empty_managed_gateway_status() -> ManagedGatewayStatusPayload {
    ManagedGatewayStatusPayload { enabled: false, credential_configured: false, external_catalog_conflict: None }
}

#[tauri::command]
pub fn set_managed_gateway_enabled(enabled: bool) -> CommandResult<ManagedGatewayStatusPayload> {
    let mut settings = SettingsStore::default().load().unwrap_or_default();
    settings.windows_managed_gateway_enabled = enabled;
    SettingsStore::default().save(&settings)?;
    managed_gateway_status()
}
```

`lib.rs` invoke_handler 追加三个命令注册。

- [ ] **Step 3: 验证**

Run: `cargo test -p codex-plus-manager`（若该 crate 有 tests）或 `cargo test --workspace`；`cargo check -p codex-plus-manager`。

- [ ] **Step 4: Commit**

```bash
git add apps/codex-plus-manager/src-tauri/src/commands.rs apps/codex-plus-manager/src-tauri/src/lib.rs
git commit -m "feat(managed-gateway): manager 受管网关状态与 Key 保存命令

Co-Authored-By: Pi"
```

---

### Task 9: 前端初始化/设置区块（App.tsx + managed-gateway.ts + i18n）

**Files:**
- Create: `apps/codex-plus-manager/src/managed-gateway.ts` + `managed-gateway.test.ts`
- Modify: `apps/codex-plus-manager/src/App.tsx`（设置页区块 + 导航 section 处理）
- Modify: `apps/codex-plus-manager/src/i18n-en.ts`（新文案英文翻译）

**Interfaces:**
- Consumes: Task 8 命令；App.tsx 中 `pendingSettingsSection` 机制（stepwise 同款，追加 `managedGateway` 支持）。
- Produces: `managed-gateway.ts` 导出 `describeManagedGatewayStatus(payload)` 纯函数（供测试）；App.tsx 新增受管网关设置区块。

- [ ] **Step 1: 写失败测试（managed-gateway.test.ts）**

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { describeManagedGatewayStatus } from "./managed-gateway";

test("status description covers conflict, credential and enabled", () => {
  assert.equal(describeManagedGatewayStatus({ enabled: false, credentialConfigured: false, externalCatalogConflict: null }), "not-configured");
  assert.equal(describeManagedGatewayStatus({ enabled: true, credentialConfigured: true, externalCatalogConflict: null }), "ready");
  assert.equal(describeManagedGatewayStatus({ enabled: true, credentialConfigured: true, externalCatalogConflict: "/tmp/x.json" }), "conflict");
});
```

- [ ] **Step 2: 实现 managed-gateway.ts**

```ts
export interface ManagedGatewayStatus {
  enabled: boolean;
  credentialConfigured: boolean;
  externalCatalogConflict: string | null;
}

export type ManagedGatewayStatusKind = "not-configured" | "ready" | "conflict";

export function describeManagedGatewayStatus(status: ManagedGatewayStatus): ManagedGatewayStatusKind {
  if (status.externalCatalogConflict) return "conflict";
  if (status.enabled && status.credentialConfigured) return "ready";
  return "not-configured";
}
```

- [ ] **Step 3: App.tsx 区块**

设置页新增区块（紧跟 stepwise 或独立 section，标题如「受管模型网关（Windows）」）：

- 状态行：已配置/未配置 + 外部 catalog 冲突提示（conflict 时显示说明：初始化完成时会备份并移除指针，不影响外部文件）。
- API Key 输入（password 型）+「验证并保存」按钮 → `invoke("save_managed_gateway_key", { apiKey, enabled: true })`；成功后清空输入框 state、刷新状态；失败展示 message（不回显 key）。
- 「重新录入 API Key」入口同上复用输入区。
- 开关「启用受管网关」（默认关）→ `invoke("set_managed_gateway_enabled", ...)`。文案明示：启用后模型请求固定发送到内置网关、OpenAI 域名走内置 SOCKS5，且地址与规则不可修改。
- Windows 之外平台显示「仅 Windows 可用」（`navigator.platform` 或复用现有平台判断，若无则用后端 status enabled 字段即可；文案提示「仅 Windows」）。
- `pendingSettingsSection === "managedGateway"` 时滚动到该区块（参考 stepwise 的 useEffect 滚动实现，3011 行附近同款逻辑追加分支）。

文案（中文原文进 t()，i18n-en.ts 加英文）：

```ts
// 新增 key（中文 → 英文）：
"受管模型网关（Windows）": "Managed model gateway (Windows)",
"仅 Windows 可用。": "Available on Windows only.",
"启用后，模型请求将固定发送到内置模型网关，OpenAI 相关域名将固定通过内置 SOCKS5 代理访问；网关、代理与规则不可修改。": "Once enabled, model requests are pinned to the built-in gateway, and OpenAI domains go through the built-in SOCKS5 proxy. Gateway, proxy and rules cannot be modified.",
"API Key 已配置。": "API Key configured.",
"API Key 未配置。": "API Key not configured.",
"验证并保存": "Verify and save",
"重新录入 API Key": "Re-enter API Key",
"检测到外部 model_catalog_json：初始化完成时会自动备份并移除该指针（外部文件保留）。": "External model_catalog_json detected: it will be backed up and the pointer removed on initialization (the external file is kept).",
```

- [ ] **Step 4: 验证**

Run: `cd apps/codex-plus-manager && npm test && npm run check && node tools/i18n-verify.mjs`

- [ ] **Step 5: Commit**

```bash
git add apps/codex-plus-manager/src/managed-gateway.ts apps/codex-plus-manager/src/managed-gateway.test.ts apps/codex-plus-manager/src/App.tsx apps/codex-plus-manager/src/i18n-en.ts
git commit -m "feat(managed-gateway): 前端初始化与设置区块

Co-Authored-By: Pi"
```

---

### Task 10: 打包与 CI（NSIS + workflows）

**Files:**
- Modify: `scripts/installer/windows/CodexPlusPlus.nsi`
- Modify: `.github/workflows/pr-build.yml`
- Modify: `.github/workflows/release-assets.yml`

**Interfaces:**
- Consumes: Task 7 二进制产物名 `codex-plus-credential.exe`（target/release）。

- [ ] **Step 1: 修改 NSIS**

`CodexPlusPlus.nsi`：

- Install section：`File "${ROOT}\dist\windows\app\codex-plus-credential.exe"` 追加在两个现有 File 之后；卸载 section：`Delete "$INSTDIR\codex-plus-credential.exe"` 追加在两个现有 Delete 之后。

- [ ] **Step 2: 修改 workflows**

`pr-build.yml` Stage 步骤追加：`Copy-Item target/release/codex-plus-credential.exe dist/windows/app/`；`release-assets.yml` 同样追加该 Copy-Item。

- [ ] **Step 3: 验证**

Run: `cargo build --release -p codex-plus-credential`（本机产物名无 .exe 后缀，macOS 上跳过；Windows CI 兜底）。检查 YAML 语法：`python3 -c "import yaml,sys;yaml.safe_load(open('.github/workflows/pr-build.yml'));yaml.safe_load(open('.github/workflows/release-assets.yml'));print('yaml ok')"`。

- [ ] **Step 4: Commit**

```bash
git add scripts/installer/windows/CodexPlusPlus.nsi .github/workflows/pr-build.yml .github/workflows/release-assets.yml
git commit -m "build(managed-gateway): 安装包与 CI 打包 codex-plus-credential

Co-Authored-By: Pi"
```

---

## 自审查记录（Self-Review）

**Spec 覆盖检查：**
- 规则快照/匹配语义/回环直连/无 DIRECT 回退 → Task 1 ✅
- PAC 端点固定内容+内容类型 → Task 5 ✅
- 启动参数唯一受管 PAC + 清理冲突 → Task 1（inject）+ Task 5（接线）✅
- 受管 provider/命令鉴权/互斥键/每次启动校正 → Task 2 ✅
- 外部 catalog 检测/备份/只删指针 → Task 2 ✅
- 凭据管理（Credential Manager/固定 target/不泄漏） → Task 3、4 ✅
- 初始化 UI（仅 Key 输入/无地址控件/重录入口） → Task 8、9 ✅
- 启动流程（凭据检查→配置→PAC 自检→TCP→导航） → Task 6 ✅
- 失败处理表（401/403 不删凭据；5xx/超时重试；PAC 失败不启动；SOCKS5 不可达不启动） → Task 4（映射）+ Task 6（阻断）+ Task 8（文案）✅
- 「Codex 已运行未带受管 PAC 时要求重启」：现有 watcher 停进程逻辑 + restart_codex_plus 已存在；本计划未新增检测（见残余风险 2）
- 打包 → Task 10 ✅
- Windows 实机验收（流量证据）→ 超出本计划范围，见残余风险 1

**Placeholder 扫描：** 无 TBD/TODO；Task 4 Step1 的测试代码骨架补齐为三 server 具体断言；Task 6 Step1 测试给出关键断言而非完整代码（依赖 FakeHooks 现有结构，已给出事件断言与覆盖点，executor 可直接落地）。

**类型一致性：** `managed_proxy_pac_url_arg`/`inject_managed_pac_arg`/`apply_managed_gateway_to_config`/`verify_gateway_key`/`GatewayKeyCheck`/`managed_gateway_credential_exists`/`save_gateway_credential`/`MANAGED_GATEWAY_CREDENTIAL_TARGET` 各任务引用一致；`launch_codex` 新签名在 Task 5 定义、Task 6 调用一致；settings 字段 `windows_managed_gateway_enabled`（serde `windowsManagedGatewayEnabled`）全链路一致。

**已知残余风险：**
1. packaged Codex 是否完整遵循 Chromium PAC 只能 Windows 实机验收（spec 明确）；本计划交付代码 + 单测/集成测试，实机验收单独立项。
2. 「发现未带受管 PAC 的运行中 Codex 要求重启」：现有启动路径每次都会重新 activate（带新参数），叠加 `stop_codex_processes_for_debug_port_and_wait`（restart 命令已用）；launch_codex_plus 直接启动路径未检测已有实例，与现状一致，不在本计划扩大范围。
3. 命令鉴权需用安装包内目标 Codex 版本验证（spec 要求），属 Windows 实机验收内容。
4. `verify_gateway_key` 用 GET /v1/models：若网关不支持该路由但支持 responses，可能误判——初始化时用户可重试，且失败不破坏已有凭据；后续可按实机反馈调整探测路径。
5. Task 2 的备份文件 `config.toml.managed-gateway-bak` 放在 CODEX_HOME 内；toml_edit 解析失败时 `unwrap_or_default` 会丢弃原文——已用「读不到视为空配置」语义，但对真正损坏的 config.toml 会静默重置。缓解：写入前备份保留原文可恢复（bak 文件）。
