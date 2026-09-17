# 实施计划：受管网关本地分流代理（方案 B）

设计依据：`docs/superpowers/specs/2026-09-17-managed-gateway-local-proxy-design.md`
分支：`claude/windows-managed-gateway-pac`（续用）

## 已定决策

- 保留 fail-closed（与「禁止 DIRECT 回退」一致）
- 代理端口默认 `17891`，支持环境变量覆盖
- 写 `~/.codex/.env` 已获用户确认
- U3（`NO_PROXY`）不单独验证，靠 §4.2 明文转发冗余兜底

## 技术前提（已勘查确认）

- helper 服务是手写 `tokio::net::TcpListener` + 自解析 HTTP（`launcher.rs:918`、`:1308`），
  本地代理沿用同一风格，不引入 hyper/axum
- workspace tokio 已含 `macros`/`process`/`rt-multi-thread`/`time`，core 额外 `io-util`/`net`/`sync`
- SOCKS5 握手手写字节，**不新增依赖**
- 规则判定复用 `managed_gateway::pac_result_for_host`，不写第二份真相

## 任务列表

全部按 TDD：先写测试→看失败→实现→看通过。纯函数先行，本机可全量验证。

### T1 `.env` 块编辑纯函数

位置：`crates/codex-plus-core/src/managed_env.rs`（新文件）

```rust
pub fn render_managed_env_block(proxy_port: u16) -> String
pub fn upsert_managed_env_block(existing: &str, proxy_port: u16) -> String
pub fn remove_managed_env_block(existing: &str) -> String
pub fn managed_env_file_path(codex_home: &Path) -> PathBuf
```

要求：标记注释包裹、块固定追加到末尾（dotenv 后定义胜出）、反复调用幂等、
完整保留用户其他行、移除后无残留空行堆积。

测试：空文件新建 / 已有用户行追加 / 重复 upsert 只一块 / 换端口重写 / remove 幂等 /
CRLF 混用 / 用户自己写了 `HTTPS_PROXY` 时仍以我们的块为准。

### T2 代理请求行解析纯函数

位置：`crates/codex-plus-core/src/managed_proxy.rs`（新文件）

```rust
pub enum ProxyRequestKind { Connect, Plain }
pub struct ProxyTarget { pub host: String, pub port: u16, pub kind: ProxyRequestKind }
pub fn parse_proxy_request_line(line: &str) -> Option<ProxyTarget>
```

要求：`CONNECT host:443 HTTP/1.1` 与绝对 URI `GET http://host:8080/p?q HTTP/1.1` 两类；
缺端口默认 CONNECT=443 / http=80；IPv6 字面量、大小写、非法输入均有用例。

### T3 分流决策纯函数

```rust
pub enum RouteDecision { Socks5, Direct }
pub fn route_for_host(host: &str) -> RouteDecision
```

包裹 `pac_result_for_host`；网关主机 `10.20.30.61` 与回环地址强制 `Direct`。
测试：OpenAI 精确域名/后缀/关键字命中→Socks5；网关、github.com、127.0.0.1→Direct。

### T4 SOCKS5 客户端字节层

```rust
pub fn build_socks5_greeting() -> [u8; 3]
pub fn build_socks5_connect_request(host: &str, port: u16) -> anyhow::Result<Vec<u8>>
pub fn parse_socks5_method_reply(bytes: &[u8]) -> anyhow::Result<()>
pub fn parse_socks5_connect_reply(bytes: &[u8]) -> anyhow::Result<()>
```

无认证（METHOD=0x00）、域名寻址 `ATYP=0x03`（不本地解析 DNS，交给上游，与 PAC 语义一致）。
测试：字节级断言 + REP≠0x00 错误映射 + 过长域名（>255）报错。

### T5 代理服务主体

```rust
pub struct ManagedProxyHandle { pub port: u16 }
pub async fn spawn_managed_proxy(port: u16) -> anyhow::Result<ManagedProxyHandle>
```

- CONNECT：`200 Connection Established` + `tokio::io::copy_bidirectional`
- 明文：重写请求行为 origin-form 后透传（不解析 body、不改头）
- 命中规则且上游失败 → `502`，**无直连尝试**
- 超时：上游连接 3s、SOCKS5 握手 3s
- 自识端点 `GET /__managed_proxy_id` 返回固定标识（供 T6 探测复用）
- 日志仅 `{host, port, decision, upstream_ok, duration_ms}`，**不写请求头与 URL query**

测试（tokio 集成，假上游 + 假目标）：命中→经 SOCKS5 双向透传；命中但上游拒连→502
且假目标断言未收到连接；未命中→直达假目标；明文转发保留 query。

### T6 端口策略

```rust
pub fn managed_proxy_port() -> u16            // 默认 17891，CODEX_PLUS_MANAGED_PROXY_PORT 可覆盖
pub async fn probe_existing_managed_proxy(port: u16) -> bool
```

占用处理：探测 `/__managed_proxy_id` 命中→复用旧实例；否则报错阻断启动，不默默换端口。

### T7 启动编排接入

改 `launcher.rs::default_ensure_managed_gateway_ready`，在现有 4 步中插入：

1. 凭据检查（不变）
2. `apply_managed_gateway_to_config`（不变）
3. **新：启本地代理 + 自测**
4. **新：写 `.env` 块**
5. PAC 端点自检（不变，供 Chromium UI 层）
6. TCP 可达性（不变）

代理 handle 用 `OnceLock<ManagedProxyHandle>` 保活，避免重复启动。
测试：`tests/launcher.rs` FakeHooks 新增 `managed_proxy_started` 计数；代理自测失败→
不启 Codex、不写 `.env`。

### T8 关闭与卸载清理

- `commands.rs::set_managed_gateway_enabled(false)` → `remove_managed_env_block`
- NSIS 卸载脚本移除 `.env` 块（不删整个文件）

### T9 前端

面板显示代理端口与「受管模式下请从本工具启动 Codex」说明，含 `i18n-en.ts` 对应项。

### T10 验证与文档

`cargo test --workspace` / `npm test` / `npm run check` / `npm run vite:build` 全绿；
设计文档补实现后的实际行为差异。

## 验证命令

```bash
cargo test -p codex-plus-core managed_env
cargo test -p codex-plus-core managed_proxy
cargo test --workspace
```

## 风险提醒

- pi-lens 每轮会 autofix 弄脏 30-40 个无关文件，每次提交前 `git status` 隔离
- `docs/superpowers/` 被 gitignore，文档需 `git add -f`
