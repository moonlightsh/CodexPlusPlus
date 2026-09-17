# Windows 受管网关：本地分流代理设计（方案 B）

状态：待审核
取代：`2026-09-16-windows-managed-gateway-pac-design.md` 中的「Chromium PAC 启动参数」机制部分
日期：2026-09-17

## 1. 为什么要改

上一版设计假设「代理范围仅由 Codex 的 Chromium 启动参数确定」。Windows 实测证伪了这个假设。

实测进程列表：

```text
codex-plus-plus.exe   （本工具启动器）
codex.exe  -c features.code_mode_host=true app-server --analytics-default-enabled -c plugins...
```

发出模型与 OpenAI 请求的是 `codex.exe app-server` —— Rust 版 codex 引擎，由 Codex 桌面应用
（`ChatGPT.exe`，Chromium/Electron）自己 spawn。两个后果：

1. `--proxy-pac-url` 是 Chromium 开关，只作用于 `ChatGPT.exe` 自身网络栈（登录 webview、遥测），
   对 `codex.exe` 无效。
2. `codex.exe` 的命令行由 Codex 应用拼装，本工具注入的参数不会传递给它。

结论：PAC 机制选错了作用对象，需要改为对 codex 引擎生效的通道。

## 2. 已核实的上游事实

以下均查证自 openai/codex 源码，是本设计的立足点。

| 事实 | 出处 |
| --- | --- |
| codex 从 `CODEX_HOME/.env` 加载环境变量，过滤掉 `CODEX_` 前缀的键 | `arg0/src/lib.rs` 的 `load_dotenv()` → `dotenvy::from_path_iter(codex_home.join(".env"))` |
| `.env` 注入是官方支持路径 | `app-server/tests/suite/v2/{account,bedrock_setup}.rs` 用 `codex_home/.env` 注入凭据 |
| reqwest 集成集中在 `codex-http-client`，产品代码不自建 client | `http-client/README.md` |
| 出站代理策略含 system、PAC/WPAD、environment、direct 四类 | 同上 |
| `RespectSystemProxy`：系统设置与 PAC/WPAD → 显式代理环境变量 → 直连 | 同上「Outbound proxy policy」 |
| `ReqwestDefault`：保留 reqwest 传统行为（读代理环境变量） | 同上 |

关键推论：**两种模式最终都会考虑「代理环境变量」这一层**。因此用 `.env` 注入 `HTTPS_PROXY`
不依赖 `respect_system_proxy` 的取值（前提见 §9 U1）。

## 3. 总体架构

新增一个**本地分流 HTTP 代理**，把原 PAC 脚本里的域名判定搬到这个代理内部；
通过 `~/.codex/.env` 把 codex 引擎指向它。

```text
codex.exe (app-server, reqwest)
  │  读 ~/.codex/.env → HTTPS_PROXY=http://127.0.0.1:<local_port>
  │                       HTTP_PROXY 同值，NO_PROXY=10.20.30.61,127.0.0.1,localhost
  ▼
本地分流代理（仅绑 127.0.0.1）
  ├─ 命中 OpenAI 域名规则 → 上游 SOCKS5 10.20.30.61:7891 建道
  ├─ 网关 10.20.30.61:8080 → 直连转发
  └─ 其他 → 直连转发
       └─ 命中规则但 SOCKS5 不可用 → 502 断开，绝不回退直连


ChatGPT.exe (Chromium UI)
  └─ 保留 --proxy-pac-url → helper /proxy.pac（登录/webview 流量）
```

两层共用同一套规则纯函数，避免两份真相。

## 4. 本地分流代理

新模块 `crates/codex-plus-core/src/managed_proxy.rs`。

### 4.1 监听与端口

- 仅绑 `127.0.0.1`，不绑 `0.0.0.0`；不做任何鉴权（等同于本机任意进程可用，与 Clash 等工具同类风险，已知并接受）。
- **固定端口**（默认 `17891`），不用动态端口。理由：`.env` 是持久文件，而 codex.exe 的寿命
  与本工具不一致；动态端口会造成 `.env` 内容与实际监听不一致。
- 端口被占：先探测已监听者是否是本工具自己的旧实例（请求 `/__managed_proxy_id` 比对标识）；
  是则复用，否则报错阻断启动（不默默换端口）。

### 4.2 必须同时支持两种代理语义

| 目标 | 请求形式 | 处理 |
| --- | --- | --- |
| HTTPS（如 `chatgpt.com:443`） | `CONNECT host:443` | 建隧道，不解密 TLS |
| 明文 HTTP（如网关 `http://10.20.30.61:8080/...`） | `GET http://host/path` 绝对 URI | 转发请求 |

为什么两种都要做：网关是明文 HTTP，如果 `NO_PROXY` 未被尊重（§9 U3），网关请求会落到本地代理；
只实现 CONNECT 会直接断模型调用。两层冗余使任一层失效都不致命。

### 4.3 分流判定

直接复用现有 `managed_gateway::pac_result_for_host`（同一套 7 精确域名 + 24 后缀 +
关键字 `openai` 规则快照），不新写判定逻辑：

- 返回 `SOCKS5 10.20.30.61:7891` → 走上游 SOCKS5
- 返回 `DIRECT` → 直连

判定输入只有主机名（CONNECT 的 authority 或绝对 URI 的 host），不依赖 path。

### 4.4 不回退语义（沿用原 spec 约束）

- 命中规则但 SOCKS5 拨号失败/超时 → 返回 `502 Bad Gateway` 并关连接，**绝不改走直连**。
- 上游 SOCKS5 握手超时：连接 3s、握手 3s。
- 不实现重试；重试策略属于 codex 客户端。

### 4.5 日志与凭据

- CONNECT 不解密，天然接触不到 `Authorization`。
- 明文转发路径会看到请求头：**禁止记录请求头与 body**，诊断日志只写
  `{host, port, decision, upstream_ok, duration_ms}`，不写 URL query。
- 新增事件：`managed_proxy.listening`、`managed_proxy.route`（采样）、
  `managed_proxy.upstream_failed`、`managed_proxy.port_conflict`。

## 5. 注入通道：`~/.codex/.env`

### 5.1 写入内容

```dotenv
# >>> codex-plus-plus managed gateway (自动生成，请勿手改) >>>
HTTPS_PROXY=http://127.0.0.1:17891
HTTP_PROXY=http://127.0.0.1:17891
NO_PROXY=10.20.30.61,127.0.0.1,localhost
# <<< codex-plus-plus managed gateway <<<
```

### 5.2 编辑规则

- **幂等块编辑**：只管两个标记注释之间的内容，完整保留用户其他行。
- 关闭开关或卸载时移除整块；若文件只剩空白则删文件。
- 写入前先备份 `．env.codexplusplus.bak`（沿用仓库现有备份命名习惯）。
- 若用户已在块外自行定义 `HTTPS_PROXY`：dotenv 后者覆盖前者，故把我们的块放在
  **文件末尾**，并在 UI 提示已接管代理变量。
- **不写任何凭据**到 `.env`；API Key 仍只在 Credential Manager。

## 6. 启动编排（改动现有 `ensure_managed_gateway_ready`）

顺序固定，任一步失败则**不启动 Codex**：

1. 凭据检查：Credential Manager 无 Key → 开管理工具到 `managedGateway` 录入页（不变）。
2. 受管 config.toml 校正（不变）。
3. **启本地分流代理**并自测：向自己发一次 `CONNECT chatgpt.com:443`，验证能经 SOCKS5 建道；
   再发一次对非 OpenAI 主机的判定（不实际连接）确认返回 DIRECT。
4. **写 `.env` 块**（幂等）。
5. TCP 可达性：网关 8080 与 SOCKS5 7891（不变）。
6. 启动 Codex，仍带 `--proxy-pac-url`（依旧服务 Chromium UI 层）。

先启代理再写 `.env` 的理由：避免 `.env` 指向一个没人监听的端口。

## 7. 生命周期（本方案最大的新风险）

`.env` 是持久的，但本地代理只活在本工具进程内。三种失配场景：

| 场景 | 后果 | 处理 |
| --- | --- | --- |
| 本工具退出，Codex 仍在跑 | 代理端口消失 → codex 请求全失败 | fail-closed，符合「禁止回退直连」；退出时弹提示 |
| 用户不经本工具直接开 Codex | `.env` 仍指向未监听端口 → 请求失败 | 同上；需在 UI 说明「受管模式下请从本工具启动」 |
| 卸载本工具 | `.env` 残留 | 卸载脚本移除块 |

这是与旧方案相比真正新增的代价：旧方案的启动参数随进程生灭，不会残留。
**需你确认接受 fail-closed**；若不接受，备选是把代理做成常驻服务（开机自启），但那是更大的变更。

### 7.1 子进程继承（实机验证发现，旧设计未计及）

`load_dotenv()` 用 `std::env::set_var` 把变量写进 codex 自身进程环境，因此 codex spawn 的
**所有子进程都会继承代理变量**。验证日志里的 `from=git-remote-https(3908) CONNECT github.com:443`
就是 codex 内部执行 git 时的子进程。

影响：

- 功能上无害——非 OpenAI 域名走我们的直连转发，结果与原本直连等价。
- 但本地代理从「只转模型流量」变成「转 codex 内全部命令行流量」（git、npm、curl 等），
  故障面与吸收的并发量都比预期大。
- **fail-closed 的影响范围随之扩大**：本工具未运行时，不仅模型调用失败，codex 内的
  `git push` / `npm install` 也会一并失败。这是 §12 决策点 1 需要重新衡量的部分。

缓解选项（待定）：代理对未命中规则的目标使用短超时 + 连接池，并在自身不可用时
尽快失败而非挂起，避免拖死用户命令。

## 8. 与旧设计的差异

| 旧设计 | 本方案 |
| --- | --- |
| 代理范围由 Chromium 启动参数确定 | 引擎侧由 `.env` 代理变量确定；UI 侧保留 Chromium 参数 |
| PAC 脚本由 helper 供 Chromium 拉取 | 规则同时用于本地代理的进程内判定，helper 端点保留 |
| 不写任何代理配置 | 仍不写 Windows 用户/机器级代理，但写应用级 `~/.codex/.env` |
| 无常驻组件 | 新增一个会话级本地监听端口 |

保留不变：固定网关与 SOCKS5 地址、规则快照、Key 只进 Credential Manager、Windows-only 且 opt-in、
命令鉴权与 `env_key` 互斥、凭据缺失阻断启动。

## 9. 假设验证结果（2026-09-17 Windows 实机）

验证手法：`~/.codex/.env` 写 `HTTP(S)_PROXY=http://127.0.0.1:17891`，本机起一个只打印请求首行
与发起进程名、固定回 502 的探针，直接启动 Codex（不经本工具，排除 PAC 参数干扰）。

探针实际输出（节选）：

```text
from=codex(14908)  request=CONNECT auth.openai.com:443 HTTP/1.1
from=codex(14908)  request=CONNECT chatgpt.com:443 HTTP/1.1
from=codex(14908)  request=GET http://10.20.30.61:8080/models?client_version=0.154.0 HTTP/1.1
from=git-remote-https(3908)  request=CONNECT github.com:443 HTTP/1.1
```

| 编号 | 假设 | 结果 |
| --- | --- | --- |
| U1 | codex 采用 `.env` 里的 `HTTPS_PROXY` | **成立**：`from=codex(14908)` 直接认定发起进程 |
| U2 | 系统设置不会盖掉 env | **成立**：`ProxyEnable=0`、`AutoConfigURL` 为空 |
| U3 | `NO_PROXY` 被尊重 | **未验证**；不阻塞实施（§4.2 已内建冗余） |
| U4 | `load_dotenv` 在 `app-server` 子命令下执行 | **成立**：本次 codex 即以 `app-server` 运行 |
| U5 | 引擎接受 `http://` 上游代理 | **成立**：CONNECT 与明文转发两类请求均到达代理 |

附带确认的两件事：

1. **明文 HTTP 转发是必选项**。网关 `GET http://10.20.30.61:8080/models` 确实经过代理，只实现
   CONNECT 会直接提断模型调用。同时说明受管 provider 已在 `config.toml` 生效。
2. **代理变量会被 codex 的子进程继承**——日志里的 `git-remote-https` 就是证据，见 §7.1。

## 10. 测试计划

纯函数层（跳平台，本机可跑）：

- 请求行解析：`CONNECT host:443` / 绝对 URI `GET http://h/p` / 非法输入
- 分流判定复用现有规则测试，新增「网关主机 → DIRECT」用例
- `.env` 块编辑：新建/重写/移除/保留用户行/反复幂等

集成层（tokio + 本地假上游）：

- 命中规则且假 SOCKS5 可用 → 隧道建立、字节双向透传
- 命中规则但 SOCKS5 拒连 → 502 且**无直连尝试**（用假目标服务器断言未收到连接）
- 未命中 → 直连到假目标
- 端口被占且非本工具 → 报错阻断，不换端口
- 启动编排：代理自测失败 → 不启动 Codex、不写 `.env`

Windows-only 层（仅 CI）：`.env` 路径解析与换行符。

## 11. 改动面

| 文件 | 改动 |
| --- | --- |
| `crates/codex-plus-core/src/managed_proxy.rs` | 新增：监听、CONNECT、明文转发、SOCKS5 拨号 |
| `crates/codex-plus-core/src/managed_gateway.rs` | 新增 `.env` 块编辑纯函数；规则函数复用不改 |
| `crates/codex-plus-core/src/launcher.rs` | `ensure_managed_gateway_ready` 插入启代理 + 写 `.env` |
| `apps/codex-plus-manager/src-tauri/src/commands.rs` | 关开关时清理 `.env` 块 |
| `apps/codex-plus-manager/src/App.tsx` | 面板增显示代理端口与「请从本工具启动」说明 |
| `scripts/installer/windows/*.nsi` | 卸载时移除 `.env` 块 |

预估：纯函数 + 代理实现约 500 行，测试约 400 行。

## 12. 需你定的事

已定：

- 写 `~/.codex/.env` 可接受（你 2026-09-17 确认）。
- §9 的验证已作为第 0 步完成，结论全部支持方案 B。

待定：

1. **fail-closed 是否接受**，且注意范围已因 §7.1 扩大：本工具未运行时，除模型调用失败外，
   codex 内的 `git push` / `npm install` 等子进程请求也会一并失败。
   备选：代理改为常驻服务（开机自启），变更更大；或退出时主动清理 `.env` 块（但会让
   正在跑的 codex 失去分流，不建议）。
2. **固定端口取值**（默认 `17891`）是否可用、是否需要可配。
3. 是否要顺便跑轮 2 验证 `NO_PROXY`（U3）。不跑也能实施，但跑了可以把网关流量
   从本地代理卸下来，减少一跳转发。







