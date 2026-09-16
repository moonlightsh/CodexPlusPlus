# Windows 固定模型网关与 OpenAI PAC 分流设计

## 背景

基于 CodexPlusPlus 对 Windows Codex 桌面应用进行受管封装。第一版固定模型网关、SOCKS5 代理和 OpenAI 域名规则，同时保留 ChatGPT 官方登录、插件等官方功能。用户只在首次启动时录入模型网关 API Key，不提供网关、代理或规则的修改入口。

本设计只约束 Codex 主体产生的网络请求。Codex 执行的 Shell 命令、MCP 服务及其他用户启动的子进程不属于代理覆盖范围。

## 目标

- 模型请求固定发送到 `http://10.20.30.61:8080`。
- OpenAI 相关域名固定通过 `socks5://10.20.30.61:7891` 访问。
- 未命中 OpenAI 规则的 Codex 主体请求保持直连。
- 保留 ChatGPT 官方登录、插件及其他依赖官方服务的 Codex 功能。
- 使用 Codex 自带模型目录；网关支持这些模型，不维护第二份模型白名单。
- API Key 由用户首次启动时录入，保存到 Windows Credential Manager。
- 匹配的 OpenAI 请求在 SOCKS5 不可用时失败，不回退到直连。

## 非目标

- 不代理 Shell、MCP 或其他工具子进程。
- 不修改 Windows 系统代理。
- 不支持 macOS 或 Linux。
- 不支持用户修改网关地址、SOCKS5 地址或 OpenAI 规则。
- 不采用上游规则中的 `IP-CIDR` 和 `IP-ASN`。
- 不在运行时自动下载规则。

## 总体架构

Windows Codex 继续由 CodexPlusPlus 通过 packaged app activation 启动。启动前，本地辅助服务提供固定 PAC 内容，并由启动器为 Codex 增加 `--proxy-pac-url=http://127.0.0.1:{helper_port}/proxy.pac` 参数；`helper_port` 使用本次启动已选定并成功监听的辅助服务端口。

网络路径如下：

```text
Codex 主体
  ├─ 模型请求：http://10.20.30.61:8080
  │    └─ DIRECT
  ├─ 命中 OpenAI 域名规则的官方请求
  │    └─ SOCKS5 10.20.30.61:7891
  └─ 其他请求
       └─ DIRECT
```

该方案不向 Windows 用户级或机器级代理配置写入数据，代理范围仅由 Codex 的 Chromium 启动参数确定。

## OpenAI 域名规则

规则来源为 BlackMatrix7 的 [OpenAI Clash 规则](https://github.com/blackmatrix7/ios_rule_script/blob/master/rule/Clash/OpenAI/OpenAI.yaml)。第一版使用项目在 2025-06-06 发布的域名类规则快照。规则只随应用版本更新，启动时不访问远端地址。

### 精确域名

- `browser-intake-datadoghq.com`
- `chat.openai.com.cdn.cloudflare.net`
- `openai-api.arkoselabs.com`
- `openaicom-api-bdcpf8c6d2e9atf6.z01.azurefd.net`
- `openaicomproductionae4b.blob.core.windows.net`
- `production-openaicom-storage.azureedge.net`
- `static.cloudflareinsights.com`

### 域名后缀

- `ai.com`
- `algolia.net`
- `api.statsig.com`
- `auth0.com`
- `chatgpt.com`
- `chatgpt.livekit.cloud`
- `client-api.arkoselabs.com`
- `events.statsigapi.net`
- `featuregates.org`
- `host.livekit.cloud`
- `identrust.com`
- `intercom.io`
- `intercomcdn.com`
- `launchdarkly.com`
- `oaistatic.com`
- `oaiusercontent.com`
- `observeit.net`
- `openai.com`
- `openaiapi-site.azureedge.net`
- `openaicom.imgix.net`
- `segment.io`
- `sentry.io`
- `stripe.com`
- `turn.livekit.cloud`

后缀规则同时匹配根域名及其所有子域名，且必须按 DNS 标签边界匹配。例如，`openai.com` 可以匹配 `api.openai.com`，不能匹配 `notopenai.com`。

### 域名关键字

- `openai`

关键字匹配只检查规范化后的主机名，不检查完整 URL、路径或查询参数。

### PAC 行为

PAC 的 `FindProxyForURL(url, host)` 先对 `host` 转为小写并移除末尾的点，再按精确域名、后缀、关键字的顺序匹配。命中返回：

```text
SOCKS5 10.20.30.61:7891
```

未命中返回：

```text
DIRECT
```

`10.20.30.61`、`localhost`、`127.0.0.1` 和 `::1` 在任何规则之前明确返回 `DIRECT`，确保模型网关和本地辅助服务不会进入 SOCKS5。

PAC 不在 SOCKS5 结果后追加 `DIRECT`，避免代理不可用时发生静默直连。

## 模型网关配置

Codex 使用“官方登录 + API”模式：官方登录状态保留在既有认证存储中，模型请求固定使用受管自定义 provider。

受管配置包含：

```toml
model_provider = "managed_gateway"

[model_providers.managed_gateway]
name = "Managed Gateway"
base_url = "http://10.20.30.61:8080"
wire_api = "responses"

[model_providers.managed_gateway.auth]
command = "C:\\Program Files\\CodexPlusPlus\\codex-plus-credential.exe"
args = ["get", "managed-gateway"]
```

安装程序允许改变安装目录，因此配置生成器必须把 `command` 改写为当前安装目录下 `codex-plus-credential.exe` 的规范化绝对路径。命令鉴权不能与 `env_key`、`experimental_bearer_token` 或 `requires_openai_auth` 同时出现。实现阶段必须用安装包内目标 Codex 版本验证命令鉴权，不能只依据配置解析测试宣称可用。

每次启动只校正下列受管内容：

- `model_provider`
- `model_providers.managed_gateway`
- 由本功能写入的 PAC 启动参数
- 由本功能生成的旧版受管 catalog 指针（若存在）

其他 Codex 配置和官方登录数据继续保留。受管配置不写入 `auth.json` 中的 `OPENAI_API_KEY`，也不删除官方登录令牌。

## 模型目录

- 不设置供应商模型白名单。
- 不为本功能生成 `model_catalog_json`。
- 保留 Codex 自带模型目录和模型选择界面。
- 不固定 `model`，新安装默认使用目标 Codex 版本的默认模型。
- 用户在 Codex 中切换内置模型时，请求仍由 `managed_gateway` provider 发送。
- Codex 升级后新增的内置模型自动进入可选范围，不要求同步修改封装程序。

若现有用户配置了外部 `model_catalog_json`，初始化界面必须说明它会影响“全部内置模型”的目标，并在用户完成初始化时备份原配置、移除该指针。不得删除外部 catalog 文件本身。

## API Key 与凭据管理

首次启动时，管理工具显示只包含 API Key 的初始化页面。网关地址、代理地址和规则均不提供输入控件。

保存流程：

1. 对输入做前后空白清理，空值直接拒绝。
2. 使用该 Key 调用固定网关的模型接口，验证网络连通性和鉴权结果。
3. 验证成功后，将 Key 写入当前 Windows 用户的 Credential Manager。
4. 配置文件只保存凭据标识和读取命令，不保存 Key。
5. 清空前端状态中的明文 Key，并避免将其放入事件、日志和错误对象。

设置页保留“重新录入 API Key”入口。该入口可以覆盖现有凭据，但不能修改网关、代理或规则。

凭据读取程序只允许读取固定凭据标识，成功时仅向标准输出写入 Token。失败信息写入标准错误且不得包含凭据内容。诊断日志只记录成功、缺失或读取失败等状态。

## 启动流程

1. 检查 Windows Credential Manager 是否存在网关凭据。
2. 凭据缺失时打开初始化页面，不启动 Codex。
3. 备份并校正受管 Codex 配置。
4. 启动本地辅助服务。
5. 从本地 `/proxy.pac` 读取 PAC，检查状态码、内容类型和核心代理结果。
6. 检查网关 TCP 连通性及 SOCKS5 TCP 连通性。检查只用于给出明确错误，不代表实际业务请求验证成功。
7. 使用带 `--proxy-pac-url` 的 packaged app activation 启动 Codex。
8. 继续执行 CodexPlusPlus 现有的 CDP 注入和界面增强流程。

若发现 Codex 已经在未带受管 PAC 参数的状态下运行，启动器应要求关闭并重新启动该实例，不能复用现有进程。

## 失败处理

| 场景 | 行为 |
| --- | --- |
| API Key 缺失 | 不启动 Codex，进入初始化页 |
| 网关返回 `401` 或 `403` | 不删除已有凭据，提示重新录入并在成功后覆盖 |
| 网关超时或返回 `5xx` | 保留凭据，提供重试；不把临时故障判为 Key 无效 |
| PAC 服务启动失败 | 不启动 Codex，记录不含敏感信息的诊断事件 |
| PAC 内容自检失败 | 不启动 Codex |
| SOCKS5 TCP 不可达 | 默认不启动 Codex，提示代理不可用并允许重试 |
| Codex 运行期间 SOCKS5 中断 | 命中的请求失败，不回退直连 |
| 受管配置写入失败 | 恢复启动前备份，不启动 Codex |
| 官方登录过期 | 由 Codex 官方登录流程处理，不影响网关凭据 |

所有外部写入采用临时文件加原子替换。若进程在写入后未返回明确结果，下一次启动先读取现状并对账，不能盲目重复覆盖或回滚。

## 安全与隐私

- API Key 不写入 CodexPlusPlus 设置、`config.toml`、`auth.json` 或日志。
- UI 不回显已保存的完整 Key，只显示是否已配置。
- API Key 验证请求不记录 Authorization 请求头。
- PAC 仅绑定回环地址，不接受局域网访问。
- PAC 响应为固定生成内容，不接收用户输入，避免脚本注入。
- 诊断导出必须对 URL 查询参数和请求头做敏感信息清理。
- 规则快照更新需经过代码评审和测试，不能把远程 `master` 分支当作运行时信任源。

## 测试设计

### 单元测试

- 精确域名只匹配完全相同的主机名。
- 后缀规则匹配根域名和子域名，并拒绝无标签边界的相似域名。
- 关键字规则大小写不敏感。
- 尾随点和大小写得到一致结果。
- 网关 IP和回环地址始终直连。
- 匹配结果只返回 SOCKS5，不包含 `DIRECT` 回退。
- PAC 端点返回正确内容类型和固定内容。
- 启动参数包含唯一的受管 `--proxy-pac-url`，并清理冲突的用户代理参数。
- 配置合并保留无关字段和官方登录数据。
- 受管 provider、网关地址和认证命令在每次启动时被校正。
- 自定义 `model_catalog_json` 在初始化确认后只移除指针，不删除其目标文件。
- 凭据缺失、读取失败、`401/403`、超时和 `5xx` 分别进入正确状态。
- 日志和错误对象不包含测试 API Key。

### Windows 集成测试

- 在临时 Credential Manager 目标中完成凭据的写入、读取、覆盖和清理。
- 使用模拟网关验证鉴权头和 Responses 请求目的地。
- 使用模拟 SOCKS5 服务验证命中域名进入代理，普通域名和网关地址不进入代理。
- 使用假的 packaged activation 接口验证启动顺序和失败阻断。

### Windows 实机验收

- 全新用户首次启动可以录入 Key 并进入 Codex。
- Key 不以明文出现在本地设置、Codex 配置和诊断日志中。
- 至少选择两个 Codex 内置模型并成功完成真实 Responses 请求。
- SOCKS5 服务端能观察到 OpenAI 规则域名连接。
- 网关和普通非 OpenAI 域名没有进入 SOCKS5。
- 断开 SOCKS5 后，OpenAI 请求失败且没有直连证据。
- ChatGPT 官方登录、插件入口及至少一个官方功能可以使用。
- Codex 已运行、代理不可用、网关不可用和 Key 失效时均出现预期恢复流程。

packaged Codex 是否完整遵循 Chromium PAC 必须以 Windows 实机流量证据为准。单元测试、模拟 SOCKS5 或进程正常运行都不能替代该验收门槛。

## 兼容性与升级

- 目标 Codex 版本升级时，检查 packaged activation 是否继续接受 `--proxy-pac-url`。
- 检查 Codex 命令鉴权配置格式是否保持兼容。
- 检查官方功能新增的域名是否需要进入下一版规则快照。
- 若官方应用将部分请求迁移到不使用 Chromium 代理的原生网络栈，本方案不能保证这些请求经过 SOCKS5；届时需要升级为本地分流代理或 Windows 网络层方案，并重新设计与验收。

## 实施边界

本设计完成后，下一阶段只编写实施计划。代码实现、构建 Windows 安装包、真实网关调用和 Windows 实机验证均不在本阶段执行。
