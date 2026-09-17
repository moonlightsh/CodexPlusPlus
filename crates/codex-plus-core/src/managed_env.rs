//! 受管网关的 `~/.codex/.env` 注入。
//!
//! codex 引擎（`codex.exe app-server`）在启动时通过 `arg0::load_dotenv()` 读取
//! `CODEX_HOME/.env`，把其中的键写进自身进程环境。受管模式借这个官方通道让引擎
//! 的 reqwest 客户端把出站流量交给本地分流代理。
//!
//! 本模块只做纯文本编辑，不碰文件系统之外的状态，也**绝不写入任何凭据**。

use std::path::Path;
use std::path::PathBuf;

/// 受管块起始标记。移除与覆盖都靠这两行定位，不做模糊匹配。
const MANAGED_ENV_BEGIN: &str = "# >>> codex-plus-plus managed gateway (自动生成，请勿手改) >>>";
/// 受管块结束标记。
const MANAGED_ENV_END: &str = "# <<< codex-plus-plus managed gateway <<<";

/// `.env` 在 codex home 下的固定位置。
pub fn managed_env_file_path(codex_home: &Path) -> PathBuf {
    codex_home.join(".env")
}

/// 生成受管块文本。
///
/// `NO_PROXY` 把网关与回环地址排除在代理之外：小一跳转发。即使引擎忽略它，
/// 本地代理也能处理明文 HTTP 转发，不会断掉模型调用。
pub fn render_managed_env_block(proxy_port: u16) -> String {
    let proxy = format!("http://127.0.0.1:{proxy_port}");
    format!(
        "{MANAGED_ENV_BEGIN}\n\
         HTTP_PROXY={proxy}\n\
         HTTPS_PROXY={proxy}\n\
         NO_PROXY={}\n\
         {MANAGED_ENV_END}\n",
        no_proxy_list()
    )
}

fn no_proxy_list() -> String {
    format!(
        "{},127.0.0.1,localhost",
        crate::managed_gateway::MANAGED_GATEWAY_SOCKS5_HOST
    )
}

/// 写入或更新受管块，幂等。
///
/// 块固定放在文件末尾：dotenvy 逐行设置，后定义覆盖先定义，所以即使用户
/// 自己写了 `HTTPS_PROXY`，受管模式下仍以本块为准。
pub fn upsert_managed_env_block(existing: &str, proxy_port: u16) -> String {
    let base = remove_managed_env_block(existing);
    let block = render_managed_env_block(proxy_port);
    if base.trim().is_empty() {
        return block;
    }
    let mut out = base.trim_end_matches('\n').to_string();
    out.push('\n');
    out.push('\n');
    out.push_str(&block);
    out
}

/// 移除受管块，保留用户其他行。块不存在时原样返回（只做末尾换行规范化）。
pub fn remove_managed_env_block(existing: &str) -> String {
    let mut kept: Vec<&str> = Vec::new();
    let mut inside = false;
    for line in existing.lines() {
        let trimmed = line.trim();
        if trimmed == MANAGED_ENV_BEGIN {
            inside = true;
            continue;
        }
        if trimmed == MANAGED_ENV_END {
            inside = false;
            continue;
        }
        if !inside {
            kept.push(line);
        }
    }
    while kept.last().is_some_and(|line| line.trim().is_empty()) {
        kept.pop();
    }
    if kept.is_empty() {
        return String::new();
    }
    let mut out = kept.join("\n");
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_block_with_proxy_and_no_proxy() {
        let block = render_managed_env_block(17891);
        assert!(block.contains("HTTP_PROXY=http://127.0.0.1:17891"));
        assert!(block.contains("HTTPS_PROXY=http://127.0.0.1:17891"));
        assert!(block.contains("NO_PROXY=10.20.30.61,127.0.0.1,localhost"));
        assert!(block.starts_with(MANAGED_ENV_BEGIN));
        assert!(block.trim_end().ends_with(MANAGED_ENV_END));
    }

    #[test]
    fn writes_block_into_empty_file() {
        let out = upsert_managed_env_block("", 17891);
        assert_eq!(out, render_managed_env_block(17891));
    }

    #[test]
    fn keeps_user_lines_and_appends_block_at_end() {
        let existing = "UNRELATED=value\nAWS_ACCESS_KEY_ID=keep-me\n";
        let out = upsert_managed_env_block(existing, 17891);
        assert!(out.starts_with("UNRELATED=value\nAWS_ACCESS_KEY_ID=keep-me\n"));
        // 块必须在末尾，dotenv 后定义胜出
        let block_start = out.find(MANAGED_ENV_BEGIN).expect("block present");
        let user_end = out.find("AWS_ACCESS_KEY_ID").expect("user line present");
        assert!(block_start > user_end);
    }

    #[test]
    fn upsert_is_idempotent() {
        let once = upsert_managed_env_block("KEEP=1\n", 17891);
        let twice = upsert_managed_env_block(&once, 17891);
        assert_eq!(once, twice);
        assert_eq!(twice.matches(MANAGED_ENV_BEGIN).count(), 1);
    }

    #[test]
    fn upsert_rewrites_changed_port() {
        let old = upsert_managed_env_block("KEEP=1\n", 17891);
        let new = upsert_managed_env_block(&old, 18000);
        assert!(new.contains("HTTPS_PROXY=http://127.0.0.1:18000"));
        assert!(!new.contains("17891"));
        assert_eq!(new.matches(MANAGED_ENV_BEGIN).count(), 1);
    }

    #[test]
    fn remove_restores_user_content_and_is_idempotent() {
        let existing = "KEEP=1\n";
        let with_block = upsert_managed_env_block(existing, 17891);
        let removed = remove_managed_env_block(&with_block);
        assert_eq!(removed, "KEEP=1\n");
        assert_eq!(remove_managed_env_block(&removed), removed);
    }

    #[test]
    fn remove_yields_empty_when_only_block_present() {
        let with_block = upsert_managed_env_block("", 17891);
        assert_eq!(remove_managed_env_block(&with_block), "");
    }

    #[test]
    fn remove_handles_crlf_markers() {
        let existing = format!(
            "KEEP=1\r\n{MANAGED_ENV_BEGIN}\r\nHTTPS_PROXY=http://127.0.0.1:1\r\n{MANAGED_ENV_END}\r\n"
        );
        let removed = remove_managed_env_block(&existing);
        assert!(!removed.contains("HTTPS_PROXY"));
        assert!(removed.contains("KEEP=1"));
    }

    #[test]
    fn managed_block_wins_over_user_defined_proxy() {
        let existing = "HTTPS_PROXY=http://user-proxy:9999\n";
        let out = upsert_managed_env_block(existing, 17891);
        let user_pos = out.find("http://user-proxy:9999").expect("user line kept");
        let managed_pos = out
            .find("HTTPS_PROXY=http://127.0.0.1:17891")
            .expect("managed line present");
        // dotenvy 逐行 set_var，后面的赋值生效
        assert!(managed_pos > user_pos);
    }

    #[test]
    fn env_file_path_is_dot_env_under_home() {
        let path = managed_env_file_path(Path::new("/tmp/codex-home"));
        assert!(path.ends_with(".env"));
    }
}
