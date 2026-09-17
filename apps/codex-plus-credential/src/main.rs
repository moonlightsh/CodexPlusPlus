//! 供 Codex 命令鉴权调用的凭据读取器，兼作受管配置的清理入口。
//!
//! 两个子命令：
//! - `get managed-gateway`：仅向 stdout 写 Token，失败信息写 stderr 且不含凭据内容
//! - `clear-managed-env`：移除 `~/.codex/.env` 里的受管代理块，供卸载脚本调用
//!
//! 放在这个二进制里是因为卸载时它已经在安装目录，且能直接复用 core 的纯函数，
//! 免得在 NSIS 脚本里手写文本块编辑。

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() == 1 && args[0] == "clear-managed-env" {
        match clear_managed_env() {
            Ok(()) => return,
            Err(error) => {
                eprintln!("clear managed env failed: {error}");
                std::process::exit(1);
            }
        }
    }
    if args.len() != 2
        || args[0] != "get"
        || args[1] != codex_plus_core::managed_gateway::MANAGED_GATEWAY_CREDENTIAL_TARGET
    {
        eprintln!(
            "usage: codex-plus-credential get {} | codex-plus-credential clear-managed-env",
            codex_plus_core::managed_gateway::MANAGED_GATEWAY_CREDENTIAL_TARGET
        );
        std::process::exit(2);
    }
    match codex_plus_core::credential::read_credential(&args[1]) {
        Ok(Some(token)) => {
            // Token 只进 stdout，供 Codex 命令鉴权读取；不写日志。
            println!("{token}");
        }
        Ok(None) => {
            eprintln!("credential not found");
            std::process::exit(2);
        }
        Err(_) => {
            // 失败信息不含凭据内容
            eprintln!("credential read failed");
            std::process::exit(2);
        }
    }
}

/// 移除 `~/.codex/.env` 中的受管代理块，保留用户自己的行。
///
/// 文件不存在、块不存在都算成功：卸载路径不应因为没东西可删而报错。
/// 用 `std::io::Result` 而不引 anyhow：这个二进制只做文件读写，不值得多一个依赖。
fn clear_managed_env() -> std::io::Result<()> {
    let home = codex_plus_core::relay_config::default_codex_home_dir();
    let path = codex_plus_core::managed_env::managed_env_file_path(&home);
    let Ok(existing) = std::fs::read_to_string(&path) else {
        return Ok(());
    };
    let updated = codex_plus_core::managed_env::remove_managed_env_block(&existing);
    if updated == existing {
        return Ok(());
    }
    if updated.trim().is_empty() {
        std::fs::remove_file(&path)?;
    } else {
        std::fs::write(&path, updated)?;
    }
    Ok(())
}
