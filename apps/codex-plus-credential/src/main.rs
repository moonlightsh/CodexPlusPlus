//! 供 Codex 命令鉴权调用的凭据读取器。
//!
//! 只允许 `get managed-gateway` 固定参数；成功时仅向 stdout 写 Token，
//! 失败信息写 stderr 且不包含凭据内容。

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 2
        || args[0] != "get"
        || args[1] != codex_plus_core::managed_gateway::MANAGED_GATEWAY_CREDENTIAL_TARGET
    {
        eprintln!(
            "usage: codex-plus-credential get {}",
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
