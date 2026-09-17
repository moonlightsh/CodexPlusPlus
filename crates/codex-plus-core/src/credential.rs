//! Windows Credential Manager 读写。
//!
//! 只做读写删除，不日志化凭据内容；调用方负责不把 Token 放进错误对象。
//! 非 Windows 平台：read 返回 `Ok(None)`，write/delete 返回 Err（本功能仅 Windows）。

#[cfg(windows)]
use windows::Win32::Security::Credentials::{
    CRED_PERSIST_ENTERPRISE, CRED_TYPE_GENERIC, CREDENTIALW, CredDeleteW, CredFree, CredReadW,
    CredWriteW,
};
#[cfg(windows)]
use windows::core::{HRESULT, PCWSTR, PWSTR};

/// ERROR_NOT_FOUND：凭据不存在。
#[cfg(windows)]
const ERROR_NOT_FOUND: u32 = 1168;

/// windows crate 把 Win32 BOOL 失败包装成 `Result`，错误码以 HRESULT 形式携带。
#[cfg(windows)]
fn is_not_found(err: &windows::core::Error) -> bool {
    err.code() == HRESULT::from_win32(ERROR_NOT_FOUND)
}

/// 读取指定 target 的凭据；不存在返回 `Ok(None)`。
pub fn read_credential(target: &str) -> anyhow::Result<Option<String>> {
    #[cfg(windows)]
    {
        read_credential_windows(target)
    }
    #[cfg(not(windows))]
    {
        let _ = target;
        Ok(None)
    }
}

/// 写入（覆盖）指定 target 的凭据。
pub fn write_credential(target: &str, token: &str) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        write_credential_windows(target, token)
    }
    #[cfg(not(windows))]
    {
        let _ = (target, token);
        anyhow::bail!("Credential Manager 仅支持 Windows")
    }
}

/// 删除指定 target 的凭据；不存在视为成功。
pub fn delete_credential(target: &str) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        delete_credential_windows(target)
    }
    #[cfg(not(windows))]
    {
        let _ = target;
        anyhow::bail!("Credential Manager 仅支持 Windows")
    }
}

#[cfg(windows)]
fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn read_credential_windows(target: &str) -> anyhow::Result<Option<String>> {
    use anyhow::Context;

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
    if let Err(err) = result {
        if is_not_found(&err) {
            return Ok(None);
        }
        anyhow::bail!("读取凭据失败（code={:#x}）", err.code().0);
    }
    let credential = unsafe { &*credential_ptr };
    let bytes = unsafe {
        std::slice::from_raw_parts(
            credential.CredentialBlob as *const u8,
            credential.CredentialBlobSize as usize,
        )
    };
    let token = String::from_utf8(bytes.to_vec()).context("凭据内容不是有效 UTF-8");
    unsafe { CredFree(credential_ptr as *const core::ffi::c_void) };
    Ok(Some(token?))
}

#[cfg(windows)]
fn write_credential_windows(target: &str, token: &str) -> anyhow::Result<()> {
    let target_wide = to_wide(target);
    let user_name_wide = to_wide("CodexPlusPlus");
    let mut credential = CREDENTIALW {
        Flags: Default::default(),
        Type: CRED_TYPE_GENERIC,
        TargetName: PWSTR(target_wide.as_ptr() as *mut u16),
        Comment: PWSTR::null(),
        LastWritten: Default::default(),
        CredentialBlobSize: token.len() as u32,
        CredentialBlob: token.as_ptr() as *mut u8,
        Persist: CRED_PERSIST_ENTERPRISE,
        AttributeCount: 0,
        Attributes: std::ptr::null_mut(),
        TargetAlias: PWSTR::null(),
        UserName: PWSTR(user_name_wide.as_ptr() as *mut u16),
    };
    unsafe { CredWriteW(&mut credential, 0) }
        .map_err(|err| anyhow::anyhow!("写入凭据失败（code={:#x}）", err.code().0))
}

#[cfg(windows)]
fn delete_credential_windows(target: &str) -> anyhow::Result<()> {
    let target_wide = to_wide(target);
    let result = unsafe { CredDeleteW(PCWSTR(target_wide.as_ptr()), CRED_TYPE_GENERIC, 0) };
    if let Err(err) = result {
        if is_not_found(&err) {
            return Ok(());
        }
        anyhow::bail!("删除凭据失败（code={:#x}）", err.code().0);
    }
    Ok(())
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    #[test]
    fn non_windows_stubs_fail_clearly() {
        assert!(write_credential("managed-gateway", "sk-test").is_err());
        assert!(delete_credential("managed-gateway").is_err());
        assert_eq!(read_credential("managed-gateway").unwrap(), None);
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn write_read_overwrite_delete_round_trip_on_temp_target() {
        let target = format!("CodexPlusPlus/test-{}", uuid::Uuid::new_v4());
        // 初始不存在
        assert_eq!(read_credential(&target).unwrap(), None);
        // 写入并读取
        write_credential(&target, "sk-first").unwrap();
        assert_eq!(
            read_credential(&target).unwrap().as_deref(),
            Some("sk-first")
        );
        // 覆盖
        write_credential(&target, "sk-second").unwrap();
        assert_eq!(
            read_credential(&target).unwrap().as_deref(),
            Some("sk-second")
        );
        // 清理；重复删除幂等
        delete_credential(&target).unwrap();
        delete_credential(&target).unwrap();
        assert_eq!(read_credential(&target).unwrap(), None);
    }
}
