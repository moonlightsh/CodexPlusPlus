//! 受管分流代理的集成测试。
//!
//! 用假 SOCKS5 上游与假目标服务器验证三条硬性行为：命中规则走上游、未命中直连、
//! 命中但上游不可用时返回 502 且**不尝试直连**。

use codex_plus_core::managed_proxy::ManagedProxyConfig;
use codex_plus_core::managed_proxy::spawn_managed_proxy_with;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

/// 极简 SOCKS5 服务器：无认证握手，CONNECT 一律成功，之后把收到的数据回显。
/// 返回 (host:port, 收到的 CONNECT 目标记录)。
async fn spawn_fake_socks5() -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind fake socks5");
    let addr = listener.local_addr().expect("addr");
    let seen: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen_clone = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let seen = Arc::clone(&seen_clone);
            tokio::spawn(async move {
                let mut greeting = [0u8; 3];
                if stream.read_exact(&mut greeting).await.is_err() {
                    return;
                }
                if stream.write_all(&[0x05, 0x00]).await.is_err() {
                    return;
                }
                let mut head = [0u8; 5];
                if stream.read_exact(&mut head).await.is_err() {
                    return;
                }
                let host_len = usize::from(head[4]);
                let mut host = vec![0u8; host_len];
                if stream.read_exact(&mut host).await.is_err() {
                    return;
                }
                let mut port = [0u8; 2];
                if stream.read_exact(&mut port).await.is_err() {
                    return;
                }
                let target = format!(
                    "{}:{}",
                    String::from_utf8_lossy(&host),
                    u16::from_be_bytes(port)
                );
                seen.lock().expect("lock").push(target);
                let reply = [0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80];
                if stream.write_all(&reply).await.is_err() {
                    return;
                }
                let mut buffer = vec![0u8; 4096];
                while let Ok(read) = stream.read(&mut buffer).await {
                    if read == 0 {
                        break;
                    }
                    if stream.write_all(&buffer[..read]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (addr.to_string(), seen)
}

/// 假目标服务器：记录是否有人连入，并回一个固定响应。
async fn spawn_fake_target() -> (u16, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind fake target");
    let port = listener.local_addr().expect("addr").port();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            hits_clone.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 4096];
                let read = stream.read(&mut buffer).await.unwrap_or(0);
                let received = String::from_utf8_lossy(&buffer[..read]).to_string();
                let body = format!("seen:{}", received.lines().next().unwrap_or_default());
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    (port, hits)
}

async fn spawn_proxy(socks5: &str) -> u16 {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind proxy");
    let (host, port) = socks5.rsplit_once(':').expect("socks5 addr");
    let handle = spawn_managed_proxy_with(
        listener,
        ManagedProxyConfig {
            socks5_host: host.to_string(),
            socks5_port: port.parse().expect("socks5 port"),
        },
    );
    let proxy_port = handle.port;
    // 句柄活到进程结束：测试内不需要回收。
    std::mem::forget(handle);
    proxy_port
}

#[tokio::test]
async fn openai_host_is_tunneled_through_socks5_upstream() {
    let (socks5, seen) = spawn_fake_socks5().await;
    let proxy_port = spawn_proxy(&socks5).await;

    let mut client = tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect proxy");
    client
        .write_all(b"CONNECT chatgpt.com:443 HTTP/1.1\r\nHost: chatgpt.com:443\r\n\r\n")
        .await
        .expect("send connect");

    let mut response = vec![0u8; 64];
    let read = client.read(&mut response).await.expect("read response");
    let text = String::from_utf8_lossy(&response[..read]).to_string();
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "expected tunnel established, got: {text}"
    );

    // 隧道建立后的字节应该透传到上游（假上游会回显）。
    client.write_all(b"ping").await.expect("write tunnel");
    let mut echo = vec![0u8; 4];
    client.read_exact(&mut echo).await.expect("read echo");
    assert_eq!(&echo, b"ping");

    let targets = seen.lock().expect("lock").clone();
    assert_eq!(targets, vec!["chatgpt.com:443".to_string()]);
}

#[tokio::test]
async fn unmatched_host_goes_direct_and_preserves_query() {
    let (socks5, seen) = spawn_fake_socks5().await;
    let (target_port, hits) = spawn_fake_target().await;
    let proxy_port = spawn_proxy(&socks5).await;

    let mut client = tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect proxy");
    let request = format!(
        "GET http://127.0.0.1:{target_port}/models?client_version=0.154.0 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
    );
    client
        .write_all(request.as_bytes())
        .await
        .expect("send request");

    let mut response = String::new();
    client
        .read_to_string(&mut response)
        .await
        .expect("read response");
    assert!(response.contains("200 OK"), "got: {response}");
    // 目标看到的应该是 origin-form 且保留 query
    assert!(
        response.contains("GET /models?client_version=0.154.0"),
        "origin-form rewrite lost query: {response}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert!(seen.lock().expect("lock").is_empty(), "must not use socks5");
}

/// 拒绍一切 CONNECT 的假 SOCKS5，用来验证不回退直连。
async fn spawn_refusing_socks5() -> (String, Arc<AtomicBool>) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind refusing socks5");
    let addr = listener.local_addr().expect("addr");
    let contacted = Arc::new(AtomicBool::new(false));
    let contacted_clone = Arc::clone(&contacted);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            contacted_clone.store(true, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut greeting = [0u8; 3];
                let _ = stream.read_exact(&mut greeting).await;
                let _ = stream.write_all(&[0x05, 0x00]).await;
                let mut head = [0u8; 5];
                let _ = stream.read_exact(&mut head).await;
                let host_len = usize::from(head[4]);
                let mut rest = vec![0u8; host_len + 2];
                let _ = stream.read_exact(&mut rest).await;
                // REP=0x05 连接被拒绝
                let _ = stream
                    .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
            });
        }
    });
    (addr.to_string(), contacted)
}

#[tokio::test]
async fn matched_host_returns_502_instead_of_falling_back_to_direct() {
    let (socks5, contacted) = spawn_refusing_socks5().await;
    let proxy_port = spawn_proxy(&socks5).await;

    let mut client = tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect proxy");
    client
        .write_all(b"CONNECT chatgpt.com:443 HTTP/1.1\r\nHost: chatgpt.com:443\r\n\r\n")
        .await
        .expect("send connect");

    let mut response = String::new();
    client
        .read_to_string(&mut response)
        .await
        .expect("read response");
    assert!(
        response.starts_with("HTTP/1.1 502"),
        "must fail closed, got: {response}"
    );
    assert!(
        !response.contains("200 Connection Established"),
        "must never fall back to direct: {response}"
    );
    assert!(contacted.load(Ordering::SeqCst), "socks5 should be tried");
}

#[tokio::test]
async fn unreachable_socks5_upstream_also_fails_closed() {
    // 绑完就释放，得到一个几乎肯定无人监听的端口。
    let dead_port = {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind");
        listener.local_addr().expect("addr").port()
    };
    let proxy_port = spawn_proxy(&format!("127.0.0.1:{dead_port}")).await;

    let mut client = tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect proxy");
    client
        .write_all(b"CONNECT api.openai.com:443 HTTP/1.1\r\n\r\n")
        .await
        .expect("send connect");

    let mut response = String::new();
    client
        .read_to_string(&mut response)
        .await
        .expect("read response");
    assert!(
        response.starts_with("HTTP/1.1 502"),
        "must fail closed, got: {response}"
    );
}

#[tokio::test]
async fn self_identify_endpoint_reports_managed_proxy() {
    let (socks5, _) = spawn_fake_socks5().await;
    let proxy_port = spawn_proxy(&socks5).await;

    let mut client = tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect proxy");
    client
        .write_all(b"GET /__managed_proxy_id HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .await
        .expect("send request");

    let mut response = String::new();
    client
        .read_to_string(&mut response)
        .await
        .expect("read response");
    assert!(response.contains("200 OK"), "got: {response}");
    assert!(
        response.contains("codex-plus-plus-managed-proxy"),
        "got: {response}"
    );
}
