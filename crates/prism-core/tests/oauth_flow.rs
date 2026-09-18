//! The full OAuth 2.1 dance against a live gateway on a loopback port.

use std::collections::HashMap;
use std::time::Duration;

use base64::Engine;
use prism_core::{AgentStatus, Gateway, PrismConfig};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Reply {
    status: u16,
    headers: HashMap<String, String>,
    body: String,
}

/// A deliberately tiny HTTP/1.1 client so the test has no client-side dependency.
async fn http(port: u16, method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> Reply {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let mut req = format!("{method} {path} HTTP/1.1\r\nConnection: close\r\n");
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("host"))
    {
        req.push_str(&format!("Host: 127.0.0.1:{port}\r\n"));
    }
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
    stream.write_all(req.as_bytes()).await.expect("write");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read");
    let text = String::from_utf8_lossy(&raw).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .expect("status line");
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    Reply {
        status,
        headers,
        body: body.to_string(),
    }
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={}", urlencoding(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn urlencoding(v: &str) -> String {
    v.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn query_param(url: &str, key: &str) -> Option<String> {
    url.split_once('?')?
        .1
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v.to_string())
}

async fn wait_for_signin(gateway: &Gateway) -> prism_core::PendingSignIn {
    for _ in 0..100 {
        if let Some(s) = gateway.pending_signins().into_iter().next() {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("no sign-in request appeared");
}

/// Register, authorize (approving whatever the panel would show), and exchange: one agent
/// with tokens, ready to talk MCP.
async fn signed_in_agent(
    gateway: &std::sync::Arc<Gateway>,
    port: u16,
    name: &str,
) -> (String, String) {
    let reg = http(
        port,
        "POST",
        "/register",
        &[("Content-Type", "application/json")],
        &format!(r#"{{"client_name":"{name}","redirect_uris":["http://localhost:4444/cb"]}}"#),
    )
    .await;
    let reg: serde_json::Value = serde_json::from_str(&reg.body).unwrap();
    let client_id = reg["client_id"].as_str().unwrap().to_string();
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    let path = format!(
        "/authorize?response_type=code&client_id={client_id}&redirect_uri={}&code_challenge={challenge}&code_challenge_method=S256",
        urlencoding("http://localhost:4444/cb")
    );
    let parked = tokio::spawn(async move { http(port, "GET", &path, &[], "").await });
    let signin = wait_for_signin(gateway).await;
    if signin.needs_consent {
        gateway.decide_signin(&signin.id, true).unwrap();
    } else {
        gateway.decide_agent(&signin.agent_id, true).await.unwrap();
    }
    let redirect = tokio::time::timeout(Duration::from_secs(5), parked)
        .await
        .unwrap()
        .unwrap();
    let code = query_param(&redirect.headers["location"], "code").unwrap();
    let tokens = http(
        port,
        "POST",
        "/token",
        &[("Content-Type", "application/x-www-form-urlencoded")],
        &form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("code_verifier", verifier),
            ("client_id", &client_id),
        ]),
    )
    .await;
    assert_eq!(tokens.status, 200, "{}", tokens.body);
    let tokens: serde_json::Value = serde_json::from_str(&tokens.body).unwrap();
    (
        signin.agent_id,
        tokens["access_token"].as_str().unwrap().to_string(),
    )
}

const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"x","version":"1"}}}"#;
const LIST_TOOLS: &str = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#;

async fn start() -> (std::sync::Arc<Gateway>, u16, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let port = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe");
        probe.local_addr().expect("addr").port()
    };
    let config = PrismConfig {
        listen_port: port,
        ..PrismConfig::default()
    };
    let config_path = dir.path().join("prism.json");
    config.save(&config_path).expect("save");
    let gateway = Gateway::start(&config_path, dir.path().join("audit.jsonl"))
        .await
        .expect("start");
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    (gateway, port, dir)
}

#[tokio::test]
async fn discovery_supports_stateless_requests_and_legacy_sessions() {
    let (gateway, port, _dir) = start().await;
    let (_, access) = signed_in_agent(&gateway, port, "discovery-client").await;
    let bearer = format!("Bearer {access}");

    // Discovery and modern tools requests work without initialize or a session.
    let discovery = http(
        port,
        "POST",
        "/mcp",
        &[
            ("Content-Type", "application/json"),
            ("Accept", "application/json, text/event-stream"),
            ("Authorization", &bearer),
            ("MCP-Protocol-Version", "2026-07-28"),
            ("Mcp-Method", "server/discover"),
        ],
        r#"{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}"#,
    )
    .await;
    assert_eq!(discovery.status, 200, "{}", discovery.body);
    assert!(discovery.body.contains("2026-07-28"), "{}", discovery.body);
    assert!(discovery.body.contains("2025-11-25"), "{}", discovery.body);
    assert!(discovery.body.contains("Prism"), "{}", discovery.body);
    assert!(!discovery.headers.contains_key("mcp-session-id"));
    let modern = modern_request(port, &access, "tools/list", serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(modern.status(), 200);
    assert!(!modern.headers().contains_key("mcp-session-id"));
    let modern = rpc_response(modern).await;
    assert_eq!(modern["result"]["resultType"], "complete");
    assert_eq!(modern["result"]["ttlMs"], 0);
    assert_eq!(modern["result"]["cacheScope"], "private");
    assert_eq!(modern["result"]["tools"], serde_json::json!([]));

    // Follow discovery with the legacy handshake and a real tools request.
    let init = http(
        port,
        "POST",
        "/mcp",
        &[
            ("Content-Type", "application/json"),
            ("Accept", "application/json, text/event-stream"),
            ("Authorization", &bearer),
        ],
        &INIT.replace("2025-06-18", "2025-11-25"),
    )
    .await;
    assert_eq!(init.status, 200, "{}", init.body);
    assert!(init.body.contains("2025-11-25"), "{}", init.body);
    let session = &init.headers["mcp-session-id"];
    let headers = [
        ("Content-Type", "application/json"),
        ("Accept", "application/json, text/event-stream"),
        ("Authorization", bearer.as_str()),
        ("MCP-Protocol-Version", "2025-11-25"),
        ("MCP-Session-Id", session.as_str()),
    ];
    let notified = http(
        port,
        "POST",
        "/mcp",
        &headers,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    )
    .await;
    assert_eq!(notified.status, 202, "{}", notified.body);
    let tools = http(port, "POST", "/mcp", &headers, LIST_TOOLS).await;
    assert_eq!(tools.status, 200, "{}", tools.body);
    assert!(tools.body.contains(r#""tools":[]"#), "{}", tools.body);
    assert!(!tools.body.contains("error"), "{}", tools.body);
    gateway.shutdown().await;
}

#[tokio::test]
async fn authorize_accepts_origin_resource_and_rejects_a_foreign_one() {
    let (gateway, port, _dir) = start().await;
    let reg = http(
        port,
        "POST",
        "/register",
        &[("Content-Type", "application/json")],
        r#"{"client_name":"claude-code","redirect_uris":["http://localhost:4444/cb"]}"#,
    )
    .await;
    let client_id = serde_json::from_str::<serde_json::Value>(&reg.body).unwrap()["client_id"]
        .as_str()
        .unwrap()
        .to_string();
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(
        b"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    ));
    let authorize = |resource: String| {
        let client_id = client_id.clone();
        let challenge = challenge.clone();
        async move {
            http(
                port,
                "GET",
                &format!(
                    "/authorize?response_type=code&client_id={client_id}&redirect_uri={}&code_challenge={challenge}&code_challenge_method=S256&resource={}",
                    urlencoding("http://localhost:4444/cb"),
                    urlencoding(&resource)
                ),
                &[],
                "",
            )
            .await
        }
    };

    let foreign = authorize(format!("http://127.0.0.1:{port}/hooks")).await;
    assert_eq!(foreign.status, 303, "{}", foreign.body);
    let location = &foreign.headers["location"];
    assert!(location.contains("invalid_target"), "{location}");

    let parked = tokio::spawn(authorize(format!("http://127.0.0.1:{port}/")));
    let signin = wait_for_signin(&gateway).await;
    gateway.decide_signin(&signin.id, false).unwrap();
    let denied = tokio::time::timeout(Duration::from_secs(5), parked)
        .await
        .expect("authorize returned")
        .unwrap();
    assert_eq!(denied.status, 303, "{}", denied.body);
    assert!(
        denied.headers["location"].contains("access_denied"),
        "{}",
        denied.headers["location"]
    );
    gateway.shutdown().await;
}

#[tokio::test]
async fn loopback_host_and_browser_origin_checks_preserve_native_clients() {
    let (gateway, port, _dir) = start().await;
    for (method, path) in [
        ("GET", "/.well-known/oauth-authorization-server"),
        ("GET", "/.well-known/oauth-protected-resource"),
        ("GET", "/authorize"),
        ("POST", "/register"),
        ("POST", "/token"),
        ("POST", "/revoke"),
        ("POST", "/mcp"),
        ("GET", "/mcp"),
        ("DELETE", "/mcp"),
    ] {
        let response = http(port, method, path, &[("Host", "evil.example")], "").await;
        assert_eq!(response.status, 403, "{path}: {}", response.body);
    }
    for host in ["localhost:1", "localhost", "localhost.evil.example"] {
        let response = http(port, "POST", "/mcp", &[("Host", host)], "{}").await;
        assert_eq!(response.status, 403, "MCP must pass the shared Host guard");
    }
    let meta = http(
        port,
        "GET",
        "/.well-known/oauth-authorization-server",
        &[],
        "",
    )
    .await;
    assert_eq!(meta.status, 200);
    for origin in ["https://evil.example", "null", "http://localhost:1"] {
        let response = http(port, "POST", "/mcp", &[("Origin", origin)], "{}").await;
        assert_eq!(response.status, 403);
    }
    let own_origin = format!("http://localhost:{port}");
    let own = http(port, "POST", "/mcp", &[("Origin", &own_origin)], "{}").await;
    assert_eq!(own.status, 401, "same-origin reaches bearer authentication");
    let native = http(port, "POST", "/mcp", &[], "{}").await;
    assert_eq!(native.status, 401, "native requests need no Origin");
    for path in ["/register", "/token", "/revoke"] {
        let response = http(
            port,
            "POST",
            path,
            &[
                ("Origin", "https://evil.example"),
                ("Content-Type", "application/x-www-form-urlencoded"),
            ],
            "token=x",
        )
        .await;
        assert_eq!(
            response.status, 403,
            "form POST {path} is checked without relying on CORS"
        );
    }
    let native_token = http(
        port,
        "POST",
        "/token",
        &[("Content-Type", "application/x-www-form-urlencoded")],
        "grant_type=invalid",
    )
    .await;
    assert_eq!(
        native_token.status, 400,
        "native form POST reaches OAuth validation"
    );
    for origin in ["https://client.example", "null"] {
        let browser = http(port, "GET", "/authorize", &[("Origin", origin)], "").await;
        assert_eq!(
            browser.status, 400,
            "authorization navigation reaches parameter validation"
        );
        assert!(browser.body.contains("client_id is required"));
    }
    gateway.shutdown().await;
}

#[tokio::test]
async fn register_authorize_token_and_call() {
    let (gateway, port, _dir) = start().await;

    // Discovery: the resource says who its authorization server is.
    let meta = http(
        port,
        "GET",
        "/.well-known/oauth-authorization-server",
        &[],
        "",
    )
    .await;
    assert_eq!(meta.status, 200);
    let meta: serde_json::Value = serde_json::from_str(&meta.body).unwrap();
    assert_eq!(
        meta["registration_endpoint"],
        format!("http://127.0.0.1:{port}/register")
    );
    assert_eq!(meta["code_challenge_methods_supported"][0], "S256");

    // No token: 401 that points at the resource metadata.
    let anon = http(
        port,
        "POST",
        "/mcp",
        &[("Content-Type", "application/json")],
        "{}",
    )
    .await;
    assert_eq!(anon.status, 401);
    let www = &anon.headers["www-authenticate"];
    assert!(
        www.contains("resource_metadata=\"http://127.0.0.1:"),
        "{www}"
    );

    // Claude Code's SDK requires the advertised resource to be a prefix of the
    // URL it dialed. The origin covers both `http://127.0.0.1:PORT/` and `/mcp`.
    let prm = http(
        port,
        "GET",
        "/.well-known/oauth-protected-resource",
        &[],
        "",
    )
    .await;
    assert_eq!(prm.status, 200);
    let prm: serde_json::Value = serde_json::from_str(&prm.body).unwrap();
    assert_eq!(prm["resource"], format!("http://127.0.0.1:{port}/"));
    let prm_path = http(
        port,
        "GET",
        "/.well-known/oauth-protected-resource/mcp",
        &[],
        "",
    )
    .await;
    let prm_path: serde_json::Value = serde_json::from_str(&prm_path.body).unwrap();
    assert_eq!(prm_path["resource"], format!("http://127.0.0.1:{port}/"));

    // Dynamic registration is open.
    let reg = http(
        port,
        "POST",
        "/register",
        &[("Content-Type", "application/json")],
        r#"{"client_name":"claude-code","redirect_uris":["http://localhost:4444/cb"],"token_endpoint_auth_method":"none"}"#,
    )
    .await;
    assert_eq!(reg.status, 201, "{}", reg.body);
    let reg: serde_json::Value = serde_json::from_str(&reg.body).unwrap();
    let client_id = reg["client_id"].as_str().unwrap().to_string();

    // A non-loopback http redirect is refused.
    let bad = http(
        port,
        "POST",
        "/register",
        &[("Content-Type", "application/json")],
        r#"{"client_name":"x","redirect_uris":["http://evil.example/cb"]}"#,
    )
    .await;
    assert_eq!(bad.status, 400);
    assert!(bad.body.contains("invalid_redirect_uri"));

    // PKCE material.
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));

    // The browser parks on /authorize until the operator decides in the panel.
    let path = format!(
        "/authorize?response_type=code&client_id={client_id}&redirect_uri={}&code_challenge={challenge}&code_challenge_method=S256&state=xyz&resource={}",
        urlencoding("http://localhost:4444/cb"),
        urlencoding(&format!("http://127.0.0.1:{port}/mcp"))
    );
    let parked = tokio::spawn(async move { http(port, "GET", &path, &[], "").await });

    let mut agent_id = None;
    for _ in 0..100 {
        if let Some(a) = gateway
            .agents()
            .await
            .into_iter()
            .find(|a| a.agent.status == AgentStatus::Pending)
        {
            agent_id = Some(a.agent.id);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let agent_id = agent_id.expect("pending agent appeared");
    let agent = gateway
        .agents()
        .await
        .into_iter()
        .find(|a| a.agent.id == agent_id)
        .unwrap();
    // A client that names a known harness is that harness, whatever scope it registered from.
    assert_eq!(agent.agent.name, "Claude Code");
    assert_eq!(agent.agent.id, "host:claude-code");
    assert_eq!(agent.agent.host.as_deref(), Some("claude-code"));
    assert!(agent.clients.iter().any(|c| c.client_id == client_id));

    gateway.decide_agent(&agent_id, true).await.unwrap();
    let redirect = tokio::time::timeout(Duration::from_secs(5), parked)
        .await
        .expect("authorize returned")
        .unwrap();
    assert_eq!(redirect.status, 303, "{}", redirect.body);
    let location = redirect.headers["location"].clone();
    assert!(
        location.starts_with("http://localhost:4444/cb?"),
        "{location}"
    );
    assert_eq!(query_param(&location, "state").as_deref(), Some("xyz"));
    let code = query_param(&location, "code").expect("code");

    // Wrong verifier: no token, and the code is burnt.
    let bad = http(
        port,
        "POST",
        "/token",
        &[("Content-Type", "application/x-www-form-urlencoded")],
        &form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            (
                "code_verifier",
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXX",
            ),
            ("client_id", &client_id),
        ]),
    )
    .await;
    assert_eq!(bad.status, 400);
    assert!(bad.body.contains("invalid_grant"));
    let again = http(
        port,
        "POST",
        "/token",
        &[("Content-Type", "application/x-www-form-urlencoded")],
        &form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("code_verifier", verifier),
            ("client_id", &client_id),
        ]),
    )
    .await;
    assert_eq!(again.status, 400, "a code is single use");

    // An approved agent signing in again still needs a yes: a public client id is not proof.
    let path = format!(
        "/authorize?response_type=code&client_id={client_id}&redirect_uri={}&code_challenge={challenge}&code_challenge_method=S256",
        urlencoding("http://localhost:4444/cb")
    );
    let parked = tokio::spawn({
        let path = path.clone();
        async move { http(port, "GET", &path, &[], "").await }
    });
    let signin = wait_for_signin(&gateway).await;
    assert_eq!(signin.agent_id, agent_id);
    assert!(signin.needs_consent);
    assert_eq!(gateway.status().await.pending_signins, 1);
    gateway.decide_signin(&signin.id, false).unwrap();
    let denied = tokio::time::timeout(Duration::from_secs(5), parked)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(denied.status, 303);
    assert_eq!(
        query_param(&denied.headers["location"], "error").as_deref(),
        Some("access_denied")
    );
    assert!(
        gateway.agents().await[0].tokens.is_empty(),
        "no token after a refused sign-in"
    );

    let parked = tokio::spawn({
        let path = path.clone();
        async move { http(port, "GET", &path, &[], "").await }
    });
    let signin = wait_for_signin(&gateway).await;
    gateway.decide_signin(&signin.id, true).unwrap();
    let redirect = tokio::time::timeout(Duration::from_secs(5), parked)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(redirect.status, 303);
    let code = query_param(&redirect.headers["location"], "code").unwrap();
    assert_eq!(gateway.status().await.pending_signins, 0);

    let tokens = http(
        port,
        "POST",
        "/token",
        &[("Content-Type", "application/x-www-form-urlencoded")],
        &form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("code_verifier", verifier),
            ("client_id", &client_id),
            ("redirect_uri", "http://localhost:4444/cb"),
        ]),
    )
    .await;
    assert_eq!(tokens.status, 200, "{}", tokens.body);
    let tokens: serde_json::Value = serde_json::from_str(&tokens.body).unwrap();
    let access = tokens["access_token"].as_str().unwrap().to_string();
    let refresh = tokens["refresh_token"].as_str().unwrap().to_string();
    assert_eq!(tokens["token_type"], "Bearer");

    // The token is the identity: initialize succeeds with a session.
    let init = http(
        port,
        "POST",
        "/mcp",
        &[
            ("Content-Type", "application/json"),
            ("Accept", "application/json, text/event-stream"),
            ("Authorization", &format!("Bearer {access}")),
        ],
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"spoofed-name","version":"1"}}}"#,
    )
    .await;
    assert_eq!(init.status, 200, "{}", init.body);
    assert!(init.headers.contains_key("mcp-session-id"));
    let views = gateway.agents().await;
    assert_eq!(
        views.len(),
        1,
        "the announced name did not create a second agent"
    );
    assert_eq!(views[0].tokens.len(), 2);

    // Refresh rotates: the old refresh token dies with the exchange.
    let rotated = http(
        port,
        "POST",
        "/token",
        &[("Content-Type", "application/x-www-form-urlencoded")],
        &form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh),
            ("client_id", &client_id),
        ]),
    )
    .await;
    assert_eq!(rotated.status, 200, "{}", rotated.body);
    let replay = http(
        port,
        "POST",
        "/token",
        &[("Content-Type", "application/x-www-form-urlencoded")],
        &form(&[("grant_type", "refresh_token"), ("refresh_token", &refresh)]),
    )
    .await;
    assert_eq!(replay.status, 400);

    // Deny in the panel: every token is gone and the next call is a 401.
    gateway.decide_agent(&agent_id, false).await.unwrap();
    let after = http(
        port,
        "POST",
        "/mcp",
        &[
            ("Content-Type", "application/json"),
            ("Accept", "application/json, text/event-stream"),
            ("Authorization", &format!("Bearer {access}")),
        ],
        "{}",
    )
    .await;
    assert_eq!(after.status, 401);
    assert!(after.headers["www-authenticate"].contains("invalid_token"));
    assert!(gateway.agents().await[0].tokens.is_empty());

    // A denied agent gets access_denied and nothing else.
    let path = format!(
        "/authorize?response_type=code&client_id={client_id}&redirect_uri={}&code_challenge={challenge}&code_challenge_method=S256",
        urlencoding("http://localhost:4444/cb")
    );
    let denied = http(port, "GET", &path, &[], "").await;
    assert_eq!(denied.status, 303);
    assert_eq!(
        query_param(&denied.headers["location"], "error").as_deref(),
        Some("access_denied")
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn every_registration_of_a_harness_is_one_agent() {
    let (gateway, port, _dir) = start().await;

    // First Claude Code registration: a pending harness agent, approved once.
    let (agent_id, _token) = signed_in_agent(&gateway, port, "Claude Code").await;
    assert_eq!(agent_id, "host:claude-code");

    // Second registration, as a project-scoped install would make: same agent, its own consent.
    let reg = http(
        port,
        "POST",
        "/register",
        &[("Content-Type", "application/json")],
        r#"{"client_name":"claude-code","redirect_uris":["http://localhost:4444/cb"]}"#,
    )
    .await;
    let reg: serde_json::Value = serde_json::from_str(&reg.body).unwrap();
    let second = reg["client_id"].as_str().unwrap().to_string();
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    let path = format!(
        "/authorize?response_type=code&client_id={second}&redirect_uri={}&code_challenge={challenge}&code_challenge_method=S256",
        urlencoding("http://localhost:4444/cb")
    );
    let parked = tokio::spawn(async move { http(port, "GET", &path, &[], "").await });
    let signin = wait_for_signin(&gateway).await;
    assert_eq!(signin.agent_id, "host:claude-code");
    assert!(
        signin.needs_consent,
        "an approved harness still consents per client"
    );
    assert!(signin.new_client, "this client never held a token");
    assert_eq!(signin.client_id, second);
    gateway.decide_signin(&signin.id, true).unwrap();
    let redirect = tokio::time::timeout(Duration::from_secs(5), parked)
        .await
        .unwrap()
        .unwrap();
    let code = query_param(&redirect.headers["location"], "code").unwrap();
    let tokens = http(
        port,
        "POST",
        "/token",
        &[("Content-Type", "application/x-www-form-urlencoded")],
        &form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("code_verifier", verifier),
            ("client_id", &second),
        ]),
    )
    .await;
    assert_eq!(tokens.status, 200, "{}", tokens.body);

    // One agent, two clients, both signed in. Another product is still its own agent.
    let (other, _) = signed_in_agent(&gateway, port, "Cursor").await;
    assert_eq!(other, "host:cursor");
    let agents = gateway.agents().await;
    let harness: Vec<_> = agents
        .iter()
        .filter(|a| a.agent.host.as_deref() == Some("claude-code"))
        .collect();
    assert_eq!(
        harness.len(),
        1,
        "{:?}",
        agents.iter().map(|a| &a.agent.id).collect::<Vec<_>>()
    );
    assert_eq!(harness[0].clients.len(), 2);
    assert!(harness[0].clients.iter().all(|c| c.signed_in));
    assert!(agents
        .iter()
        .any(|a| a.agent.name == "Cursor" && a.agent.host.as_deref() == Some("cursor")));

    // Forgetting one client leaves the other and the agent's settings alone.
    gateway
        .forget_client("host:claude-code", &second)
        .await
        .unwrap();
    let agents = gateway.agents().await;
    let harness = agents
        .iter()
        .find(|a| a.agent.id == "host:claude-code")
        .unwrap();
    assert_eq!(harness.clients.len(), 1);
    assert!(harness.agent.is_approved());
    assert!(gateway
        .forget_client("host:claude-code", &second)
        .await
        .is_err());
    gateway.shutdown().await;
}

#[tokio::test]
async fn new_harness_client_aliases_share_only_their_own_authenticated_agent() {
    let (gateway, port, _dir) = start().await;
    for (host, first, second) in [
        ("cursor", "Cursor", "cursor"),
        ("opencode", "OpenCode", "opencode"),
        ("goose", "goose-cli", "goose-desktop"),
        ("antigravity", "Antigravity", "antigravity"),
    ] {
        let (first_id, _) = signed_in_agent(&gateway, port, first).await;
        let (second_id, _) = signed_in_agent(&gateway, port, second).await;
        assert_eq!(first_id, format!("host:{host}"));
        assert_eq!(first_id, second_id);
    }
    let agents = gateway.agents().await;
    assert_eq!(agents.len(), 4);
    for agent in agents {
        assert!(agent.agent.is_approved());
        assert_eq!(agent.clients.len(), 2);
        assert!(agent.clients.iter().all(|client| client.signed_in));
    }
    gateway.shutdown().await;
}

#[tokio::test]
async fn sessions_are_bound_to_the_identity_that_opened_them() {
    let (gateway, port, _dir) = start().await;
    let (agent_a, token_a) = signed_in_agent(&gateway, port, "alpha").await;
    let (agent_b, token_b) = signed_in_agent(&gateway, port, "beta").await;
    assert_ne!(agent_a, agent_b);

    let init = http(
        port,
        "POST",
        "/mcp",
        &[
            ("Content-Type", "application/json"),
            ("Accept", "application/json, text/event-stream"),
            ("Authorization", &format!("Bearer {token_a}")),
        ],
        INIT,
    )
    .await;
    assert_eq!(init.status, 200, "{}", init.body);
    let session = init.headers["mcp-session-id"].clone();

    // Beta holds a perfectly valid token, but this is alpha's session.
    let hijack = http(
        port,
        "POST",
        "/mcp",
        &[
            ("Content-Type", "application/json"),
            ("Accept", "application/json, text/event-stream"),
            ("Authorization", &format!("Bearer {token_b}")),
            ("Mcp-Session-Id", &session),
        ],
        LIST_TOOLS,
    )
    .await;
    assert_eq!(hijack.status, 403, "{}", hijack.body);
    let stream = http(
        port,
        "GET",
        "/mcp",
        &[
            ("Accept", "text/event-stream"),
            ("Authorization", &format!("Bearer {token_b}")),
            ("Mcp-Session-Id", &session),
        ],
        "",
    )
    .await;
    assert_eq!(stream.status, 403);
    let close = http(
        port,
        "DELETE",
        "/mcp",
        &[
            ("Authorization", &format!("Bearer {token_b}")),
            ("Mcp-Session-Id", &session),
        ],
        "",
    )
    .await;
    assert_eq!(close.status, 403);

    // The owner carries on.
    let own = http(
        port,
        "POST",
        "/mcp",
        &[
            ("Content-Type", "application/json"),
            ("Accept", "application/json, text/event-stream"),
            ("Authorization", &format!("Bearer {token_a}")),
            ("Mcp-Session-Id", &session),
        ],
        LIST_TOOLS,
    )
    .await;
    assert_eq!(own.status, 200, "{}", own.body);
    gateway.shutdown().await;
}

// Manual and OAuth clients use the same HTTP authentication and session ownership checks.
#[tokio::test]
async fn manual_tokens_replace_anonymous_access_and_revoke_live_sessions() {
    let (gateway, port, dir) = start().await;
    let (oauth_id, oauth_token) = signed_in_agent(&gateway, port, "same-name").await;
    let issued = gateway.create_manual_agent("same-name").await.unwrap();
    let other = gateway.create_manual_agent("same-name").await.unwrap();
    assert_ne!(issued.agent_id, oauth_id);
    assert_ne!(issued.agent_id, other.agent_id);
    assert_eq!(
        gateway.authenticate(&issued.token).await.as_deref(),
        Some(issued.agent_id.as_str())
    );
    let persisted = std::fs::read_to_string(dir.path().join("prism.json")).unwrap();
    assert!(!persisted.contains(&issued.token));
    assert!(!serde_json::to_string(&gateway.agents().await)
        .unwrap()
        .contains(&issued.token));
    let config: PrismConfig = serde_json::from_str(&persisted).unwrap();
    let record = config
        .tokens
        .iter()
        .find(|t| t.agent_id == issued.agent_id)
        .unwrap();
    assert_eq!(record.kind, prism_core::TokenKind::Manual);
    assert_eq!(record.hash, prism_core::hash_token(&issued.token));
    assert_eq!(record.expires_at, None);
    assert_eq!(record.client_id, None);
    assert_eq!(
        gateway
            .agents()
            .await
            .iter()
            .find(|a| a.agent.id == issued.agent_id)
            .unwrap()
            .agent
            .posture,
        prism_core::Posture::FirstUse
    );

    let base = [
        ("Content-Type", "application/json"),
        ("Accept", "application/json, text/event-stream"),
    ];
    let bearer = format!("Bearer {}", issued.token);
    let init = INIT.replace("\"x\"", "\"same-name\"");
    assert_eq!(http(port, "POST", "/mcp", &base, &init).await.status, 401);
    let initialized = http(
        port,
        "POST",
        "/mcp",
        &[base[0], base[1], ("Authorization", &bearer)],
        &init,
    )
    .await;
    assert_eq!(initialized.status, 200);
    let session = initialized.headers["mcp-session-id"].clone();
    let headers = [
        base[0],
        base[1],
        ("Authorization", bearer.as_str()),
        ("Mcp-Session-Id", session.as_str()),
    ];
    assert_eq!(
        http(port, "POST", "/mcp", &headers, LIST_TOOLS)
            .await
            .status,
        200
    );
    for wrong in [&oauth_token, &other.token] {
        assert_eq!(
            http(
                port,
                "POST",
                "/mcp",
                &[
                    base[0],
                    base[1],
                    ("Authorization", &format!("Bearer {wrong}")),
                    ("Mcp-Session-Id", &session)
                ],
                LIST_TOOLS
            )
            .await
            .status,
            403
        );
    }
    let refresh = http(
        port,
        "POST",
        "/token",
        &[("Content-Type", "application/x-www-form-urlencoded")],
        &form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &issued.token),
        ]),
    )
    .await;
    assert_eq!(
        refresh.status, 400,
        "manual tokens cannot be exchanged for OAuth tokens"
    );
    assert!(gateway.replace_manual_token(&oauth_id).await.is_err());
    assert!(gateway.create_manual_agent("  ").await.is_err());

    let replacement = gateway
        .replace_manual_token(&issued.agent_id)
        .await
        .unwrap();
    assert_ne!(replacement.token, issued.token);
    assert_eq!(gateway.authenticate(&issued.token).await, None);
    for method in ["POST", "GET", "DELETE"] {
        assert_eq!(
            http(
                port,
                method,
                "/mcp",
                &headers,
                if method == "POST" { LIST_TOOLS } else { "" }
            )
            .await
            .status,
            401
        );
    }
    assert_eq!(
        gateway.authenticate(&replacement.token).await.as_deref(),
        Some(issued.agent_id.as_str())
    );
    assert_eq!(
        gateway
            .agents()
            .await
            .iter()
            .find(|a| a.agent.id == issued.agent_id)
            .unwrap()
            .tokens
            .len(),
        1
    );
    let fresh_bearer = format!("Bearer {}", replacement.token);
    // Same agent can continue its session with its replacement token.
    assert_eq!(
        http(
            port,
            "POST",
            "/mcp",
            &[
                base[0],
                base[1],
                ("Authorization", fresh_bearer.as_str()),
                ("Mcp-Session-Id", &session)
            ],
            LIST_TOOLS
        )
        .await
        .status,
        200
    );
    gateway.revoke_agent_tokens(&issued.agent_id).await.unwrap();
    assert_eq!(gateway.authenticate(&replacement.token).await, None);
    assert_eq!(
        gateway.authenticate(&oauth_token).await.as_deref(),
        Some(oauth_id.as_str())
    );
    let final_token = gateway
        .replace_manual_token(&issued.agent_id)
        .await
        .unwrap();
    gateway.decide_agent(&issued.agent_id, false).await.unwrap();
    assert_eq!(gateway.authenticate(&final_token.token).await, None);
    assert!(gateway
        .replace_manual_token(&issued.agent_id)
        .await
        .is_err());
    gateway.shutdown().await;
}

#[tokio::test]
async fn old_anonymous_settings_are_ignored_and_existing_grants_survive_provisioning() {
    let dir = tempfile::tempdir().unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let path = dir.path().join("prism.json");
    let legacy = serde_json::json!({
        "listen_port": port, "allow_unauthenticated": true,
        "agents": [{"id":"old", "name":"legacy", "token":"obsolete-key", "status":"approved", "created_at":"2026-09-01T00:00:00Z", "posture":"supervised"}],
        "rules": [{"id":"grant", "agent_id":"old", "server_id":null, "tool":"read_file", "decision":"deny", "scope":"always", "created_at":"2026-09-01T00:00:00Z"}]
    });
    std::fs::write(&path, legacy.to_string()).unwrap();
    let gateway = Gateway::start(&path, dir.path().join("audit.jsonl"))
        .await
        .unwrap();
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let headers = [
        ("Content-Type", "application/json"),
        ("Accept", "application/json, text/event-stream"),
    ];
    assert_eq!(http(port, "POST", "/mcp", &headers, INIT).await.status, 401);
    assert_eq!(gateway.authenticate("obsolete-key").await, None);
    assert_eq!(
        gateway.agents().await.len(),
        1,
        "bare requests cannot create agents"
    );
    let token = gateway.replace_manual_token("old").await.unwrap();
    let saved = PrismConfig::load(&path).unwrap();
    assert_eq!(saved.rules[0].id, "grant");
    assert_eq!(saved.agents[0].posture, prism_core::Posture::Supervised);
    let json = std::fs::read_to_string(&path).unwrap();
    assert!(!json.contains("allow_unauthenticated"));
    assert!(!json.contains("obsolete-key"));
    assert!(!json.contains(&token.token));
    gateway.shutdown().await;
    // Reopen the actual persisted file on another listener; tokens survive app restarts.
    let mut saved = saved;
    saved.listen_port = 0;
    saved.save(&path).unwrap();
    let reopened = Gateway::start(&path, dir.path().join("audit.jsonl"))
        .await
        .unwrap();
    assert_eq!(
        reopened.authenticate(&token.token).await.as_deref(),
        Some("old")
    );
    reopened.remove_agent("old").await.unwrap();
    assert_eq!(reopened.authenticate(&token.token).await, None);
    reopened.shutdown().await;
}

#[tokio::test]
async fn signin_caps_do_not_share_consent_and_release_cancelled_waiters() {
    let (gateway, _port, _dir) = start().await;
    let request = |client_id: &str| {
        serde_json::from_value::<prism_core::AuthorizeParams>(serde_json::json!({
        "client_id": client_id, "response_type": "code", "code_challenge": "test-challenge", "code_challenge_method": "S256"
    })).unwrap()
    };
    let mut clients = Vec::new();
    for i in 0..17 {
        clients.push(gateway.register_client(serde_json::from_value(serde_json::json!({
            "client_name": format!("cap-test-{i}"), "redirect_uris": ["http://localhost/cb"]
        })).unwrap()).await.unwrap());
    }
    let mut parked = Vec::new();
    for client in &clients[..16] {
        let g = gateway.clone();
        let params = request(&client.client_id);
        parked.push(tokio::spawn(async move { g.authorize(params).await }));
        if parked.len() == 1 {
            wait_for_signin(&gateway).await;
            let duplicate = tokio::time::timeout(
                Duration::from_secs(2),
                gateway.authorize(request(&client.client_id)),
            )
            .await
            .unwrap();
            let prism_core::AuthorizeOutcome::Redirect(uri) = duplicate else {
                panic!("expected OAuth error")
            };
            assert_eq!(
                query_param(&uri, "error").as_deref(),
                Some("temporarily_unavailable")
            );
            assert_eq!(gateway.pending_signins().len(), 1);
        }
    }
    for _ in 0..100 {
        if gateway.pending_signins().len() == 16 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(gateway.pending_signins().len(), 16);
    for client in [&clients[0], &clients[16]] {
        let outcome = tokio::time::timeout(
            Duration::from_secs(2),
            gateway.authorize(request(&client.client_id)),
        )
        .await
        .unwrap();
        let prism_core::AuthorizeOutcome::Redirect(uri) = outcome else {
            panic!("expected OAuth error")
        };
        assert_eq!(
            query_param(&uri, "error").as_deref(),
            Some("temporarily_unavailable")
        );
        assert!(query_param(&uri, "code").is_none());
    }
    assert_eq!(gateway.agents().await.len(), 16);
    parked[0].abort();
    let _ = (&mut parked[0]).await;
    assert_eq!(gateway.pending_signins().len(), 15);
    // The cancelled request's slot can be reused, with fresh consent.
    let g = gateway.clone();
    let params = request(&clients[0].client_id);
    let retry = tokio::spawn(async move { g.authorize(params).await });
    for _ in 0..100 {
        if gateway.pending_signins().len() == 16 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let signin = gateway
        .pending_signins()
        .into_iter()
        .find(|s| s.client_name == "cap-test-0")
        .unwrap();
    gateway.decide_agent(&signin.agent_id, true).await.unwrap();
    let prism_core::AuthorizeOutcome::Redirect(uri) = retry.await.unwrap() else {
        panic!("expected code")
    };
    assert!(query_param(&uri, "code").is_some());
    assert_eq!(gateway.pending_signins().len(), 15);
    for job in parked {
        job.abort();
    }
    gateway.shutdown().await;
}

#[tokio::test]
async fn oauth_http_limits_reject_floods_and_large_bodies() {
    let (gateway, port, _dir) = start().await;
    let oversized = serde_json::json!({"client_name": "x".repeat(33 * 1024), "redirect_uris": ["http://localhost/cb"]}).to_string();
    assert_eq!(
        http(
            port,
            "POST",
            "/register",
            &[("Content-Type", "application/json")],
            &oversized
        )
        .await
        .status,
        413
    );
    for (method, path, content_type, limit) in [
        ("POST", "/register", "application/json", 29),
        ("GET", "/authorize", "application/json", 30),
        ("POST", "/token", "application/x-www-form-urlencoded", 120),
        ("POST", "/revoke", "application/x-www-form-urlencoded", 60),
    ] {
        for _ in 0..limit {
            let reply = http(port, method, path, &[("Content-Type", content_type)], "").await;
            assert_ne!(reply.status, 429, "{path}");
        }
        let reply = http(port, method, path, &[("Content-Type", content_type)], "").await;
        assert_eq!(reply.status, 429, "{path}: {}", reply.body);
        assert!(reply.headers["retry-after"].parse::<u64>().unwrap() > 0);
        assert_eq!(reply.headers["cache-control"], "no-store");
    }
    assert_eq!(
        http(
            port,
            "GET",
            "/.well-known/oauth-authorization-server",
            &[],
            ""
        )
        .await
        .status,
        200
    );
    assert!(PrismConfig::load(_dir.path().join("prism.json"))
        .unwrap()
        .clients
        .is_empty());
    gateway.shutdown().await;
}

/// Modern requests deliberately all claim the same clientInfo: the bearer,
/// never the client's self-description, must decide policy and audit identity.
fn modern_request(
    port: u16,
    token: &str,
    method: &str,
    mut params: serde_json::Value,
) -> reqwest::RequestBuilder {
    params["_meta"] = serde_json::json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name":"spoofed-client", "version":"1"},
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    let mut request = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/mcp"))
        .bearer_auth(token)
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", method);
    if let Some(name) = params.get("name").and_then(|n| n.as_str()) {
        request = request.header("Mcp-Name", name);
    }
    request.json(&serde_json::json!({"jsonrpc":"2.0", "id":42, "method":method, "params":params}))
}

async fn rpc_response(response: reqwest::Response) -> serde_json::Value {
    let text = tokio::time::timeout(Duration::from_secs(5), response.text())
        .await
        .unwrap()
        .unwrap();
    if text.starts_with('{') {
        return serde_json::from_str(&text).unwrap();
    }
    text.lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|value| value.get("result").is_some() || value.get("error").is_some())
        .unwrap_or_else(|| panic!("no JSON-RPC response: {text}"))
}

#[derive(Clone)]
struct CountingTool(
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
    rmcp::model::ProtocolVersion,
);

impl rmcp::ServerHandler for CountingTool {
    fn supported_protocol_versions(
        &self,
    ) -> std::borrow::Cow<'static, [rmcp::model::ProtocolVersion]> {
        std::borrow::Cow::Owned(vec![self.1.clone()])
    }
    fn get_info(&self) -> rmcp::model::ServerInfo {
        rmcp::model::ServerInfo::new(
            rmcp::model::ServerCapabilities::builder()
                .enable_tools()
                .build(),
        )
    }
    async fn list_tools(
        &self,
        _: Option<rmcp::model::PaginatedRequestParams>,
        _: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::ListToolsResult, rmcp::ErrorData> {
        let mut result = rmcp::model::ListToolsResult::default();
        result.tools.push(rmcp::model::Tool::new(
            "ping",
            "Count an execution",
            serde_json::json!({"type":"object"})
                .as_object()
                .unwrap()
                .clone(),
        ));
        Ok(result)
    }
    async fn call_tool(
        &self,
        _: rmcp::model::CallToolRequestParams,
        _: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::CallToolResponse, rmcp::ErrorData> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(
            rmcp::model::CallToolResult::success(vec![rmcp::model::ContentBlock::text("pong")])
                .into(),
        )
    }
}

struct ToolFixture {
    config: prism_core::ServerConfig,
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for ToolFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl ToolFixture {
    async fn start() -> Self {
        Self::with_version(rmcp::model::ProtocolVersion::V_2025_11_25).await
    }
    async fn with_version(version: rmcp::model::ProtocolVersion) -> Self {
        use rmcp::transport::streamable_http_server::{
            session::local::LocalSessionManager, tower::StreamableHttpService,
        };
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let tool = CountingTool(calls.clone(), version);
        let service = StreamableHttpService::new(
            move || Ok(tool.clone()),
            std::sync::Arc::new(LocalSessionManager::default()),
            rmcp::transport::StreamableHttpServerConfig::default().disable_allowed_hosts(),
        );
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            axum::serve(listener, axum::Router::new().nest_service("/mcp", service))
                .await
                .unwrap();
        });
        let config = serde_json::from_value(serde_json::json!({"id":"fixture", "name":"fixture", "url":format!("http://127.0.0.1:{port}/mcp"), "enabled":true})).unwrap();
        Self {
            config,
            calls,
            task,
        }
    }
}

async fn wait_for_call(gateway: &Gateway) -> prism_core::PendingCall {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(call) = gateway.pending().await.into_iter().next() {
                break call;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn stateless_calls_preserve_bearer_identity_policy_and_audit() {
    for version in [
        rmcp::model::ProtocolVersion::V_2025_11_25,
        rmcp::model::ProtocolVersion::V_2026_07_28,
    ] {
        assert_stateless_calls_through_upstream(version).await;
    }
}

async fn assert_stateless_calls_through_upstream(version: rmcp::model::ProtocolVersion) {
    let (gateway, port, _dir) = start().await;
    let fixture = ToolFixture::with_version(version).await;
    gateway.add_server(fixture.config.clone()).await.unwrap();
    let (agent_a, token_a) = signed_in_agent(&gateway, port, "modern-a").await;
    let (agent_b, token_b) = signed_in_agent(&gateway, port, "modern-b").await;
    let call = serde_json::json!({"name":"fixture__ping", "arguments":{}});

    for (agent, token, verdict) in [(&agent_a, &token_a, "allow"), (&agent_b, &token_b, "deny")] {
        let request = modern_request(port, token, "tools/call", call.clone());
        let response = tokio::spawn(async move { request.send().await.unwrap() });
        let pending = wait_for_call(&gateway).await;
        assert_eq!(&pending.agent_id, agent);
        gateway
            .decide(
                &pending.id,
                serde_json::from_value(serde_json::json!({"verdict":verdict, "scope":"always"}))
                    .unwrap(),
            )
            .await
            .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(3), response)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), 200);
        assert!(!response.headers().contains_key("mcp-session-id"));
        let reply = rpc_response(response).await;
        assert_eq!(reply["result"]["resultType"], "complete", "{reply}");
        assert_eq!(
            reply["result"]["isError"].as_bool().unwrap_or(false),
            verdict == "deny"
        );
    }
    assert_eq!(fixture.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    let denied = modern_request(port, &token_b, "tools/call", call.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(rpc_response(denied).await["result"]["isError"], true);
    assert!(gateway.pending().await.is_empty());
    assert_eq!(fixture.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    let audit = gateway.audit(10).await;
    assert_eq!(audit.len(), 3);
    assert_eq!(
        audit
            .iter()
            .filter(|e| e.agent_id == agent_a && e.verdict == prism_core::AuditVerdict::Allowed)
            .count(),
        1
    );
    assert_eq!(
        audit
            .iter()
            .filter(|e| e.agent_id == agent_b && e.verdict == prism_core::AuditVerdict::Denied)
            .count(),
        2
    );
    assert!(gateway
        .agents()
        .await
        .iter()
        .all(|a| a.agent.name != "spoofed-client"));

    // The same upstream also serves an older downstream client. Preserve its
    // legacy wire shape even when the upstream speaks the July protocol.
    let bearer = format!("Bearer {token_a}");
    let init = http(
        port,
        "POST",
        "/mcp",
        &[
            ("Content-Type", "application/json"),
            ("Accept", "application/json, text/event-stream"),
            ("Authorization", &bearer),
        ],
        INIT,
    )
    .await;
    assert_eq!(init.status, 200, "{}", init.body);
    let session = &init.headers["mcp-session-id"];
    let headers = [
        ("Content-Type", "application/json"),
        ("Accept", "application/json, text/event-stream"),
        ("Authorization", bearer.as_str()),
        ("MCP-Session-Id", session.as_str()),
        ("MCP-Protocol-Version", "2025-06-18"),
    ];
    let ready = http(
        port,
        "POST",
        "/mcp",
        &headers,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    )
    .await;
    assert_eq!(ready.status, 202);
    let legacy = http(port, "POST", "/mcp", &headers, r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fixture__ping","arguments":{}}}"#).await;
    assert_eq!(legacy.status, 200, "{}", legacy.body);
    assert!(legacy.body.contains("pong"), "{}", legacy.body);
    assert!(!legacy.body.contains("resultType"), "{}", legacy.body);
    assert_eq!(fixture.calls.load(std::sync::atomic::Ordering::SeqCst), 2);

    gateway.revoke_agent_tokens(&agent_a).await.unwrap();
    assert_eq!(
        modern_request(port, &token_a, "tools/call", call)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    gateway.shutdown().await;
}

async fn stream_until(response: &mut reqwest::Response, needle: &str) -> String {
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut text = String::new();
        loop {
            let bytes = response.chunk().await.unwrap().expect("stream ended early");
            text.push_str(&String::from_utf8_lossy(&bytes));
            if text.contains(needle) {
                break text;
            }
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn stateless_subscriptions_notify_and_end_on_revoke_or_disconnect() {
    let (gateway, port, _dir) = start().await;
    let token = gateway.create_manual_agent("listener").await.unwrap();
    let mut response = modern_request(
        port,
        &token.token,
        "subscriptions/listen",
        serde_json::json!({"notifications":{"toolsListChanged":true,"promptsListChanged":true}}),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(response.status(), 200);
    assert!(!response.headers().contains_key("mcp-session-id"));
    let ack = stream_until(&mut response, "notifications/subscriptions/acknowledged").await;
    assert!(ack.contains("toolsListChanged"));
    assert!(!ack.contains("promptsListChanged"));
    let fixture = ToolFixture::start().await;
    gateway.add_server(fixture.config.clone()).await.unwrap();
    stream_until(&mut response, "notifications/tools/list_changed").await;
    assert!(
        gateway
            .agents()
            .await
            .into_iter()
            .find(|a| a.agent.id == token.agent_id)
            .unwrap()
            .connected
    );
    gateway.revoke_token(&token.token).await;
    tokio::time::timeout(Duration::from_secs(3), response.text())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        modern_request(port, &token.token, "tools/list", serde_json::json!({}))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );

    let token2 = gateway
        .create_manual_agent("disconnected-listener")
        .await
        .unwrap();
    let mut response = modern_request(
        port,
        &token2.token,
        "subscriptions/listen",
        serde_json::json!({"notifications":{"toolsListChanged":true}}),
    )
    .send()
    .await
    .unwrap();
    stream_until(&mut response, "notifications/subscriptions/acknowledged").await;
    drop(response);
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if gateway.agents().await.iter().all(|a| !a.connected) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    gateway.shutdown().await;
}

#[tokio::test]
async fn stateless_disconnect_cancels_pending_approval_without_executing() {
    let (gateway, port, _dir) = start().await;
    let fixture = ToolFixture::start().await;
    gateway.add_server(fixture.config.clone()).await.unwrap();
    let token = gateway
        .create_manual_agent("cancelled-caller")
        .await
        .unwrap();
    let mut events = gateway.subscribe();
    let request = modern_request(
        port,
        &token.token,
        "tools/call",
        serde_json::json!({"name":"fixture__ping", "arguments":{}}),
    );
    let response = tokio::spawn(async move { request.send().await });
    let pending = wait_for_call(&gateway).await;
    response.abort();
    let _ = response.await;
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let prism_core::GatewayEvent::CallCancelled { id } = events.recv().await.unwrap() {
                assert_eq!(id, pending.id);
                break;
            }
        }
    })
    .await
    .unwrap();
    assert!(gateway.pending().await.is_empty());
    assert!(gateway
        .decide(
            &pending.id,
            serde_json::from_value(serde_json::json!({"verdict":"allow", "scope":"always"}))
                .unwrap()
        )
        .await
        .is_err());
    assert!(gateway.rules().await.is_empty());
    assert_eq!(fixture.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    let audit = gateway.audit(10).await;
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].agent_id, token.agent_id);
    assert!(matches!(
        audit[0].source,
        prism_core::AuditSource::Cancelled
    ));
    gateway.shutdown().await;
}

#[tokio::test]
async fn modern_requests_reject_missing_auth_and_mismatched_metadata() {
    let (gateway, port, _dir) = start().await;
    let token = gateway
        .create_manual_agent("metadata-client")
        .await
        .unwrap();
    let mut anonymous =
        modern_request(port, &token.token, "server/discover", serde_json::json!({}))
            .build()
            .unwrap();
    anonymous.headers_mut().remove("authorization");
    assert_eq!(
        reqwest::Client::new()
            .execute(anonymous)
            .await
            .unwrap()
            .status(),
        401
    );
    for (header, value) in [
        ("Mcp-Method", "tools/call"),
        ("MCP-Protocol-Version", "2025-11-25"),
    ] {
        let mut request = modern_request(port, &token.token, "tools/list", serde_json::json!({}))
            .build()
            .unwrap();
        request.headers_mut().insert(
            http::header::HeaderName::from_bytes(header.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
        let response = reqwest::Client::new().execute(request).await.unwrap();
        assert_eq!(response.status(), 400);
    }
    assert_eq!(
        modern_request(port, "invalid", "tools/list", serde_json::json!({}))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        modern_request(port, &token.token, "tools/list", serde_json::json!({}))
            .header("Origin", "https://evil.example")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    gateway.shutdown().await;
}

#[tokio::test]
#[ignore = "requires the Claude CLI; uses isolated settings and no model calls"]
async fn claude_cli_negotiates_both_protocols() {
    let (gateway, port, _dir) = start().await;
    let (_, access) = signed_in_agent(&gateway, port, "claude-smoke").await;
    let config = tempfile::tempdir().unwrap();
    let path = config.path().to_path_buf();
    tokio::task::spawn_blocking(move || {
        let server = serde_json::json!({"type":"http", "url":format!("http://127.0.0.1:{port}/mcp"), "headers":{"Authorization":format!("Bearer {access}")}});
        let added = std::process::Command::new("claude").env("CLAUDE_CONFIG_DIR", &path).current_dir(&path)
            .args(["mcp", "add-json", "prism-smoke", &server.to_string(), "--scope", "user"])
            .output().unwrap();
        assert!(added.status.success(), "isolated config failed");
        for (generation, negotiation, expected) in [("v2", "auto", "modern"), ("v2", "legacy", "legacy"), ("v1", "legacy", "v1")] {
            let log = path.join(format!("claude-{expected}.log")).to_string_lossy().into_owned();
            let result = std::process::Command::new("claude")
                .env("CLAUDE_CONFIG_DIR", &path).current_dir(&path)
                .env("MCP_SDK_GENERATION", generation).env("MCP_PROTOCOL_NEGOTIATION", negotiation)
                .args(["--debug-file", &log, "mcp", "get", "prism-smoke"])
                .output().unwrap();
            let output = String::from_utf8_lossy(&result.stdout);
            for line in output.lines().filter(|l| l.contains("Status:") || l.contains("Issue:")) { println!("{expected}: {line}"); }
            assert!(result.status.success());
            assert!(output.contains("Connected") && !output.contains("failed"));
            let log = std::fs::read_to_string(log).unwrap();
            if generation == "v2" { assert!(log.contains(&format!("\"protocolEra\":\"{expected}\"")), "wrong protocol lifecycle"); }
        }
    }).await.unwrap();
    gateway.shutdown().await;
}

#[tokio::test]
async fn browser_authorize_waits_privately_then_redirects_once() {
    for approved in [true, false] {
        let (gateway, port, _dir) = start().await;
        let browser = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let client = gateway
            .register_client(
                serde_json::from_value(serde_json::json!({
                    "client_name": "Browser <agent>", "redirect_uris": ["http://localhost:4444/cb"]
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier));
        let url = format!(
            "http://127.0.0.1:{port}/authorize?{}",
            form(&[
                ("client_id", &client.client_id),
                ("response_type", "code"),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
                ("state", "private-state&with=punctuation"),
            ])
        );
        let page = tokio::time::timeout(
            Duration::from_secs(2),
            browser
                .get(&url)
                .header("Accept", "text/html,application/xhtml+xml;q=0.9")
                .send(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(page.status(), 200);
        assert_eq!(page.headers()["cache-control"], "no-store");
        assert_eq!(page.headers()["referrer-policy"], "no-referrer");
        assert!(page.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'"));
        let html = page.text().await.unwrap();
        assert!(html.contains("Open Prism in your tray."));
        assert!(html.contains("Browser &lt;agent&gt;"));
        assert!(!html.contains("private-state"));
        assert!(!html.contains(&challenge));
        let req = html
            .split("const request = \"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        assert_eq!(req.len(), 43); // independent 256-bit capability
        let signin = wait_for_signin(&gateway).await;
        assert_ne!(req, signin.id);
        let status_url = format!("http://127.0.0.1:{port}/authorize/status?req={req}");
        let finish_url = format!("http://127.0.0.1:{port}/authorize/finish?req={req}");
        assert_eq!(browser.get(&status_url).send().await.unwrap().status(), 403);
        assert_eq!(
            browser
                .get(&status_url)
                .header("X-Prism-OAuth", "1")
                .header("Sec-Fetch-Site", "cross-site")
                .send()
                .await
                .unwrap()
                .status(),
            403
        );
        assert_eq!(
            browser
                .get(&finish_url)
                .header("Origin", "https://evil.example")
                .send()
                .await
                .unwrap()
                .status(),
            403
        );
        let pending = browser
            .get(&status_url)
            .header("X-Prism-OAuth", "1")
            .send()
            .await
            .unwrap();
        assert_eq!(
            pending.json::<serde_json::Value>().await.unwrap(),
            serde_json::json!({"status":"pending"})
        );
        assert_eq!(browser.get(&finish_url).send().await.unwrap().status(), 409);
        gateway
            .decide_agent(&signin.agent_id, approved)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let result = browser
                    .get(&status_url)
                    .header("X-Prism-OAuth", "1")
                    .send()
                    .await
                    .unwrap();
                assert_eq!(result.headers()["cache-control"], "no-store");
                let result = result.json::<serde_json::Value>().await.unwrap();
                if result == serde_json::json!({"status":"ready"}) {
                    break;
                }
                assert_eq!(result, serde_json::json!({"status":"pending"}));
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        let redirect = browser.get(&finish_url).send().await.unwrap();
        assert_eq!(redirect.status(), 303);
        assert_eq!(redirect.headers()["referrer-policy"], "no-referrer");
        let location =
            reqwest::Url::parse(redirect.headers()["location"].to_str().unwrap()).unwrap();
        let params: HashMap<_, _> = location.query_pairs().into_owned().collect();
        assert_eq!(params["state"], "private-state&with=punctuation");
        if approved {
            assert!(!params.contains_key("error"));
            let tokens = browser
                .post(format!("http://127.0.0.1:{port}/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(form(&[
                    ("grant_type", "authorization_code"),
                    ("code", params["code"].as_str()),
                    ("code_verifier", verifier),
                    ("client_id", &client.client_id),
                ]))
                .send()
                .await
                .unwrap();
            assert_eq!(tokens.status(), 200);
        } else {
            assert_eq!(params["error"], "access_denied");
            assert!(!params.contains_key("code"));
        }
        assert_eq!(browser.get(&finish_url).send().await.unwrap().status(), 410);
        assert_eq!(
            browser
                .get(&status_url)
                .header("X-Prism-OAuth", "1")
                .send()
                .await
                .unwrap()
                .status(),
            410
        );
        assert!(gateway.pending_signins().is_empty());
        gateway.shutdown().await;
    }
}

#[tokio::test]
async fn mcp_traffic_logs_requests_and_responses() {
    let (gateway, port, _dir) = start().await;
    let fixture = ToolFixture::start().await;
    gateway.add_server(fixture.config.clone()).await.unwrap();
    let (agent, token) = signed_in_agent(&gateway, port, "traffic-agent").await;
    gateway
        .set_agent_policy(&agent, Some(prism_core::Posture::Trusted), None)
        .await
        .unwrap();

    let auth_header = format!("Bearer {token}");
    let init_headers = [
        ("Content-Type", "application/json"),
        ("Accept", "application/json, text/event-stream"),
        ("Authorization", auth_header.as_str()),
    ];

    let init = http(port, "POST", "/mcp", &init_headers, INIT).await;
    assert_eq!(init.status, 200, "{}", init.body);

    let session = &init.headers["mcp-session-id"];
    let session_headers = [
        ("Content-Type", "application/json"),
        ("Accept", "application/json, text/event-stream"),
        ("Authorization", auth_header.as_str()),
        ("MCP-Session-Id", session.as_str()),
        ("MCP-Protocol-Version", "2025-06-18"),
    ];

    let list = http(port, "POST", "/mcp", &session_headers, LIST_TOOLS).await;
    assert_eq!(list.status, 200, "{}", list.body);

    let call = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fixture__ping","arguments":{}}}"#;
    let call_resp = http(port, "POST", "/mcp", &session_headers, call).await;
    assert_eq!(call_resp.status, 200, "{}", call_resp.body);

    let mcp_path = gateway.mcp_traffic_path();
    assert!(mcp_path.exists());

    let content = std::fs::read_to_string(mcp_path).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert!(lines.len() >= 3, "actual lines: {:?}", lines);

    let parsed: Vec<serde_json::Value> = lines
        .into_iter()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();

    assert!(parsed.iter().any(|p| p["method"] == "initialize"));
    assert!(parsed.iter().any(|p| p["method"] == "tools/list"));
    let tool_call = parsed.iter().find(|p| p["method"] == "tools/call").expect("tool call logged");
    assert_eq!(tool_call["method"], "tools/call");
    assert_eq!(tool_call["request"]["name"], "fixture__ping");
    assert!(tool_call["response"].to_string().contains("pong"), "actual tool_call: {tool_call}");

    gateway.shutdown().await;
}

