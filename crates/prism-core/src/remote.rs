//! Remote MCP servers over Streamable HTTP: plain, header-authenticated, or OAuth 2.1.
//!
//! OAuth uses rmcp's client: discovery from the server's 401 challenge (RFC 9728 and
//! RFC 8414), dynamic client registration (RFC 7591) as a public native client, the
//! authorization code flow with PKCE, and refresh. Prism signs in through the system browser
//! and takes the code back on a loopback listener bound for that one sign-in. The registered
//! client id and the tokens live in the OS credential store under the server's `oauth_ref`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::get;
use axum::Router;
use rmcp::model::ProtocolVersion;
use rmcp::service::{ClientLifecycleMode, ClientServiceExt};
use rmcp::transport::auth::{
    AuthClient, AuthError, AuthorizationManager, AuthorizationRequest, CredentialRefreshGuard,
    CredentialStore as TokenStore, OAuthState as RmcpOAuthState, StoredCredentials,
};
use rmcp::transport::streamable_http_client::{
    StreamableHttpClientTransport, StreamableHttpClientTransportConfig,
};
use tokio::sync::{mpsc, oneshot, Mutex};
use tracing::warn;

use crate::config::{HttpAuth, ServerConfig};
use crate::credentials::{self, CredentialStore, LaunchSettings};
use crate::error::{Error, Result};

#[path = "remote_revoke.rs"]
mod revocation;
pub(crate) use revocation::sign_out;

/// Name registered with the authorization server; it is what the consent page shows.
pub const CLIENT_NAME: &str = "Prism";
/// How long a browser sign-in may stay open before the loopback listener gives up.
pub const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

use crate::backend::{McpClient, Upstream};

fn http_client() -> Result<reqwest::Client> {
    // No global timeout: SSE responses stay open for as long as the session lives.
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .user_agent(format!("Prism/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|_| Error::Gateway("could not build an HTTP client".into()))
}

/// The remote endpoint must be https, or plain http on this machine only.
pub(crate) fn validate_url(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    let url = reqwest::Url::parse(trimmed)
        .map_err(|_| Error::Invalid("server URL is not valid".into()))?;
    let host = url
        .host_str()
        .ok_or_else(|| Error::Invalid("server URL needs a host".into()))?;
    let loopback = matches!(host, "127.0.0.1" | "localhost" | "[::1]" | "::1");
    match url.scheme() {
        "https" => {}
        "http" if loopback => {}
        "http" => {
            return Err(Error::Invalid(
                "plain http is only allowed for servers on this machine; use https".into(),
            ))
        }
        _ => return Err(Error::Invalid("server URL must start with https://".into())),
    }
    Ok(trimmed.to_string())
}

fn transport_config(
    url: &str,
    headers: &std::collections::BTreeMap<String, String>,
) -> Result<StreamableHttpClientTransportConfig> {
    let mut custom = HashMap::new();
    for (name, value) in headers {
        let name = http::HeaderName::from_bytes(name.trim().as_bytes())
            .map_err(|_| Error::Invalid(format!("invalid header name {name:?}")))?;
        let value = http::HeaderValue::from_str(value.trim())
            .map_err(|_| Error::Invalid(format!("invalid value for header {}", name.as_str())))?;
        custom.insert(name, value);
    }
    Ok(
        StreamableHttpClientTransportConfig::with_uri(url.to_string())
            .custom_headers(custom)
            .reinit_on_expired_session(true),
    )
}

fn describe(err: AuthError) -> Error {
    // Never echo the server's text: it may carry URLs with codes or tokens.
    match err {
        AuthError::AuthorizationRequired => Error::SignInRequired,
        AuthError::NoAuthorizationSupport => {
            Error::Gateway("this server does not offer OAuth sign-in".into())
        }
        AuthError::PkceUnsupported => {
            Error::Gateway("this server's sign-in does not support PKCE".into())
        }
        AuthError::RegistrationFailed(_) => {
            Error::Gateway("the server refused to register Prism as a client".into())
        }
        AuthError::MetadataError(_) => {
            Error::Gateway("could not read the server's sign-in settings".into())
        }
        AuthError::CredentialStoreError(_) => {
            Error::Gateway("could not save sign-in credentials".into())
        }
        AuthError::TokenExchangeFailed(_) => {
            Error::Gateway("could not exchange the sign-in code".into())
        }
        _ => Error::Gateway("sign-in failed".into()),
    }
}

async fn handshake<F>(serve: F) -> Result<McpClient>
where
    F: std::future::Future<
        Output = std::result::Result<McpClient, rmcp::service::ClientInitializeError>,
    >,
{
    tokio::time::timeout(HANDSHAKE_TIMEOUT, serve)
        .await
        .map_err(|_| Error::Backend("server handshake timed out".into()))?
        .map_err(|err| {
            let text = err.to_string();
            if text.contains("401") || text.contains("Unauthorized") || text.contains("auth") {
                Error::SignInRequired
            } else {
                Error::Backend(format!("server handshake failed: {err}; check the URL and its sign-in"))
            }
        })
}

/// Open a session to a remote server. `SignInRequired` means the operator must sign in first.
pub(crate) async fn connect(
    config: &ServerConfig,
    launch: &LaunchSettings,
    store: Arc<dyn CredentialStore>,
    traffic: Arc<crate::mcp_traffic::McpTrafficLogger>,
) -> Result<McpClient> {
    let url = config
        .url
        .as_deref()
        .ok_or_else(|| Error::Invalid("remote server has no URL".into()))?;
    let transport_config = transport_config(url, &launch.headers)?;
    match config.auth {
        HttpAuth::None | HttpAuth::Header => {
            let transport =
                StreamableHttpClientTransport::with_client(http_client()?, transport_config);
            let logged = crate::mcp_traffic::ServerLoggingTransport::new(transport, config.id.clone(), traffic);
            handshake(Upstream::default().serve_with_lifecycle(logged, remote_lifecycle())).await
        }
        HttpAuth::Oauth => {
            let manager = authorized_manager(config, store).await?;
            let client = AuthClient::new(http_client()?, manager);
            let transport = StreamableHttpClientTransport::with_client(client, transport_config);
            let logged = crate::mcp_traffic::ServerLoggingTransport::new(transport, config.id.clone(), traffic);
            handshake(Upstream::default().serve_with_lifecycle(logged, remote_lifecycle())).await
        }
    }
}

fn remote_lifecycle() -> ClientLifecycleMode {
    ClientLifecycleMode::Auto {
        preferred_versions: vec![
            ProtocolVersion::V_2026_07_28,
            ProtocolVersion::V_2025_11_25,
            ProtocolVersion::V_2025_06_18,
            ProtocolVersion::V_2025_03_26,
        ],
        legacy_version: Some(ProtocolVersion::V_2025_11_25),
    }
}

/// An authorization manager loaded from stored tokens, or `SignInRequired`.
async fn authorized_manager(
    config: &ServerConfig,
    store: Arc<dyn CredentialStore>,
) -> Result<AuthorizationManager> {
    let url = config.url.as_deref().unwrap_or_default();
    let mut manager = AuthorizationManager::new(url).await.map_err(describe)?;
    manager.with_client(http_client()?).map_err(describe)?;
    manager.set_credential_store(Tokens::new(store, config.oauth_ref.clone())?);
    let ready = tokio::time::timeout(HANDSHAKE_TIMEOUT, manager.initialize_from_store())
        .await
        .map_err(|_| Error::Backend("server handshake timed out".into()))?
        .map_err(describe)?;
    if !ready {
        return Err(Error::SignInRequired);
    }
    Ok(manager)
}

/// rmcp's credential store on top of the OS credential store, one record per server.
struct Tokens {
    store: Arc<dyn CredentialStore>,
    id: String,
    refresh: Arc<Mutex<()>>,
}

impl Tokens {
    fn new(store: Arc<dyn CredentialStore>, id: Option<String>) -> Result<Self> {
        let id =
            id.ok_or_else(|| Error::Invalid("OAuth server has no credential reference".into()))?;
        uuid::Uuid::parse_str(&id)
            .map_err(|_| Error::Invalid("invalid OAuth credential reference".into()))?;
        Ok(Self {
            store,
            id,
            refresh: Arc::new(Mutex::new(())),
        })
    }
}

#[async_trait::async_trait]
impl TokenStore for Tokens {
    async fn load(&self) -> std::result::Result<Option<StoredCredentials>, AuthError> {
        let (store, id) = (self.store.clone(), self.id.clone());
        let bytes = tokio::task::spawn_blocking(move || credentials::get_blob(store.as_ref(), &id))
            .await
            .map_err(|_| AuthError::CredentialStoreError("credential store task failed".into()))?;
        match bytes {
            // A missing record and a locked store look the same to the keyring; both mean
            // "sign in", and a locked store surfaces on the save that follows.
            Err(_) => Ok(None),
            Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|_| {
                AuthError::CredentialStoreError("stored tokens are unreadable".into())
            }),
        }
    }

    async fn save(&self, creds: StoredCredentials) -> std::result::Result<(), AuthError> {
        let bytes = serde_json::to_vec(&creds)
            .map_err(|_| AuthError::CredentialStoreError("could not encode tokens".into()))?;
        let (store, id) = (self.store.clone(), self.id.clone());
        tokio::task::spawn_blocking(move || credentials::put_blob(store.as_ref(), &id, &bytes))
            .await
            .map_err(|_| AuthError::CredentialStoreError("credential store task failed".into()))?
            .map_err(|_| AuthError::CredentialStoreError("credential store is unavailable".into()))
    }

    async fn clear(&self) -> std::result::Result<(), AuthError> {
        let (store, id) = (self.store.clone(), self.id.clone());
        tokio::task::spawn_blocking(move || credentials::delete_if_present(store.as_ref(), &id))
            .await
            .map_err(|_| AuthError::CredentialStoreError("credential store task failed".into()))?
            .map_err(|_| AuthError::CredentialStoreError("credential store is unavailable".into()))
    }

    async fn acquire_refresh_guard(
        &self,
    ) -> std::result::Result<Option<CredentialRefreshGuard>, AuthError> {
        Ok(Some(CredentialRefreshGuard::new(
            self.refresh.clone().lock_owned().await,
        )))
    }
}

/// Forget a server's registration and tokens.
pub(crate) fn forget_tokens(store: &dyn CredentialStore, config: &ServerConfig) -> Result<()> {
    match &config.oauth_ref {
        Some(id) => credentials::delete_if_present(store, id),
        None => Ok(()),
    }
}

/// A browser sign-in in progress: the URL to open, and the outcome once the browser comes back.
pub(crate) struct SignIn {
    pub url: String,
    pub done: oneshot::Receiver<Result<()>>,
}

#[derive(Clone)]
struct CallbackState {
    tx: mpsc::Sender<CallbackRequest>,
    expected_state: String,
    server_name: String,
}

/// The page the browser lands on. Same tokens as the panel; nothing loaded from anywhere.
const CALLBACK_PAGE: &str = include_str!("callback.html");

pub(crate) fn html_escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Fill the callback page for one outcome. `lede` may carry the escaped server name in a `<b>`.
pub(crate) fn callback_page(
    state: &str,
    eyebrow_class: &str,
    eyebrow: &str,
    title: &str,
    lede: &str,
) -> String {
    CALLBACK_PAGE
        .replace("{{state}}", state)
        .replace("{{eyebrow_class}}", eyebrow_class)
        .replace("{{eyebrow}}", eyebrow)
        .replace("{{title}}", title)
        .replace(
            "{{footer}}",
            if matches!(state, "waiting" | "inprogress") {
                "Keep this tab open."
            } else {
                "You can close this tab."
            },
        )
        .replace(
            "{{script}}",
            "<script>history.replaceState(null, \"\", location.pathname);</script>",
        )
        .replace("{{lede}}", lede)
}

struct CallbackRequest {
    query: String,
    refused: bool,
    reply: oneshot::Sender<CallbackOutcome>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CallbackOutcome {
    Saved,
    Refused,
    Invalid,
    StoreFailed,
    ExchangeFailed,
    TimedOut,
    Finished,
    Busy,
}

impl CallbackOutcome {
    fn response(self, name: &str) -> axum::response::Response {
        let (status, state, eyebrow, title, lede) = match self {
            Self::Saved => (StatusCode::OK, "ok", "Credentials saved", "Signed in.",
                format!("Prism saved your sign-in for <b>{}</b>. Check the Servers tab while Prism connects.", html_escape(name))),
            Self::Refused => (StatusCode::FORBIDDEN, "refused", "Access not granted", "Sign-in refused.",
                "The server did not grant access. You can try again from the Prism panel.".into()),
            Self::Invalid => (StatusCode::BAD_REQUEST, "failed", "Callback rejected", "Could not verify this callback.",
                "It is incomplete or does not match this sign-in. Return to the original sign-in tab to continue.".into()),
            Self::StoreFailed => (StatusCode::INTERNAL_SERVER_ERROR, "failed", "Credentials not saved", "Could not save your sign-in.",
                "Prism could not save credentials in the system credential store. Unlock it, then try signing in again from Prism.".into()),
            Self::ExchangeFailed => (StatusCode::BAD_GATEWAY, "failed", "Sign-in failed", "Could not complete sign-in.",
                "Prism could not exchange the server's authorization code for credentials. Try again from the Prism panel.".into()),
            Self::TimedOut => (StatusCode::GATEWAY_TIMEOUT, "failed", "Sign-in timed out", "The server took too long.",
                "Prism could not confirm that sign-in finished. Check the Servers tab and try again.".into()),
            Self::Finished => (StatusCode::GONE, "done", "Sign-in ended", "This sign-in already ended.",
                "Check the Servers tab for the result, or start a new sign-in from Prism.".into()),
            Self::Busy => (StatusCode::CONFLICT, "done", "Sign-in in progress", "Prism is checking your sign-in.",
                "Keep the original callback tab open for the result.".into()),
        };
        crate::oauth::browser_response(
            status,
            callback_page(
                state,
                if state == "ok" { "" } else { "warn" },
                eyebrow,
                title,
                &lede,
            ),
        )
    }
}

fn callback_progress_page(name: &str) -> String {
    callback_page(
        "inprogress",
        "",
        "Completing sign-in",
        "Finishing your sign-in.",
        &format!(
            "Prism is checking the response from <b>{}</b> and saving your credentials.",
            html_escape(name)
        ),
    )
    .replace(
        "<script>history.replaceState(null, \"\", location.pathname);</script>",
        include_str!("callback-progress.html"),
    )
}

async fn callback(
    State(state): State<CallbackState>,
    headers: HeaderMap,
    Query(params): Query<Vec<(String, String)>>,
) -> axum::response::Response {
    // Validate before handing off the attempt. Missing, duplicated, empty or forged
    // callbacks must not consume the PKCE state or close the legitimate listener.
    let one = |key: &str| -> Option<&str> {
        let mut values = params
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.as_str());
        let value = values.next()?;
        (!value.is_empty() && values.next().is_none()).then_some(value)
    };
    let valid_state = one("state").is_some_and(|value| {
        crate::oauth::constant_time_eq(value.as_bytes(), state.expected_state.as_bytes())
    });
    let has_code = params.iter().any(|(k, _)| k == "code");
    let has_error = params.iter().any(|(k, _)| k == "error");
    let valid_result = (has_code && !has_error && one("code").is_some())
        || (has_error && !has_code && one("error").is_some());
    let has_issuer = params.iter().any(|(k, _)| k == "iss");
    if !valid_state || !valid_result || (has_issuer && one("iss").is_none()) {
        return CallbackOutcome::Invalid.response(&state.server_name);
    }
    if state.tx.is_closed() {
        return CallbackOutcome::Finished.response(&state.server_name);
    }
    if crate::oauth::wants_html(&headers) {
        // Navigation only renders progress; its script submits the callback once.
        return crate::oauth::browser_response(
            StatusCode::OK,
            callback_progress_page(&state.server_name),
        );
    }
    if !crate::oauth::same_origin(&headers)
        || headers
            .get("x-prism-oauth")
            .is_some_and(|value| value != "1")
    {
        return crate::oauth::private_response(axum::response::IntoResponse::into_response(
            StatusCode::FORBIDDEN,
        ));
    }
    let query = params
        .iter()
        .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let (reply, received) = oneshot::channel();
    match state.tx.try_send(CallbackRequest {
        query,
        refused: has_error,
        reply,
    }) {
        Ok(()) => received.await.unwrap_or(CallbackOutcome::Finished),
        Err(mpsc::error::TrySendError::Full(_)) => CallbackOutcome::Busy,
        Err(mpsc::error::TrySendError::Closed(_)) => CallbackOutcome::Finished,
    }
    .response(&state.server_name)
}

async fn receive_callback(
    state: &mut RmcpOAuthState,
    rx: &mut mpsc::Receiver<CallbackRequest>,
    redirect_uri: &str,
    timeout: Duration,
    exchange_timeout: Duration,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let request = match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(request)) => request,
            Ok(None) => return Err(Error::Gateway("sign-in was cancelled".into())),
            Err(_) => {
                return Err(Error::Gateway(
                    "sign-in timed out; the browser never came back".into(),
                ))
            }
        };
        let (page, outcome) = if request.refused {
            (
                CallbackOutcome::Refused,
                Err(Error::Gateway("the server refused sign-in".into())),
            )
        } else {
            let url = format!("{redirect_uri}?{}", request.query);
            match tokio::time::timeout(exchange_timeout, state.handle_callback_url(&url)).await {
                Ok(Ok(())) => (CallbackOutcome::Saved, Ok(())),
                Ok(Err(err)) => {
                    // rmcp keeps the authorization state when issuer validation fails.
                    // Keep the callback listener too, so the real response can still arrive.
                    if matches!(
                        err,
                        AuthError::AuthorizationServerMismatch { .. }
                            | AuthError::AuthorizationServerMissingIssuer { .. }
                            | AuthError::AuthorizationFailed(_)
                    ) {
                        let _ = request.reply.send(CallbackOutcome::Invalid);
                        continue;
                    }
                    let page = if matches!(err, AuthError::CredentialStoreError(_)) {
                        CallbackOutcome::StoreFailed
                    } else {
                        CallbackOutcome::ExchangeFailed
                    };
                    warn!("OAuth sign-in failed: {}", kind(&err));
                    (page, Err(describe(err)))
                }
                Err(_) => (
                    CallbackOutcome::TimedOut,
                    Err(Error::Gateway(
                        "sign-in timed out while completing the callback".into(),
                    )),
                ),
            }
        };
        // Only now may the browser report success: rmcp has validated state,
        // exchanged the code, and awaited Tokens::save all the way through keyring.
        let _ = request.reply.send(page);
        return outcome;
    }
}

fn urlencode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Start a browser sign-in for an OAuth server. Returns the URL to open; the receiver
/// resolves once the browser has come back and the tokens are stored, or on failure.
pub(crate) async fn begin_sign_in(
    config: &ServerConfig,
    store: Arc<dyn CredentialStore>,
) -> Result<SignIn> {
    let url = config
        .url
        .clone()
        .ok_or_else(|| Error::Invalid("remote server has no URL".into()))?;
    if config.auth != HttpAuth::Oauth {
        return Err(Error::Invalid("this server does not use OAuth".into()));
    }
    let tokens = Tokens::new(store, config.oauth_ref.clone())?;

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");

    let mut state = RmcpOAuthState::new(url.as_str(), Some(http_client()?))
        .await
        .map_err(describe)?;
    if let RmcpOAuthState::Unauthorized(manager) = &mut state {
        manager.set_credential_store(tokens);
    }
    let request = AuthorizationRequest::new(redirect_uri.clone()).with_client_name(CLIENT_NAME);
    tokio::time::timeout(HANDSHAKE_TIMEOUT, state.start_authorization(request))
        .await
        .map_err(|_| Error::Backend("the server's sign-in settings took too long to load".into()))?
        .map_err(describe)?;
    let auth_url = state.get_authorization_url().await.map_err(describe)?;

    let expected_state = reqwest::Url::parse(&auth_url)
        .ok()
        .and_then(|url| {
            url.query_pairs()
                .find(|(k, _)| k == "state")
                .map(|(_, v)| v.into_owned())
        })
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::Gateway("the sign-in URL has no state".into()))?;
    let (query_tx, mut query_rx) = mpsc::channel::<CallbackRequest>(1);
    let (done_tx, done_rx) = oneshot::channel::<Result<()>>();
    let app = Router::new()
        .route("/callback", get(callback))
        .with_state(CallbackState {
            tx: query_tx,
            expected_state,
            server_name: config.name.clone(),
        });
    tokio::spawn(async move {
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let mut serve = tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = stop_rx.await;
                })
                .await;
        });
        let outcome = receive_callback(
            &mut state,
            &mut query_rx,
            &redirect_uri,
            SIGN_IN_TIMEOUT,
            HANDSHAKE_TIMEOUT,
        )
        .await;
        // Close queued/replayed callbacks without processing them a second time.
        drop(query_rx);
        // Let the browser receive its page before the listener goes away.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let _ = stop_tx.send(());
        if tokio::time::timeout(Duration::from_secs(1), &mut serve)
            .await
            .is_err()
        {
            serve.abort();
        }
        let _ = done_tx.send(outcome);
    });

    Ok(SignIn {
        url: auth_url,
        done: done_rx,
    })
}

fn kind(err: &AuthError) -> &'static str {
    match err {
        AuthError::AuthorizationRequired => "authorization required",
        AuthError::NoAuthorizationSupport => "no authorization support",
        AuthError::PkceUnsupported => "pkce unsupported",
        AuthError::RegistrationFailed(_) => "registration failed",
        AuthError::MetadataError(_) => "metadata error",
        AuthError::CredentialStoreError(_) => "credential store error",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;

    #[test]
    fn urls_must_be_https_unless_local() {
        assert!(validate_url("https://mcp.example.com/mcp").is_ok());
        assert!(validate_url("http://127.0.0.1:8080/mcp").is_ok());
        assert!(validate_url("http://localhost:8080/mcp").is_ok());
        assert!(validate_url("http://mcp.example.com/mcp").is_err());
        assert!(validate_url("ftp://mcp.example.com/mcp").is_err());
        assert!(validate_url("not a url").is_err());
    }

    #[test]
    fn header_names_and_values_are_checked() {
        let mut headers = std::collections::BTreeMap::new();
        headers.insert("Authorization".to_string(), "Bearer abc".to_string());
        assert!(transport_config("https://x.example/mcp", &headers).is_ok());
        headers.insert("bad header".to_string(), "x".to_string());
        assert!(transport_config("https://x.example/mcp", &headers).is_err());
    }

    #[test]
    fn callback_page_escapes_the_server_name_and_marks_the_outcome() {
        let name = html_escape("acme <b>&</b> \"co\"");
        let page = callback_page(
            "ok",
            "",
            "Connected",
            "Signed in.",
            &format!("from <b>{name}</b>"),
        );
        assert!(page.contains("data-state=\"ok\""));
        assert!(page.contains("<h1>Signed in.</h1>"));
        assert!(page.contains("from <b>acme &lt;b&gt;&amp;&lt;/b&gt; &quot;co&quot;</b>"));
        assert!(!page.contains("{{"), "every placeholder is filled");
        assert!(
            !page.contains("https://"),
            "the page loads nothing from anywhere"
        );
    }

    #[test]
    fn callback_query_is_reencoded() {
        assert_eq!(urlencode("a b/c"), "a%20b%2Fc");
        assert_eq!(urlencode("safe-_.~"), "safe-_.~");
    }

    use crate::backend::{BackendManager, BackendStatus};
    use crate::credentials::tests::MemoryStore;
    use crate::gateway::Gateway;
    use rmcp::handler::server::ServerHandler;
    use rmcp::model::{
        ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerInfo, Tool,
    };
    use rmcp::service::RequestContext;
    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use rmcp::transport::streamable_http_server::tower::StreamableHttpService;
    use rmcp::transport::StreamableHttpServerConfig;
    use rmcp::{ErrorData as McpError, RoleServer};
    use std::collections::BTreeMap;

    const TEST_KEY: &str = "Bearer test-key";

    /// A one-tool server behind a fixed API key.
    #[derive(Clone)]
    struct Pinger;

    impl ServerHandler for Pinger {
        fn get_info(&self) -> ServerInfo {
            ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
        }

        async fn list_tools(
            &self,
            _request: Option<PaginatedRequestParams>,
            _context: RequestContext<RoleServer>,
        ) -> std::result::Result<ListToolsResult, McpError> {
            #[allow(clippy::field_reassign_with_default)]
            {
                let mut result = ListToolsResult::default();
                result.tools = vec![Tool::new("ping", "pong", serde_json::Map::new())];
                Ok(result)
            }
        }
    }

    async fn require_key(
        request: axum::extract::Request,
        next: axum::middleware::Next,
    ) -> axum::response::Response {
        let ok = request
            .headers()
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            == Some(TEST_KEY);
        if ok {
            next.run(request).await
        } else {
            (
                http::StatusCode::UNAUTHORIZED,
                [(http::header::WWW_AUTHENTICATE, "Bearer")],
                "no",
            )
                .into_response()
        }
    }

    async fn pinger_on_loopback() -> u16 {
        let service: StreamableHttpService<Pinger, LocalSessionManager> =
            StreamableHttpService::new(
                || Ok(Pinger),
                LocalSessionManager::default().into(),
                StreamableHttpServerConfig::default().disable_allowed_hosts(),
            );
        let app = Router::new()
            .nest_service("/mcp", service)
            .layer(axum::middleware::from_fn(require_key));
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        port
    }

    fn remote(
        name: &str,
        url: String,
        auth: HttpAuth,
        headers: BTreeMap<String, String>,
    ) -> ServerConfig {
        ServerConfig {
            id: name.to_string(),
            name: name.to_string(),
            command: String::new(),
            args: Vec::new(),
            env: BTreeMap::new(),
            credential_ref: None,
            enabled: true,
            url: Some(url),
            auth,
            headers,
            oauth_ref: None,
            hidden_tools: Default::default(),
        }
    }

    async fn status_of(manager: &BackendManager, id: &str) -> BackendStatus {
        manager
            .snapshot()
            .await
            .into_iter()
            .find(|(c, _)| c.id == id)
            .map(|(_, s)| s)
            .unwrap()
    }

    #[tokio::test]
    async fn header_auth_reaches_a_remote_server_and_the_key_stays_in_the_store() {
        let port = pinger_on_loopback().await;
        let store = Arc::new(MemoryStore::default());
        let (events, _rx) = crate::events::channel();
        let manager = BackendManager::new(events, store.clone());
        let url = format!("http://127.0.0.1:{port}/mcp");

        let mut good = remote(
            "good",
            url.clone(),
            HttpAuth::Header,
            BTreeMap::from([("Authorization".to_string(), TEST_KEY.to_string())]),
        );
        credentials::protect_server(store.as_ref(), &mut good).unwrap();
        assert!(
            good.headers.is_empty(),
            "the key must not stay in the config"
        );
        assert!(good.credential_ref.is_some());
        manager.start(good.clone()).await;
        assert_eq!(
            status_of(&manager, "good").await,
            BackendStatus::Running { tool_count: 1 }
        );
        let tools = manager.list_tools(false).await;
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].1.name.as_ref(), "ping");

        let mut bad = remote(
            "bad",
            url.clone(),
            HttpAuth::Header,
            BTreeMap::from([("Authorization".to_string(), "Bearer wrong".to_string())]),
        );
        credentials::protect_server(store.as_ref(), &mut bad).unwrap();
        manager.start(bad).await;
        assert!(
            matches!(
                status_of(&manager, "bad").await,
                BackendStatus::Failed { .. } | BackendStatus::SignInRequired
            ),
            "a refused key must not show as running"
        );

        let none = remote("none", url, HttpAuth::None, BTreeMap::new());
        manager.start(none).await;
        assert!(!matches!(
            status_of(&manager, "none").await,
            BackendStatus::Running { .. }
        ));
    }

    async fn gateway_on_loopback() -> (Arc<Gateway>, u16, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let config = crate::config::PrismConfig {
            listen_port: port,
            ..Default::default()
        };
        let path = dir.path().join("prism.json");
        config.save(&path).unwrap();
        let gateway = Gateway::start_with_credentials(
            path,
            dir.path().join("audit.jsonl"),
            Arc::new(MemoryStore::default()),
        )
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
        (gateway, port, dir)
    }

    async fn wait_for<F: Fn(&crate::backend::BackendStatus) -> bool>(
        gateway: &Gateway,
        id: &str,
        what: &str,
        pred: F,
    ) -> BackendStatus {
        for _ in 0..200 {
            let status = gateway
                .servers()
                .await
                .into_iter()
                .find(|s| s.id == id)
                .map(|s| s.status)
                .unwrap();
            if pred(&status) {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("server never reached {what}");
    }

    // Only the token-bearing save is controlled; dynamic registration still succeeds.
    struct TestTokenStore {
        inner: MemoryStore,
        fail: bool,
        entered: tokio::sync::Notify,
        release: (std::sync::Mutex<bool>, std::sync::Condvar),
    }
    impl TestTokenStore {
        fn new(fail: bool) -> Self {
            Self {
                inner: MemoryStore::default(),
                fail,
                entered: tokio::sync::Notify::new(),
                release: (std::sync::Mutex::new(false), std::sync::Condvar::new()),
            }
        }
        fn release(&self) {
            *self.release.0.lock().unwrap() = true;
            self.release.1.notify_all();
        }
    }
    impl CredentialStore for TestTokenStore {
        fn set(&self, key: &str, value: &[u8]) -> Result<()> {
            let json: serde_json::Value = serde_json::from_slice(value).unwrap();
            if json
                .get("token_response")
                .is_some_and(|token| !token.is_null())
            {
                self.entered.notify_one();
                let (released, _) = self
                    .release
                    .1
                    .wait_timeout_while(
                        self.release.0.lock().unwrap(),
                        Duration::from_secs(5),
                        |released| !*released,
                    )
                    .unwrap();
                assert!(*released, "test must release the credential store");
                if self.fail {
                    return Err(Error::Gateway("synthetic locked store".into()));
                }
            }
            self.inner.set(key, value)
        }
        fn get(&self, key: &str) -> Result<Vec<u8>> {
            self.inner.get(key)
        }
        fn delete(&self, key: &str) -> Result<()> {
            self.inner.delete(key)
        }
    }

    #[tokio::test]
    async fn callback_waits_for_the_actual_credential_save_and_reports_failures() {
        for fail in [false, true] {
            let (upstream, port, _dir) = gateway_on_loopback().await;
            let store = Arc::new(TestTokenStore::new(fail));
            let mut config = remote(
                "store <test>",
                format!("http://127.0.0.1:{port}/mcp"),
                HttpAuth::Oauth,
                BTreeMap::new(),
            );
            let id = uuid::Uuid::new_v4().to_string();
            config.oauth_ref = Some(id.clone());
            let mut signin = begin_sign_in(&config, store.clone()).await.unwrap();
            let browser = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap();
            let auth_url = reqwest::Url::parse(&signin.url).unwrap();
            let params: HashMap<_, _> = auth_url.query_pairs().into_owned().collect();
            let callback_url = &params["redirect_uri"];
            // All malformed callbacks leave the legitimate attempt available.
            for query in [
                "".into(),
                "code=secret-code&state=wrong".into(),
                format!(
                    "code=secret-code&state={}&state={}",
                    params["state"], params["state"]
                ),
                format!("code=&state={}", params["state"]),
                format!("code=secret-code&error=denied&state={}", params["state"]),
            ] {
                let response = browser
                    .get(format!("{callback_url}?{query}"))
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status(), 400);
                let html = response.text().await.unwrap();
                assert!(html.contains("Could not verify this callback"));
                assert!(!html.contains("secret-code"));
                assert!(!html.contains("Credentials saved"));
                assert!(matches!(
                    signin.done.try_recv(),
                    Err(oneshot::error::TryRecvError::Empty)
                ));
            }
            let authorization = tokio::spawn({
                let browser = browser.clone();
                let url = signin.url.clone();
                async move { browser.get(url).send().await.unwrap() }
            });
            let pending = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if let Some(pending) = upstream.pending_signins().into_iter().next() {
                        break pending;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
            upstream
                .decide_agent(&pending.agent_id, true)
                .await
                .unwrap();
            let authorized = authorization.await.unwrap();
            assert_eq!(authorized.status(), 303);
            let location = authorized.headers()["location"]
                .to_str()
                .unwrap()
                .to_owned();
            // Even a state-matching callback with a forged issuer must not burn the real code.
            let forged = browser
                .get(format!("{location}&iss=https%3A%2F%2Fwrong.example"))
                .send()
                .await
                .unwrap();
            assert_eq!(forged.status(), 400);
            assert!(matches!(
                signin.done.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            let progress = tokio::time::timeout(
                Duration::from_secs(1),
                browser.get(&location).header("Accept", "text/html").send(),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(progress.status(), 200);
            assert_eq!(progress.headers()["cache-control"], "no-store");
            let csp = progress.headers()["content-security-policy"]
                .to_str()
                .unwrap()
                .to_owned();
            let html = progress.text().await.unwrap();
            assert!(html.contains("data-state=\"inprogress\""));
            assert!(html.contains("Finishing your sign-in"));
            assert!(!html.contains("Credentials saved"));
            assert!(!html.contains(&params["state"]));
            let code = reqwest::Url::parse(&location)
                .unwrap()
                .query_pairs()
                .find(|(k, _)| k == "code")
                .unwrap()
                .1
                .into_owned();
            assert!(!html.contains(&code));
            let nonce = html
                .split("<script nonce=\"")
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap();
            assert!(csp.contains(&format!("'nonce-{nonce}'")));
            assert!(
                tokio::time::timeout(Duration::from_millis(25), store.entered.notified())
                    .await
                    .is_err(),
                "rendering HTML must not consume the callback"
            );
            let rejected = browser
                .get(&location)
                .header("Accept", "application/json")
                .header("X-Prism-OAuth", "1")
                .header("Sec-Fetch-Site", "cross-site")
                .send()
                .await
                .unwrap();
            assert_eq!(rejected.status(), 403);
            let mut callback = tokio::spawn({
                let browser = browser.clone();
                let location = location.clone();
                async move {
                    browser
                        .get(location)
                        .header("Accept", "application/json")
                        .header("X-Prism-OAuth", "1")
                        .header("Sec-Fetch-Site", "same-origin")
                        .send()
                        .await
                        .unwrap()
                }
            });
            tokio::time::timeout(Duration::from_secs(2), store.entered.notified())
                .await
                .unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(25), &mut callback)
                    .await
                    .is_err(),
                "browser must wait until the credential store finishes"
            );
            // Even while the real exchange is blocked in keyring, browser navigation
            // gets progress immediately and cannot enqueue/consume another attempt.
            let progress = tokio::time::timeout(
                Duration::from_secs(1),
                browser.get(&location).header("Accept", "text/html").send(),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(progress.status(), 200);
            assert!(progress
                .text()
                .await
                .unwrap()
                .contains("Finishing your sign-in"));
            store.release();
            let response = callback.await.unwrap();
            assert_eq!(response.headers()["cache-control"], "no-store");
            assert_eq!(response.headers()["referrer-policy"], "no-referrer");
            assert_eq!(response.status(), if fail { 500 } else { 200 });
            let html = response.text().await.unwrap();
            assert!(html.contains(if fail {
                "Could not save your sign-in"
            } else {
                "Credentials saved"
            }));
            assert!(!html.contains(&params["state"]));
            let creds = Tokens::new(store.clone(), Some(id))
                .unwrap()
                .load()
                .await
                .unwrap();
            assert_eq!(creds.and_then(|c| c.token_response).is_some(), !fail);
            let replay = browser.get(&location).send().await.unwrap();
            assert_eq!(replay.status(), 410);
            assert!(!replay.text().await.unwrap().contains("Credentials saved"));
            assert_eq!(signin.done.await.unwrap().is_ok(), !fail);
            upstream.shutdown().await;
        }
    }

    #[tokio::test]
    async fn callback_refusal_and_failed_exchange_never_claim_success() {
        for refused in [true, false] {
            let (upstream, port, _dir) = gateway_on_loopback().await;
            let store = Arc::new(MemoryStore::default());
            let mut config = remote(
                "failure",
                format!("http://127.0.0.1:{port}/mcp"),
                HttpAuth::Oauth,
                BTreeMap::new(),
            );
            config.oauth_ref = Some(uuid::Uuid::new_v4().to_string());
            let signin = begin_sign_in(&config, store.clone()).await.unwrap();
            let params: HashMap<_, _> = reqwest::Url::parse(&signin.url)
                .unwrap()
                .query_pairs()
                .into_owned()
                .collect();
            let query = if refused {
                "error=access_denied&error_description=secret-text"
            } else {
                "code=secret-invalid-code"
            };
            let response = reqwest::get(format!(
                "{}?{query}&state={}",
                params["redirect_uri"], params["state"]
            ))
            .await
            .unwrap();
            assert_eq!(response.status(), if refused { 403 } else { 502 });
            let html = response.text().await.unwrap();
            assert!(html.contains(if refused {
                "Sign-in refused"
            } else {
                "Could not complete sign-in"
            }));
            assert!(!html.contains("secret-"));
            assert!(!html.contains("Credentials saved"));
            assert!(signin.done.await.unwrap().is_err());
            assert!(Tokens::new(store, config.oauth_ref)
                .unwrap()
                .load()
                .await
                .unwrap()
                .and_then(|credentials| credentials.token_response)
                .is_none());
            upstream.shutdown().await;
        }
    }

    #[tokio::test]
    async fn callback_wait_is_bounded_without_a_browser() {
        let (upstream, port, _dir) = gateway_on_loopback().await;
        let mut state = RmcpOAuthState::new(
            format!("http://127.0.0.1:{port}/mcp").as_str(),
            Some(http_client().unwrap()),
        )
        .await
        .unwrap();
        let (_tx, mut rx) = mpsc::channel(1);
        let result = receive_callback(
            &mut state,
            &mut rx,
            "http://localhost/callback",
            Duration::from_millis(5),
            HANDSHAKE_TIMEOUT,
        )
        .await;
        assert!(result.unwrap_err().to_string().contains("timed out"));
        upstream.shutdown().await;
    }

    #[tokio::test]
    async fn callback_exchange_timeout_reports_an_unconfirmed_result() {
        let (upstream, port, _dir) = gateway_on_loopback().await;
        let store = Arc::new(MemoryStore::default());
        let mut state = RmcpOAuthState::new(
            format!("http://127.0.0.1:{port}/mcp").as_str(),
            Some(http_client().unwrap()),
        )
        .await
        .unwrap();
        if let RmcpOAuthState::Unauthorized(manager) = &mut state {
            manager.set_credential_store(
                Tokens::new(store.clone(), Some(uuid::Uuid::new_v4().to_string())).unwrap(),
            );
        }
        state
            .start_authorization(
                AuthorizationRequest::new("http://localhost/callback")
                    .with_client_name(CLIENT_NAME),
            )
            .await
            .unwrap();
        let auth_url = reqwest::Url::parse(&state.get_authorization_url().await.unwrap()).unwrap();
        let authorization = tokio::spawn(async move {
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap()
                .get(auth_url)
                .send()
                .await
                .unwrap()
        });
        let pending = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(pending) = upstream.pending_signins().into_iter().next() {
                    break pending;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        upstream
            .decide_agent(&pending.agent_id, true)
            .await
            .unwrap();
        let authorized = authorization.await.unwrap();
        assert_eq!(authorized.status(), StatusCode::SEE_OTHER);
        let callback_url =
            reqwest::Url::parse(authorized.headers()["location"].to_str().unwrap()).unwrap();
        // Holding the upstream config makes the token exchange wait without changing
        // an account, using the real HTTP/token path and a very short test deadline.
        let blocked = upstream.config.write().await;
        let (tx, mut rx) = mpsc::channel(1);
        let (reply, result) = oneshot::channel();
        tx.send(CallbackRequest {
            query: callback_url.query().unwrap().to_string(),
            refused: false,
            reply,
        })
        .await
        .unwrap();
        let outcome = receive_callback(
            &mut state,
            &mut rx,
            "http://localhost/callback",
            SIGN_IN_TIMEOUT,
            Duration::from_millis(10),
        )
        .await;
        assert!(outcome.unwrap_err().to_string().contains("timed out"));
        assert_eq!(result.await.unwrap(), CallbackOutcome::TimedOut);
        drop(blocked);
        upstream.shutdown().await;
    }

    /// The whole OAuth path against Prism's own authorization server: discovery from the
    /// 401 challenge, dynamic registration, the browser hop with consent in the upstream
    /// panel, the loopback callback, the token exchange, and a live session afterwards.
    #[tokio::test]
    async fn oauth_sign_in_against_another_prism() {
        let (upstream, upstream_port, _up_dir) = gateway_on_loopback().await;
        let (gateway, _port, _dir) = gateway_on_loopback().await;

        let added = gateway
            .add_server(remote(
                "upstream",
                format!("http://127.0.0.1:{upstream_port}/mcp"),
                HttpAuth::Oauth,
                BTreeMap::new(),
            ))
            .await
            .unwrap();
        assert!(added.oauth_ref.is_some());
        wait_for(&gateway, &added.id, "sign-in required", |s| {
            matches!(s, BackendStatus::SignInRequired)
        })
        .await;

        let auth_url = gateway.sign_in_server(&added.id).await.unwrap();
        assert!(
            auth_url.starts_with(&format!("http://127.0.0.1:{upstream_port}/authorize")),
            "{auth_url}"
        );

        // A real browser gets helpful HTML immediately and polls only its own status.
        let browser = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let page = browser
            .get(&auth_url)
            .header("Accept", "text/html")
            .send()
            .await
            .unwrap();
        assert_eq!(page.status(), 200);
        let html = page.text().await.unwrap();
        let req = html
            .split("const request = \"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        let status_url = format!("http://127.0.0.1:{upstream_port}/authorize/status?req={req}");
        let finish_url = format!("http://127.0.0.1:{upstream_port}/authorize/finish?req={req}");
        let mut pending = None;
        for _ in 0..100 {
            pending = upstream.agents().await.into_iter().find(|a| {
                a.agent.name == CLIENT_NAME && a.agent.status == crate::config::AgentStatus::Pending
            });
            if pending.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let pending = pending.expect("upstream saw Prism asking to connect");
        upstream
            .decide_agent(&pending.agent.id, true)
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let status: serde_json::Value = browser
                    .get(&status_url)
                    .header("X-Prism-OAuth", "1")
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                if status["status"] == "ready" {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let redirect = browser.get(finish_url).send().await.unwrap();
        assert_eq!(redirect.status(), 303);
        let location = redirect.headers()["location"].to_str().unwrap().to_string();
        assert!(location.starts_with("http://127.0.0.1:"), "{location}");
        assert!(location.contains("/callback?"), "{location}");
        let landed = browser.get(&location).send().await.unwrap();
        assert_eq!(landed.status(), 200);
        let landed = landed.text().await.unwrap();
        assert!(landed.contains("Signed in"));
        assert!(landed.contains("data-state=\"ok\""));
        assert!(landed.contains("<b>upstream</b>"), "{landed}");

        let status = wait_for(&gateway, &added.id, "running", |s| {
            matches!(s, BackendStatus::Running { .. })
        })
        .await;
        assert_eq!(status, BackendStatus::Running { tool_count: 0 });

        // Signing out forgets the tokens; the server asks again.
        gateway.sign_out_server(&added.id).await.unwrap();
        wait_for(&gateway, &added.id, "sign-in required again", |s| {
            matches!(s, BackendStatus::SignInRequired)
        })
        .await;
    }
}
