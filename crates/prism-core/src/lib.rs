//! Headless Prism MCP gateway: policy, stdio backends, approvals, and audit.

pub mod activity;
mod approval;
mod audit;
mod backend;
mod config;
mod credentials;
mod error;
mod events;
mod gateway;
mod http_security;
mod listener;
pub mod native;
pub mod mcp_traffic;
mod oauth;
pub mod policy;
mod remote;
mod shell_path;
mod storage;

pub use mcp_traffic::{McpTrafficLogger, McpTransaction, ServerLoggingTransport};

pub use approval::{
    ApprovalRegistry, Decision, DecisionScope, DecisionTarget, DecisionVerdict, HoldOutcome,
    HoldReason, Offer, OfferKind, PendingCall, DEFAULT_HOLD_TIMEOUT, TIMEOUT_MESSAGE,
};
pub use audit::{
    AuditEntry, AuditExport, AuditLog, AuditPage, AuditQuery, AuditSource, AuditVerdict,
    AuditWindow, NativeDetail,
};
pub use backend::{BackendStatus, ServerView};
pub use config::{
    AgentConfig, AgentStatus, Attention, HttpAuth, ListenAddress, PanelAnchor, Posture,
    PrismConfig, Rule, RuleDecision, RuleScope, ServerConfig, TimeoutBehavior,
};
pub use config::{OAuthClient, TokenKind, TokenRecord};
pub use error::{Error, Result};
pub use events::{EventReceiver, GatewayEvent};
pub use gateway::{AgentView, ConnectSnippet, Gateway, GatewayStatus, NewRule, Settings, ToolInfo};
pub use listener::{ListenerState, PortHolder};
pub use native::{NativeStatus, ReasonCount, ShadowRule};
pub use oauth::{
    hash_token, pkce_matches, redirect_uri_allowed, AuthenticatedAgent, AuthorizeOutcome,
    AuthorizeParams, ManualToken, OAuthError, PendingSignIn, RegisterRequest, TokenRequest,
    TokenResponse, TokenView,
};
pub use policy::{evaluate, glob_match, Decider, Evaluation, ToolAnnotations, Verdict};
pub use shell_path::adopt_login_shell_path;
pub use storage::write_client_config;
