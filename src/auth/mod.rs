//! Generic authenticated transport and session protocol.
//!
//! This module owns token/session handling, `/api/sdk/info` and heartbeat
//! requests, remote configuration, HTTPS/TLS transport, and cryptographic
//! framing. Hosts provide endpoint and certificate material through the
//! configuration types; no game-specific offset parsing lives here.

mod client;
mod config;
mod crypto;
mod heartbeat;
mod manager;
mod response;
mod transport;

pub use client::{AuthClient, AuthClientError, AuthConfig, Clock, CryptoRandom, SystemClock};
pub use config::{
    Config, ConfigError, ConfigValue, RemoteConfigClient, RemoteConfigData, RemoteConfigEnvelope,
    RemoteConfigError, RemoteConfigStore, RemoteConfigWriteback, RemoteConfigWritebackSink,
    ROOT_SECTION,
};
pub use crypto::{AuthCrypto, AuthCryptoError};
pub use heartbeat::{HeartbeatAuthorization, HeartbeatMonitor, HeartbeatPermit, HeartbeatSource};
pub use manager::AuthManagerBoundary;
pub use response::{AuthEnvelope, AuthEnvelopeError, AuthResponse};
pub use transport::{
    AuthHttpResponse, AuthMethod, AuthRequest, AuthTransport, AuthTransportError, RustlsTransport,
    RustlsTransportConfig,
};

pub use crate::error::AuthError;
