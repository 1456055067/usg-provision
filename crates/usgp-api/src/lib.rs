//! usgp-api: the operator API of the control plane (plan M2 WU-6).
//!
//! HTTP/1.1 over mutual TLS (`usgp_crypto::tls::ServerTls`, FIPS
//! provider). Every request is authenticated by its client certificate's
//! SHA-256 bound to exactly one enrolled operator ([`authn`]), authorised
//! against the route's permission ([`rbac`], [`routes`]), and audited
//! (who, what, when, where, source, outcome) in the same transaction as
//! any change it makes ([`context`]); if the record cannot be written the
//! action is refused (decision 0015 item 1).
//!
//! Content (Windows image files and preinstall environments) is uploaded
//! in one streamed body into a content-addressed store ([`store`]),
//! checked in the background ([`checker`]), made read-only and given a
//! signed content manifest when Ready, and verified chunk by chunk on
//! every use (`handlers::content`). Editions are declared by the
//! operator and cross-checked with documented file facts (decision 0013).
//! Packages pair one Ready, in-scope edition with one Ready x64 PE and get
//! a signed package manifest when Ready ([`package_status`]).
//!
//! Wiring for `usgp-server` (WU-7):
//!
//! ```text
//! let keys = ContentKeys::new(content_signing_key, trusted_content_pubs)?;
//! let api = Api::builder(store, config, chain, keys)
//!     .checkpointer(checkpointer)
//!     .build()?;
//! api.recover().await?;                      // before serving
//! let tls = Arc::new(TlsAcceptorHandle::new(server_tls));
//! serve(api.clone(), listener, tls.clone(), shutdown).await?;
//! api.checkpoint(true).await;                // clean shutdown
//! ```

// Parses untrusted input (request heads, JSON, paths, stored rows):
// indexing and slicing that can panic are denied (CLAUDE.md, Engineering
// Rules).
#![deny(clippy::indexing_slicing)]

pub mod authn;
pub mod body;
pub mod checker;
pub mod context;
pub mod error;
mod handlers;
pub mod idle;
pub mod limits;
pub mod manifest;
pub mod package_status;
pub mod rbac;
pub mod router;
pub mod routes;
pub mod server;
pub mod store;

pub use checker::{CheckReport, ContentChecker, RecoveryReport, WimChecker};
pub use context::{Api, ApiBuilder, COMPONENT, RequestCtx};
pub use error::{ApiError, ApiInitError};
pub use handlers::content_view_etag;
pub use limits::{ApiConfig, ApiLimits, ConfigError, ContentConfig};
pub use manifest::ContentKeys;
pub use rbac::Permission;
pub use routes::{ROUTES, RouteId, RouteSpec};
pub use server::{TlsAcceptorHandle, serve};
