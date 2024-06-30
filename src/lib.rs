#![cfg(windows)]

//! # LAPS Password retrieval
//!
//! This crate enables the retrieval of a [LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview) passwords.
//!
//! Central for that are the two structs [`AdConnection`] and [`AdConnectionAsync`] which hold a connection to the Active Directory and implement `try_search()`
//!
//! ## Example
//!
//! Both examples perform a search for `"computername"`
//!
//! ### Synchronous search
//! ```rust,no_run
//! use laps_rs::{AdSettings, AdConnection, LdapProtocol, Scope};
//!
//!let settings = AdSettings::new(
//!    "dc.test.internal",
//!    636,
//!    LdapProtocol::Secure,
//!    "OU=path,OU=to,OU=computers,DC=test,DC=internal",
//!    Scope::Subtree,
//!);
//!let mut con: AdConnection = settings.connect().expect("working domain controller");
//!let password = con
//!    .try_search("computername", &settings)
//!    .expect("computer exists and has a LAPS Password");
//!println!("{password:?}");
//! ```
//!
//! See also [`AdConnection::try_search()`]
//!
//! ### Asynchronous search
// ignore here because correctly importing tokio in doc comments annoys me
// FIXME: correctly import tokio here to change this to no_run
//! ```rust,ignore
//! use laps_rs::{AdSettings, AdConnectionAsync, LdapProtocol, Scope};
//!
//! #[tokio::main]
//! async fn main() {
//!     let settings = AdSettings::new(
//!         "dc.test.internal",
//!         636,
//!         LdapProtocol::Secure,
//!         "OU=path,OU=to,OU=computers,DC=test,DC=internal",
//!         Scope::Subtree,
//!     );
//!     let mut con: AdConnectionAsync = settings
//!         .connect_async()
//!         .await
//!         .expect("working domain controller");
//!     let password = con
//!         .try_search("computername", &settings)
//!         .await
//!         .expect("computer exists and has a LAPS Password");
//!     println!("{password:?}");
//! }
//! ```
//!
//! See also [`AdConnectionAsync::try_search()`]
//!
//! ## Quirks
//!
//! Since it can be the case that both encrypted and unencrypted LAPS data exists for the same
//! computer [`process_ldap_search_result()`] will prefer the encrypted information in case of
//! an identical password expiration.
//!
//! In any other case the password with the longer expiration will be returned.

mod decryption;
mod error;
mod helpers;
mod ldap;
mod types;

pub use error::*;
pub use ldap::{lookup_laps_info, lookup_laps_info_async, process_ldap_search_result};
pub use ldap3::Scope;
pub use types::*;
