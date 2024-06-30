use std::str::FromStr;

use chrono::{DateTime, Utc};
use ldap3::{tokio, Ldap, LdapConn, LdapConnAsync};
use serde::{de::Visitor, Deserialize, Deserializer};
use tracing::warn;

use crate::{
    helpers::filetime_to_datetime, lookup_laps_info, lookup_laps_info_async,
    process_ldap_search_result, LapsError,
};

/// Connection to the Active Directory
///
/// will be constructed by [`AdSettings::connect()`]
///
/// for searching see [`AdConnection::try_search()`]
#[derive(Debug)]
pub struct AdConnection {
    pub(crate) ldap: LdapConn,
}

/// Async connection to the Active Directory
///
/// will be constructed by [`AdSettings::connect_async()`]
///
/// for searching see [`AdConnectionAsync::try_search()`]
#[derive(Clone, Debug)]
pub struct AdConnectionAsync {
    pub(crate) ldap: Ldap,
}

impl AdConnection {
    /// Will perform a search for the LAPS credentials for given computer by computer name.
    ///
    /// This search calls [`lookup_laps_info()`] in the background and will then process the result with
    /// [`process_ldap_search_result()`]
    pub fn try_search(
        &mut self,
        computer_name: &str,
        ad_settings: &AdSettings,
    ) -> Result<MsLapsPassword, LapsError> {
        let rs = lookup_laps_info(
            computer_name,
            self,
            &ad_settings.search_base,
            ad_settings.scope,
        );
        process_ldap_search_result(rs)
    }
}

impl AdConnectionAsync {
    /// Will perform a search for the LAPS credentials for given computer by computer name.
    ///
    /// This search calls [`lookup_laps_info_async()`] in the background and will then process the result with
    /// [`process_ldap_search_result()`]
    pub async fn try_search(
        &mut self,
        computer_name: &str,
        ad_settings: &AdSettings,
    ) -> Result<MsLapsPassword, LapsError> {
        let rs = lookup_laps_info_async(
            computer_name,
            self,
            &ad_settings.search_base,
            ad_settings.scope,
        )
        .await;
        process_ldap_search_result(rs)
    }
}

#[derive(Debug, Deserialize, Clone)]
/// Settings needed by [`ldap3`](mod@ldap3) to successfully connect and search the Active Directory
pub struct AdSettings {
    /// Server FQDN
    pub server_fqdn: String,
    /// LDAP Port (in most cases either 389 or 636)
    pub port: LdapPort,
    /// Will use the following protocols for the ldap connection
    ///
    /// * [`LdapProtocol::Secure`] => `ldaps://`
    /// * [`LdapProtocol::Unsecure`] => `ldap://`
    pub protocol: LdapProtocol,
    /// LDAP search base where to search for the computer
    pub search_base: String,
    /// LDAP Search Scope
    #[serde(deserialize_with = "ldap_scope_deserializer")]
    pub scope: ldap3::Scope,
}

pub type LdapPort = usize;

impl AdSettings {
    pub fn new(
        server: impl Into<String>,
        port: LdapPort,
        protocol: LdapProtocol,
        search_base: impl Into<String>,
        scope: ldap3::Scope,
    ) -> Self {
        Self {
            server_fqdn: server.into(),
            port,
            protocol,
            search_base: search_base.into(),
            scope,
        }
    }

    /// This will construct a connection uri from the settings given
    pub fn get_connection_uri(&self) -> String {
        let protocol: &str = self.protocol.into();
        format!("{}://{}:{}", protocol, self.server_fqdn, self.port)
    }

    /// Opens a new [`ldap3::LdapConn`] connection with the given settings.
    ///
    /// This connection is synchronous will be `sasl_gssapi` bound with the credentials of the user running the process.
    ///
    /// Those same credentials will be used to decrypt the LAPS password information.
    /// # Error
    ///
    /// Will return a [`LapsError`] if the connection fails
    pub fn connect(&self) -> Result<AdConnection, LapsError> {
        let con_str = self.get_connection_uri();
        let mut con = LdapConn::new(&con_str)?;
        con.sasl_gssapi_bind(&self.server_fqdn)?;
        Ok(AdConnection { ldap: con })
    }

    /// Opens a new [`ldap3::Ldap`] connection with the given settings.
    ///
    /// This connection is asynchronous will be `sasl_gssapi` bound with the credentials of the user running the process.
    ///
    /// Those same credentials will be used to decrypt the LAPS password information.
    ///
    /// # Error
    ///
    /// Will return a [`LapsError`] if the connection fails
    pub async fn connect_async(&self) -> Result<AdConnectionAsync, LapsError> {
        let (ldap_con, mut ldap) = LdapConnAsync::new(&self.get_connection_uri()).await?;
        tokio::spawn(async move {
            if let Err(e) = ldap_con.drive().await {
                warn!("LDAP connection error: {}", e);
            }
        });
        ldap.sasl_gssapi_bind(&self.server_fqdn).await?;
        Ok(AdConnectionAsync { ldap })
    }
}

fn ldap_scope_deserializer<'de, D>(deserializer: D) -> Result<ldap3::Scope, D::Error>
where
    D: Deserializer<'de>,
{
    struct ScopeVisitor;

    impl<'de> Visitor<'de> for ScopeVisitor {
        type Value = ldap3::Scope;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("one of 'Base', 'OneLevel', or 'Subtree'")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            use ldap3::Scope;
            match v.to_ascii_lowercase().as_str() {
                "base" => Ok(Scope::Base),
                "onelevel" => Ok(Scope::OneLevel),
                "subtree" => Ok(Scope::Subtree),
                _ => Err(serde::de::Error::invalid_type(
                    serde::de::Unexpected::Str(v),
                    &self,
                )),
            }
        }
    }
    deserializer.deserialize_str(ScopeVisitor)
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
/// LAPS Information
pub struct MsLapsPassword {
    /// Username of the administrative user managed by LAPS
    #[serde(rename(deserialize = "n"))]
    pub username: String,
    /// Expiration time of the password.
    ///
    /// Can be in the past in case of a computer being disconnected from the AD for a
    /// longer time
    #[serde(rename(deserialize = "t"), deserialize_with = "filetime_deserializer")]
    pub time: DateTime<Utc>,
    /// The LAPS password
    #[serde(rename(deserialize = "p"))]
    pub password: String,
}

fn filetime_deserializer<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct FieldVisitor;

    impl<'de> serde::de::Visitor<'de> for FieldVisitor {
        type Value = DateTime<Utc>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("test?")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            let num: i64 = i64::from_str_radix(v, 16)
                .map_err(|_| serde::de::Error::custom("error converting datetime"))?;
            Ok(filetime_to_datetime(num))
        }
    }

    deserializer.deserialize_string(FieldVisitor)
}

#[derive(serde::Deserialize, Debug, Clone, Copy)]
pub enum LdapProtocol {
    Secure,
    Unsecure,
}

impl From<LdapProtocol> for &str {
    fn from(value: LdapProtocol) -> Self {
        match value {
            LdapProtocol::Secure => "ldaps",
            LdapProtocol::Unsecure => "ldap",
        }
    }
}

impl FromStr for LdapProtocol {
    type Err = LapsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ldap" => Ok(LdapProtocol::Unsecure),
            "ldaps" => Ok(LdapProtocol::Secure),
            _ => Err(LapsError::ConversionError(format!(
                "unknown LdapProtocol: {s}"
            ))),
        }
    }
}
