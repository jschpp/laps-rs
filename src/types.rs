use std::str::FromStr;

use chrono::{DateTime, Utc};
use ldap3::{tokio, Ldap, LdapConn, LdapConnAsync};
use serde::{de::Visitor, Deserialize, Deserializer};
use tracing::warn;

use crate::{
    helpers::filetime_to_datetime, lookup_laps_info, lookup_laps_info_async,
    process_ldap_search_result, LapsError,
};

#[derive(Debug)]
pub struct AdConnection {
    pub(crate) ldap: LdapConn,
}

#[derive(Clone, Debug)]
pub struct AdConnectionAsync {
    pub(crate) ldap: Ldap,
}

impl AdConnection {
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
    /// if this is true use the `ldaps:\\` protocol
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

    pub fn connect(&self) -> Result<AdConnection, LapsError> {
        let con_str = self.get_connection_uri();
        let mut con = LdapConn::new(&con_str)?;
        con.sasl_gssapi_bind(&self.server_fqdn)?;
        Ok(AdConnection { ldap: con })
    }

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
    #[serde(rename(deserialize = "n"))]
    pub username: String,
    #[serde(rename(deserialize = "t"), deserialize_with = "filetime_deserializer")]
    pub time: DateTime<Utc>,
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
