use serde::{de::Visitor, Deserialize, Deserializer};

use crate::ldap::LdapProtocol;

#[derive(Debug, Deserialize, Clone)]
/// Settings needed by [`ldap3`](mod@ldap3) to successfully connect and search the Active Directory
pub struct AdSettings {
    /// Server FQDN
    pub server: String,
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
            server: server.into(),
            port,
            protocol,
            search_base: search_base.into(),
            scope,
        }
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
