use serde::{de::Visitor, Deserialize, Deserializer};

#[derive(Debug, Deserialize, Clone)]
pub struct AdSettings {
    pub server: String,
    pub port: LdapPort,
    pub ssl: bool,
    pub search_base: String,
    #[serde(deserialize_with = "ldap_scope_deserializer")]
    pub scope: ldap3::Scope,
}

pub type LdapPort = usize;

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
