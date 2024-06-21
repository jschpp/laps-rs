use chrono::{DateTime, Utc};
use ldap3::{Ldap, LdapConn, LdapError, Scope, SearchEntry, SearchResult};
use std::str::FromStr;

use crate::{
    decryption::{DecryptLapsPassword, EncryptedPasswordAttribute},
    error::LapsError,
    helpers::filetime_to_datetime,
};

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

#[derive(serde::Deserialize, Debug)]
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

/// This will try to retrieve the LAPS password information from Active Directory.
///
/// This is a lower level function which expects a already bound and open [`LdapConn`] and will panic otherwise.
///
/// It will look for the following Attributes:
/// ```plain
/// msLAPS-Password
/// msLAPS-EncryptedPassword
/// msLAPS-PasswordExpirationTime
/// ```
///
/// # Panics
/// Will panic if con is closed
pub fn lookup_laps_info(
    computer_name: &str,
    con: &mut LdapConn,
    search_base: &str,
    scope: Scope,
) -> Result<SearchResult, LdapError> {
    assert!(!con.is_closed());
    // perform search
    let filter = format!("(&(objectClass=computer)(Name={computer_name}))");
    con.search(
        search_base,
        scope,
        &filter,
        vec![
            "msLAPS-Password",
            "msLAPS-EncryptedPassword",
            "msLAPS-PasswordExpirationTime",
        ],
    )
}

/// See [`lookup_laps_info`]
///
/// This is the async version
pub async fn lookup_laps_info_async(
    computer_name: &str,
    con: &mut Ldap,
    search_base: &str,
    scope: Scope,
) -> Result<SearchResult, LdapError> {
    assert!(!con.is_closed());
    let filter = format!("(&(objectClass=computer)(Name={computer_name}))");
    con.search(
        search_base,
        scope,
        &filter,
        vec![
            "msLAPS-Password",
            "msLAPS-EncryptedPassword",
            "msLAPS-PasswordExpirationTime",
        ],
    )
    .await
}

/// This will process the result of [`lookup_laps_info()`] or [`lookup_laps_info_async()`]
///
/// In the case of a computer having both `msLAPS-Password` and `msLAPS-EncryptedPassword`
/// it will return the password with the longer expiration time preferring `msLAPS-EncryptedPassword`.
///
/// It will use your current users credential to decrypt the information if it was encrypted.
/// The decryption uses [`NCryptUnprotectSecret()`](windows_sys::Win32::Security::Cryptography::NCryptUnprotectSecret) in the background
///
/// # Panics
/// This will panic in case that Microsoft changes the internal representation of the two password fields from valid JSON to anything else
pub fn process_ldap_search_result(
    search_result: Result<SearchResult, LdapError>,
) -> Result<MsLapsPassword, LapsError> {
    let (rs, _res) = search_result?.success()?;

    // we expect exactly one result else we will err out
    if rs.len() != 1 {
        return Err(LapsError::NotFound("Computer".into()));
    }

    let entry = SearchEntry::construct(
        rs.first()
            .expect("at least one Search result exists")
            .to_owned(),
    );

    // At this point it could be the case that a single computer has an encrypted and an unencrypted password.
    // we need to take the one with the longer ExpirationTime
    let ms_laps_password: Option<MsLapsPassword> = if entry.attrs.contains_key("msLAPS-Password") {
        let encoded_pass_info = entry.attrs["msLAPS-Password"]
            .first()
            .expect("msLAPS-Password attribute should contain at least one value");
        Some(
            serde_json::from_str::<MsLapsPassword>(encoded_pass_info).map_err(|_| {
                LapsError::ConversionError("msLAPS-Password is not a valid JSON String".into())
            })?,
        )
    } else {
        None
    };

    let ms_laps_encrypted_password: Option<MsLapsPassword> =
        if entry.bin_attrs.contains_key("msLAPS-EncryptedPassword") {
            let blob = entry.bin_attrs["msLAPS-EncryptedPassword"]
                .first()
                .expect("msLAPS-EncryptedPassword attribute should contain at least one value")
                .as_slice();
            let encrypted_password_info = EncryptedPasswordAttribute::try_from(blob)?;
            Some(EncryptedPasswordAttribute::decrypt(
                &encrypted_password_info,
            )?)
        } else {
            None
        };

    let result = [ms_laps_password, ms_laps_encrypted_password]
        .into_iter()
        .flatten()
        .max_by_key(|pass| pass.time);
    let Some(result) = result else {
        return Err(LapsError::NotFound("Laps password".into()));
    };

    Ok(result)
}
