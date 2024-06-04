use chrono::{DateTime, Utc};
use ldap3::{LdapConn, SearchEntry};
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer,
};
use std::str::FromStr;

use crate::{
    decryption::decrypt_password_blob_ng, error::LapsError, helpers::filetime_to_datetime,
    settings::AdSettings,
};

#[derive(Deserialize, Debug, Clone, Copy)]
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
    type Err = ConversionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ldap" => Ok(LdapProtocol::Unsecure),
            "ldaps" => Ok(LdapProtocol::Secure),
            _ => Err(ConversionError::Other(format!(
                "unknown LdapProtocolType: {s}"
            ))),
        }
    }
}

#[derive(Deserialize, Default, Debug)]
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
    D: Deserializer<'de>,
{
    struct FieldVisitor;

    impl<'de> Visitor<'de> for FieldVisitor {
        type Value = DateTime<Utc>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("test?")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            let num: i64 = i64::from_str_radix(v, 16)
                .map_err(|_| de::Error::custom("error converting datetime"))?;
            Ok(filetime_to_datetime(num))
        }
    }

    deserializer.deserialize_string(FieldVisitor)
}

/// This will try to retrieve the LAPS password information from Active Directory.
///
/// It will look for the following Attributes:
/// ```plain
/// msLAPS-Password
/// msLAPS-EncryptedPassword
/// msLAPS-PasswordExpirationTime
/// ```
/// In the case of a computer having both `msLAPS-Password` and `msLAPS-PasswordExpirationTime`
/// it will return the password with the longer expiration time.
///
/// It will use your current users credential to decrypt the information if it was encrypted.
/// The decryption uses [`NCryptUnprotectSecret()`](windows_sys::Win32::Security::Cryptography::NCryptUnprotectSecret) in the background
///
/// # Panics
/// This will panic if the password attributes within the AD are not valid JSON
pub fn retrieve_laps_info(
    computer_name: &str,
    con_settings: AdSettings,
) -> Result<MsLapsPassword, LapsError> {
    // construct ldap conncection uri
    let prot = con_settings.protocol.to_string();
    let con_str = format!("{}://{}:{}", prot, con_settings.server, con_settings.port);

    // bind
    let mut ldap: LdapConn =
        LdapConn::new(&con_str).map_err(|e| LapsError::LdapError(e.to_string()))?;
    ldap.sasl_gssapi_bind(&con_settings.server)
        .map_err(|e| LapsError::LdapError(e.to_string()))?;

    // perform search
    let filter = format!("(&(objectClass=computer)(Name={computer_name}))");
    let search_result = ldap.search(
        &con_settings.search_base,
        con_settings.scope,
        &filter,
        vec![
            "msLAPS-Password",
            "msLAPS-EncryptedPassword",
            "msLAPS-PasswordExpirationTime",
        ],
    );

    // handle search result
    let Ok(search_result) = search_result else {
        return Err(LapsError::LdapError(
            search_result
                .expect_err("search_result is not Ok()")
                .to_string(),
        ));
    };

    let search_result = search_result.success();
    let rs = match search_result {
        Ok((rs, _res)) => rs,
        Err(e) => return Err(LapsError::LdapError(e.to_string())),
    };

    if rs.len() != 1 {
        Err(LapsError::LdapError(String::from("Computer not found")))?
    }

    let entry = SearchEntry::construct(rs[0].clone());

    // At this point it could be the case that a single computer has an encrypted and an unencrypted password.
    // we need to take the one with the longer ExpirationTime
    let ms_laps_password = entry.attrs["msLAPS-Password"].first().map(|json_str| {
        serde_json::from_str::<MsLapsPassword>(json_str)
            .expect("msLAPS-Password is a valid JSON String")
    });

    let ms_laps_encrypted_password: Option<MsLapsPassword> =
        if entry.bin_attrs.contains_key("msLAPS-EncryptedPassword") {
            let blob = entry.bin_attrs["msLAPS-EncryptedPassword"]
                .first()
                .expect("at least one entry should exist")
                .to_owned();
            let decrypted_blob = match decrypt_password_blob_ng(&blob) {
                Ok(value) => value,
                Err(e) => return Err(LapsError::DecryptionError(e)),
            };
            Some(
                serde_json::from_str(&decrypted_blob)
                    .expect("The decrypted msLAPS-EncryptedPassword is a valid JSON String"),
            )
        } else {
            None
        };

    let result = [ms_laps_password, ms_laps_encrypted_password]
        .into_iter()
        .flatten()
        .max_by_key(|pass| pass.time);
    let Some(result) = result else {
        return Err(LapsError::Other(String::from("No Laps Password found")));
    };

    ldap.unbind()
        .map_err(|e| LapsError::LdapError(e.to_string()))?;

    Ok(result)
}
