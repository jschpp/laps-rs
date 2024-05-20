use std::cmp::Ordering;

use chrono::{DateTime, Utc};
use ldap3::{LdapConn, SearchEntry};
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer,
};

use crate::{
    decryption::decrypt_password_blob_ng,
    error::{ConversionError, LapsError},
    helpers::filetime_to_datetime,
    settings::AdSettings,
};

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

impl PartialOrd for MsLapsPassword {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.time.partial_cmp(&other.time)
    }
}

impl PartialEq for MsLapsPassword {
    fn eq(&self, other: &Self) -> bool {
        self.username == other.username && self.time == other.time
    }
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
pub fn retrieve_laps_info(
    computer_name: &str,
    con_settings: AdSettings,
) -> Result<MsLapsPassword, LapsError> {
    // construct ldap conncection uri
    let prot = if con_settings.ssl { "ldaps" } else { "ldap" };
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

    let Ok((rs, _res)) = search_result.success() else {
        return Err(LapsError::LdapError(search_result.1.to_string()));
    };

    if rs.len() != 1 {
        Err(LapsError::LdapError(String::from("Computer not found")))?
    }

    let entry = SearchEntry::construct(rs[0].clone());
    let mut result: MsLapsPassword = MsLapsPassword::default();

    // At this point it could be the case that a single computer has an encrypted and an unencrypted password.
    // we need to take the one with the longer ExpirationTime

    let ms_laps_password: Option<MsLapsPassword> = if entry.attrs.contains_key("msLAPS-Password") {
        let blob = entry.attrs["msLAPS-Password"]
            .first()
            .expect("at least one entry should exist");
        let Ok(ms_laps_password) = serde_json::from_str(blob) else {
            return Err(LapsError::ConversionError(ConversionError::Other(
                String::from("error parsing json"),
            )));
        };
        ms_laps_password
    } else {
        None
    };

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
            let Ok(ms_laps_encrypted_password) = serde_json::from_str(&decrypted_blob) else {
                return Err(LapsError::ConversionError(ConversionError::Other(
                    String::from("error parsing json"),
                )));
            };
            Some(ms_laps_encrypted_password)
        } else {
            None
        };

    if ms_laps_encrypted_password.is_some() && ms_laps_password.is_some() {
        // in this case we need to check which password has the higher expiration time
        let ms_laps_encrypted_password = ms_laps_encrypted_password.expect("is some");
        let ms_laps_password = ms_laps_password.expect("is some");

        // this will prefer the ms_laps_encrypted_password in case of equality
        if ms_laps_password.time > ms_laps_encrypted_password.time {
            result = ms_laps_password;
        } else {
            result = ms_laps_encrypted_password;
        }
    } else if ms_laps_encrypted_password.is_some() {
        result = ms_laps_encrypted_password.expect("is some")
    } else if ms_laps_password.is_some() {
        result = ms_laps_password.expect("is some")
    } else {
        return Err(LapsError::Other(String::from("No Laps Password found")));
    }

    ldap.unbind()
        .map_err(|e| LapsError::LdapError(e.to_string()))?;

    Ok(result)
}
