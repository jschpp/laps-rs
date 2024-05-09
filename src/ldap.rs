use chrono::{DateTime, Utc};
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer,
};

use crate::helpers::filetime_to_datetime;

#[derive(Deserialize, Default, Debug)]
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
