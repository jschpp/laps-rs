#![cfg(windows)]

mod decryption;
mod error;
mod helpers;
mod ldap;
mod types;

pub use error::*;
pub use ldap::{lookup_laps_info, lookup_laps_info_async, process_ldap_search_result};
pub use ldap3::Scope;
pub use types::*;

pub fn get_laps_info(
    computer_name: &str,
    settings: AdSettings,
) -> Result<MsLapsPassword, LapsError> {
    // construct ldap connection uri
    let con_str = settings.get_connection_uri();

    // bind
    let mut con: ldap3::LdapConn = ldap3::LdapConn::new(&con_str)?;
    con.sasl_gssapi_bind(&settings.server)?;

    // lookup
    let result = lookup_laps_info(
        computer_name,
        &mut con,
        &settings.search_base,
        settings.scope,
    );

    // unbind
    con.unbind()?;

    // process and decrypt (if necessary)
    process_ldap_search_result(result)
}
