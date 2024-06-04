mod decryption;
mod error;
mod helpers;
mod ldap;
mod settings;

pub use error::*;
pub use ldap::{
    lookup_laps_info, lookup_laps_info_async, process_ldap_search_result, LdapProtocol,
    MsLapsPassword,
};
pub use ldap3::Scope;
pub use settings::*;

pub fn get_laps_info(
    computer_name: &str,
    settings: AdSettings,
) -> Result<MsLapsPassword, LapsError> {
    // construct ldap connection uri
    let prot: &str = settings.protocol.into();
    let con_str = format!("{}://{}:{}", prot, settings.server, settings.port);

    // bind
    let mut con: ldap3::LdapConn = ldap3::LdapConn::new(&con_str)?;
    con.sasl_gssapi_bind(&settings.server)?;
    let result = lookup_laps_info(
        computer_name,
        &mut con,
        &settings.search_base,
        settings.scope,
    );
    con.unbind()?;
    process_ldap_search_result(result)
}
