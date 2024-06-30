# laps-rs

Library for the retrieval of [LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview) passwords

Central for that are the two structs [`AdConnection`] and [`AdConnectionAsync`] which hold a connection to the Active Directory and implement `try_search()`

## Usage

In `Cargo.toml`:

```toml
[dependencies.laps_rs]
version = "0.1.0"
```

## Example

Both examples perform a search for `"computername"`

### Synchronous search

```rust
use laps_rs::{AdSettings, AdConnection, LdapProtocol, Scope};

let settings = AdSettings::new(
   "dc.test.internal",
   636,
   LdapProtocol::Secure,
   "OU=path,OU=to,OU=computers,DC=test,DC=internal",
   Scope::Subtree,
);
let mut con: AdConnection = settings.connect()?;
let password = con.try_search("computername", &settings)?;
println!("{password:?}");
```

See also [`AdConnection::try_search()`]

### Asynchronous search

```rust
use laps_rs::{AdSettings, AdConnectionAsync, LdapProtocol, Scope};

let settings = AdSettings::new(
   "dc.test.internal",
   636,
   LdapProtocol::Secure,
   "OU=path,OU=to,OU=computers,DC=test,DC=internal",
   Scope::Subtree,
);
let mut con: AdConnectionAsync = settings
   .connect_async()
   .await?;
let password = con
   .try_search("computername", &settings)
   .await?;
println!("{password:?}");
```

See also [`AdConnectionAsync::try_search()`]

## Quirks

Since it can be the case that both encrypted and unencrypted LAPS data exists for the same
computer [`process_ldap_search_result()`] will prefer the encrypted information in case of
an identical password expiration.

In any other case the password with the longer expiration will be returned.

## Current Version

0.1.0
