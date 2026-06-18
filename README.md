# libnss-rs

Rust bindings for creating libnss (Name Service Switch) modules.

Currently supports the following databases:
- **passwd** — user account information
- **shadow** — password / shadow data
- **group** — group membership
- **host** — hostname resolution (IPv4 & IPv6)
- **initgroups** — supplementary group initialization for sessions

## Architecture

```
Application (login, su, etc.)
    │
    ▼
glibc NSS dispatcher  (/etc/nsswitch.conf)
    │  resolves "passwd: example files"
    ▼
libnss_<name>.so.2   (C ABI, exported symbols)
    │
    ▼
Rust trait implementation
    │  your data source
    ▼
NssStatus (Success / NotFound / TryAgain / Unavail)
```

## Getting started

### 1. Create a new library

```bash
cargo new nss_example --lib
```

### 2. Change library type to `cdylib` in your `Cargo.toml`

```toml
[lib]
name = "nss_example"
crate-type = ["cdylib"]
```

> **Note:** The crate name itself is not important. The **library name** must follow the `nss_xxx` pattern so glibc can find it (e.g., `libnss_example.so.2`).

### 3. Add dependencies to your `Cargo.toml`

```toml
[dependencies]
libnss = "0.9.0"
libc = "0.2"
```

### 4. Pick a database and implement it

Each database follows the same three-step pattern:
1. Define a struct for your data.
2. Call a macro to generate all C-exported functions.
3. Implement the database's trait.

---

## Database: passwd

Provides user account lookups (equivalent to `/etc/passwd`).

### Struct

```rust
pub struct Passwd {
    pub name: String,   // username
    pub passwd: String, // password (or "x" for shadowed)
    pub uid: u32,       // user ID
    pub gid: u32,       // primary group ID
    pub gecos: String,  // GECOS / comment field (full name, room number, etc.)
    pub dir: String,    // home directory
    pub shell: String,  // login shell
}
```

### Trait

```rust
pub trait PasswdHooks {
    // Fetch all user entries.
    fn get_all_entries() -> Response<Vec<Passwd>>;

    // Look up a single user by UID.
    fn get_entry_by_uid(uid: libc::uid_t) -> Response<Passwd>;

    // Look up a single user by username.
    fn get_entry_by_name(name: String) -> Response<Passwd>;
}
```

### Generated C functions

| Function | Input | Output |
|---|---|---|
| `nss_<name>_setpwent()` | none | `NssStatus` |
| `nss_<name>_endpwent()` | none | `NssStatus` |
| `nss_<name>_getpwent_r(result, buf, buflen, errnop)` | buf/buflen = output buffer | `NssStatus` — next entry |
| `nss_<name>_getpwuid_r(uid, result, buf, buflen, errnop)` | uid = user ID | `NssStatus` — entry or not found |
| `nss_<name>_getpwnam_r(name, result, buf, buflen, errnop)` | name = C string (username) | `NssStatus` — entry or not found |

### Implementation example

```rust
use libnss::passwd::{Passwd, PasswdHooks};
use libnss::{libnss_passwd_hooks, interop::Response};

struct ExamplePasswd;
libnss_passwd_hooks!(example, ExamplePasswd);

impl PasswdHooks for ExamplePasswd {
    fn get_all_entries() -> Response<Vec<Passwd>> {
        Response::Success(vec![
            Passwd {
                name: "root".to_string(),
                passwd: "x".to_string(),
                uid: 0,
                gid: 0,
                gecos: "Root".to_string(),
                dir: "/root".to_string(),
                shell: "/bin/bash".to_string(),
            },
            Passwd {
                name: "test".to_string(),
                passwd: "$6$xyz".to_string(),
                uid: 1000,
                gid: 1000,
                gecos: "Test User".to_string(),
                dir: "/home/test".to_string(),
                shell: "/bin/bash".to_string(),
            },
        ])
    }

    fn get_entry_by_uid(uid: libc::uid_t) -> Response<Passwd> {
        if uid == 1000 {
            Response::Success(Passwd {
                name: "test".to_string(),
                passwd: "$6$xyz".to_string(),
                uid: 1000,
                gid: 1000,
                gecos: "Test User".to_string(),
                dir: "/home/test".to_string(),
                shell: "/bin/bash".to_string(),
            })
        } else {
            Response::NotFound
        }
    }

    fn get_entry_by_name(name: String) -> Response<Passwd> {
        if name == "test" {
            Response::Success(Passwd {
                name: "test".to_string(),
                passwd: "$6$xyz".to_string(),
                uid: 1000,
                gid: 1000,
                gecos: "Test User".to_string(),
                dir: "/home/test".to_string(),
                shell: "/bin/bash".to_string(),
            })
        } else {
            Response::NotFound
        }
    }
}
```

---

## Database: shadow

Provides password/shadow data (equivalent to `/etc/shadow`).
Read by privileged processes to retrieve password hashes and aging information.

### Struct

```rust
pub struct Shadow {
    pub name: String,                  // username
    pub passwd: String,                // encrypted password hash
    pub last_change: isize,            // days since 1970-01-01 of last password change
    pub change_min_days: isize,        // minimum days between password changes
    pub change_max_days: isize,        // maximum days between password changes
    pub change_warn_days: isize,       // days to warn before password expires
    pub change_inactive_days: isize,   // days after expiry until account disabled
    pub expire_date: isize,            // absolute expiry date (days since 1970-01-01)
    pub reserved: usize,               // reserved (unused in NSS)
}
```

### Trait

```rust
pub trait ShadowHooks {
    // Fetch all shadow entries.
    fn get_all_entries() -> Response<Vec<Shadow>>;

    // Look up a single shadow entry by username.
    fn get_entry_by_name(name: String) -> Response<Shadow>;
}
```

### Generated C functions

| Function | Input | Output |
|---|---|---|
| `nss_<name>_setspent()` | none | `NssStatus` |
| `nss_<name>_endspent()` | none | `NssStatus` |
| `nss_<name>_getspent_r(result, buf, buflen, errnop)` | buf/buflen = output buffer | `NssStatus` — next entry |
| `nss_<name>_getspnam_r(name, result, buf, buflen, errnop)` | name = C string (username) | `NssStatus` — entry or not found |

### Implementation example

```rust
use libnss::shadow::{Shadow, ShadowHooks};
use libnss::{libnss_shadow_hooks, interop::Response};

struct ExampleShadow;
libnss_shadow_hooks!(example, ExampleShadow);

impl ShadowHooks for ExampleShadow {
    fn get_all_entries() -> Response<Vec<Shadow>> {
        Response::Success(vec![
            Shadow {
                name: "root".to_string(),
                passwd: "$6$rounds=656000$salt$hash".to_string(),
                last_change: 18660,
                change_min_days: 0,
                change_max_days: 99999,
                change_warn_days: 7,
                change_inactive_days: -1,
                expire_date: -1,
                reserved: 0,
            },
            Shadow {
                name: "test".to_string(),
                passwd: "$6$KEnq4G3CxkA2iU$hash".to_string(),
                last_change: 18660,
                change_min_days: 0,
                change_max_days: 99999,
                change_warn_days: 7,
                change_inactive_days: -1,
                expire_date: -1,
                reserved: 0,
            },
        ])
    }

    fn get_entry_by_name(name: String) -> Response<Shadow> {
        if name == "test" {
            Response::Success(Shadow {
                name: "test".to_string(),
                passwd: "$6$KEnq4G3CxkA2iU$hash".to_string(),
                last_change: 18660,
                change_min_days: 0,
                change_max_days: 99999,
                change_warn_days: 7,
                change_inactive_days: -1,
                expire_date: -1,
                reserved: 0,
            })
        } else {
            Response::NotFound
        }
    }
}
```

---

## Database: group

Provides group membership information (equivalent to `/etc/group`).

### Struct

```rust
pub struct Group {
    pub name: String,    // group name
    pub passwd: String,  // group password (often empty)
    pub gid: u32,        // group ID
    pub members: Vec<String>, // list of member usernames
}
```

### Trait

```rust
pub trait GroupHooks {
    // Fetch all group entries.
    fn get_all_entries() -> Response<Vec<Group>>;

    // Look up a single group by GID.
    fn get_entry_by_gid(gid: libc::gid_t) -> Response<Group>;

    // Look up a single group by name.
    fn get_entry_by_name(name: String) -> Response<Group>;
}
```

### Generated C functions

| Function | Input | Output |
|---|---|---|
| `nss_<name>_setgrent()` | none | `NssStatus` |
| `nss_<name>_endgrent()` | none | `NssStatus` |
| `nss_<name>_getgrent_r(result, buf, buflen, errnop)` | buf/buflen = output buffer | `NssStatus` — next entry |
| `nss_<name>_getgrgid_r(gid, result, buf, buflen, errnop)` | gid = group ID | `NssStatus` — entry or not found |
| `nss_<name>_getgrnam_r(name, result, buf, buflen, errnop)` | name = C string (group name) | `NssStatus` — entry or not found |

### Implementation example

```rust
use libnss::group::{Group, GroupHooks};
use libnss::{libnss_group_hooks, interop::Response};

struct ExampleGroup;
libnss_group_hooks!(example, ExampleGroup);

impl GroupHooks for ExampleGroup {
    fn get_all_entries() -> Response<Vec<Group>> {
        Response::Success(vec![
            Group {
                name: "root".to_string(),
                passwd: "".to_string(),
                gid: 0,
                members: vec!["root".to_string()],
            },
            Group {
                name: "test".to_string(),
                passwd: "".to_string(),
                gid: 1000,
                members: vec!["test".to_string(), "admin".to_string()],
            },
        ])
    }

    fn get_entry_by_gid(gid: libc::gid_t) -> Response<Group> {
        if gid == 1000 {
            Response::Success(Group {
                name: "test".to_string(),
                passwd: "".to_string(),
                gid: 1000,
                members: vec!["test".to_string(), "admin".to_string()],
            })
        } else {
            Response::NotFound
        }
    }

    fn get_entry_by_name(name: String) -> Response<Group> {
        if name == "test" {
            Response::Success(Group {
                name: "test".to_string(),
                passwd: "".to_string(),
                gid: 1000,
                members: vec!["test".to_string(), "admin".to_string()],
            })
        } else {
            Response::NotFound
        }
    }
}
```

---

## Database: host

Provides hostname-to-address resolution (equivalent to `/etc/hosts` + DNS).
Supports both IPv4 and IPv6.

### Structs

```rust
pub struct Host {
    pub name: String,        // canonical hostname
    pub aliases: Vec<String>, // list of alias names
    pub addresses: Addresses, // IP addresses
}

pub enum Addresses {
    V4(Vec<Ipv4Addr>),
    V6(Vec<Ipv6Addr>),
}

pub enum AddressFamily {
    IPv4,
    IPv6,
    Unspecified,
}
```

### Trait

```rust
pub trait HostHooks {
    // Fetch all host entries.
    fn get_all_entries() -> Response<Vec<Host>>;

    // Look up a host by its IP address.
    fn get_host_by_addr(addr: std::net::IpAddr) -> Response<Host>;

    // Look up a host by name and address family.
    fn get_host_by_name(name: &str, family: AddressFamily) -> Response<Host>;
}
```

### Generated C functions

| Function | Input | Output |
|---|---|---|
| `nss_<name>_sethostent()` | none | `NssStatus` |
| `nss_<name>_endhostent()` | none | `NssStatus` |
| `nss_<name>_gethostent_r(result, buf, buflen, errnop)` | buf/buflen = output buffer | `NssStatus` — next entry |
| `nss_<name>_gethostbyaddr_r(addr, len, format, result, buf, buflen, errnop, h_errnop)` | addr = C bytes, len = byte length, format = AF_INET/AF_INET6 | `NssStatus` — entry or not found |
| `nss_<name>_gethostbyname_r(name, result, buf, buflen, errnop, h_errnop)` | name = C string (hostname) | `NssStatus` — entry or not found |
| `nss_<name>_gethostbyname2_r(name, family, result, buf, buflen, errnop, h_errnop)` | name = C string, family = AF_INET/AF_INET6/AF_UNSPEC | `NssStatus` — entry or not found |
| `nss_<name>_gethostbyname3_r(name, family, result, buf, buflen, errnop, h_errnop, ttlp, canonp)` | name = C string, family = AF_UNSPEC by default | `NssStatus` — entry or not found (sets TTL and canonical name) |

### Implementation example

```rust
use std::net::{IpAddr, Ipv4Addr};
use libnss::host::{Host, HostHooks, Addresses, AddressFamily};
use libnss::{libnss_host_hooks, interop::Response};

struct ExampleHost;
libnss_host_hooks!(example, ExampleHost);

impl HostHooks for ExampleHost {
    fn get_all_entries() -> Response<Vec<Host>> {
        Response::Success(vec![
            Host {
                name: "localhost".to_string(),
                aliases: vec!["localhost.localdomain".to_string()],
                addresses: Addresses::V4(vec![
                    Ipv4Addr::new(127, 0, 0, 1),
                ]),
            },
            Host {
                name: "test.example".to_string(),
                aliases: vec!["other.example".to_string()],
                addresses: Addresses::V4(vec![
                    Ipv4Addr::new(177, 42, 42, 42),
                ]),
            },
        ])
    }

    fn get_host_by_addr(addr: IpAddr) -> Response<Host> {
        match addr {
            IpAddr::V4(addr) if addr.octets() == [177, 42, 42, 42] => {
                Response::Success(Host {
                    name: "test.example".to_string(),
                    aliases: vec!["other.example".to_string()],
                    addresses: Addresses::V4(vec![Ipv4Addr::new(177, 42, 42, 42)]),
                })
            }
            _ => Response::NotFound,
        }
    }

    fn get_host_by_name(name: &str, family: AddressFamily) -> Response<Host> {
        if name == "test.example" && family == AddressFamily::IPv4 {
            Response::Success(Host {
                name: "test.example".to_string(),
                aliases: vec!["test.example".to_string(), "other.example".to_string()],
                addresses: Addresses::V4(vec![Ipv4Addr::new(177, 42, 42, 42)]),
            })
        } else {
            Response::NotFound
        }
    }
}
```

---

## Database: initgroups

Provides supplementary group initialization for user sessions.
Called during login to build the list of groups a user belongs to.

### Trait

```rust
pub trait InitgroupsHooks {
    // Get all groups for a user (returns groups as Group structs).
    // The returned GIDs are written into the caller's group array,
    // excluding the primary group (skipgroup).
    fn get_entries_by_user(user: String) -> Response<Vec<Group>>;
}
```

### Generated C function

| Function | Input | Output |
|---|---|---|
| `nss_<name>_initgroups_dyn(user, skipgroup, start, size, groupsp, limit, errnop)` | **user**: C string (username)<br>**skipgroup**: primary GID to exclude<br>**start**: current offset in group array (in/out)<br>**size**: current capacity of group array (in/out)<br>**groupsp**: pointer to group ID array (in/out)<br>**limit**: maximum number of groups to return<br>**errnop**: error code pointer | `c_int` — `NssStatus` |

### Implementation example

```rust
use libnss::initgroups::InitgroupsHooks;
use libnss::group::Group;
use libnss::{libnss_initgroups_hooks, interop::Response};

struct ExampleInitgroups;
libnss_initgroups_hooks!(example, ExampleInitgroups);

impl InitgroupsHooks for ExampleInitgroups {
    fn get_entries_by_user(user: String) -> Response<Vec<Group>> {
        if user == "test" {
            Response::Success(vec![
                Group {
                    name: "test".to_string(),
                    passwd: "".to_string(),
                    gid: 1000,
                    members: vec!["test".to_string()],
                },
                Group {
                    name: "wheel".to_string(),
                    passwd: "".to_string(),
                    gid: 0,
                    members: vec!["root".to_string(), "test".to_string()],
                },
                Group {
                    name: "users".to_string(),
                    passwd: "".to_string(),
                    gid: 100,
                    members: vec!["test".to_string()],
                },
            ])
        } else {
            Response::NotFound
        }
    }
}
```

---

## Interop Layer

The interop module provides types shared across all databases:

### NssStatus

```rust
pub enum NssStatus {
    TryAgain  = -2,   // Buffer too small, caller should retry with larger buffer
    Unavail   = -1,   // Temporary server failure
    NotFound  = 0,    // Entry not found
    Success   = 1,    // Success
    Return    = 2,    // No more data (iterator exhausted)
}
```

### Response\<R\>

```rust
pub enum Response<R> {
    TryAgain,
    Unavail,
    NotFound,
    Success(R),    // Contains the actual data
    Return,
}
```

---

## Putting it all together

A complete module implements multiple databases and declares the generated hooks:

```rust
use libnss::passwd::{Passwd, PasswdHooks};
use libnss::group::{Group, GroupHooks};
use libnss::host::{Host, HostHooks, Addresses, AddressFamily};
use libnss::initgroups::InitgroupsHooks;
use libnss::shadow::{Shadow, ShadowHooks};
use libnss::{
    libnss_passwd_hooks, libnss_group_hooks, libnss_host_hooks,
    libnss_initgroups_hooks, libnss_shadow_hooks,
    interop::Response,
};

struct MyPasswd;
libnss_passwd_hooks!(mylib, MyPasswd);

struct MyGroup;
libnss_group_hooks!(mylib, MyGroup);

struct MyHost;
libnss_host_hooks!(mylib, MyHost);

struct MyInitgroups;
libnss_initgroups_hooks!(mylib, MyInitgroups);

struct MyShadow;
libnss_shadow_hooks!(mylib, MyShadow);

// Implement the traits for each...
```

### Build

```bash
cargo build --release
```

### Install the library

```bash
cd target/release
cp libnss_mylib.so libnss_mylib.so.2
sudo install -m 0644 libnss_mylib.so.2 /usr/lib
sudo ldconfig
```

### Enable your module in `/etc/nsswitch.conf`

The name must match the library name prefix (`libnss_<name>.so.2`):

```
passwd:         mylib files
shadow:         mylib files
group:          mylib files
hosts:          mylib files
initgroups:     mylib
```

---

## FreeBSD support

On FreeBSD, the `CPasswd` struct includes additional fields:
- `pw_change` — password change interval
- `pw_class` — access class
- `pw_expire` — account expiration
- `pw_fields` — field count

These are compiled conditionally with `#[cfg(target_os = "freebsd")]`.
