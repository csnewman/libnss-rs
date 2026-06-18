# nss_setpwent() — Start/Reset passwd Enumeration

## Rust Signature

```rust
fn setpwent() -> NssStatus;
// Called via:
// <super::$hooks_ident as PasswdHooks>::get_all_entries()
// iter.open(entries)
```

## C ABI Signature

```c
extern "C" {
    int nss_<name>_setpwent(void);
}
```

The first parameter (`name`) in the macro invocation (`libnss_passwd_hooks!(mylib, MyPasswd)`)
becomes the symbol prefix: `nss_mylib_setpwent`.

## Parameters

| Parameter | Direction | Type | Description |
|---|---|---|---|
| *(none)* | — | — | No input parameters. |

## Return Value

| Value | Constant | Description |
|---|---|---|
| `1` | `NssStatus::Success` | Entries loaded successfully, iterator ready. |
| `-2` | `NssStatus::TryAgain` | Buffer too small, retry with larger buffer. |
| `-1` | `NssStatus::Unavail` | Temporary server failure, try again later. |
| `0` | `NssStatus::NotFound` | No entries available. |

## How It Works

```
┌──────────────────────────────────────────────────────────┐
│  Application (e.g., getent, login, su)                   │
│      │                                                   │
│      ▼  Calls nss_<name>_setpwent()                      │
│  glibc NSS dispatcher                                    │
│      │                                                   │
│      ▼  PasswdHooks::get_all_entries()                   │
│  Your Rust implementation                                │
│      │                                                   │
│      ▼  iter.open(Vec<Passwd>)                           │
│  lazy_static Mutex<Iterator<Passwd>>                     │
│      │                                                   │
│      ▼  Iterator state: items = Some(VecDeque), index = 0│
│  Iterator ready for sequential getpwent_r() calls        │
└──────────────────────────────────────────────────────────┘
```

**Step-by-step:**

1. **Application calls `nss_<name>_setpwent()`** — Typically the first call before a series
   of `getpwent_r()` calls. It resets the iterator to the beginning.
2. **glibc dispatches to your shared library** — The `#[no_mangle]` export ensures glibc
   finds the symbol by name in `libnss_<name>.so.2`.
3. **Your `PasswdHooks::get_all_entries()` is called** — This fetches all passwd entries
   from your data source (file, LDAP, database, hardcoded, etc.).
4. **The `lazy_static Mutex<Iterator<Passwd>>` is updated** — The iterator stores all entries
   in a `VecDeque`, sets `index` to `0`, and marks the state as `Success`.
5. **Subsequent `getpwent_r()` calls** return entries one at a time, advancing the index.

## Integration Examples

### 1. `getent passwd` (system utility)

```bash
# getent calls:
# 1. setpwent()  — reset iterator
# 2. getpwent_r()  — get first entry
# 3. getpwent_r()  — get second entry
# ...
# n. getpwent_r()  — last entry returns `NotFound`
# n+1. endpwent()  — close iterator
```

### 2. User login flow

```
login(3) → getpwnam_r("root")     — look up user by name
                │
                ▼
getpwuid_r(0)  — verify UID matches
                │
                ▼
initgroups_dyn("root", ...)   — build group list
```

### 3. PAM authentication

```
pam_get_item(PAM_USER)  → "test"
                │
                ▼
nss_getpwnam_r("test")  — lookup password entry
                │
                ▼
compare shadow via nss_getspnam_r("test")
```

### 4. Filesystem mount integration

```bash
# mount checks /etc/fstab by owner UID
mount → getpwuid_r(1000)  — check home directory ownership
```

## Rust Implementation Example

```rust
use libnss::passwd::{Passwd, PasswdHooks};
use libnss::interop::Response;
use libnss::libnss_passwd_hooks;

struct ExamplePasswd;
libnss_passwd_hooks!(example, ExamplePasswd);

impl PasswdHooks for ExamplePasswd {
    fn get_all_entries() -> Response<Vec<Passwd>> {
        // This is called internally by setpwent
        // Returns all entries which become the iterator's contents
        Response::Success(vec![
            Passwd {
                name: "root".to_string(),
                passwd: "$6$xyz".to_string(),
                uid: 0,
                gid: 0,
                gecos: "Root".to_string(),
                dir: "/root".to_string(),
                shell: "/bin/bash".to_string(),
            },
            Passwd {
                name: "test".to_string(),
                passwd: "$6$abc".to_string(),
                uid: 1000,
                gid: 1000,
                gecos: "Test User".to_string(),
                dir: "/home/test".to_string(),
                shell: "/bin/bash".to_string(),
            },
        ])
    }
    // ... other trait methods
}
```

## State Diagram

```
  Idle
    │
    │ setpwent()
    ▼
  Active ──getpwent_r()──→ entries advance
    │                         │
    │                         ├──→ TryAgain (iterator exhausted)
    │                         │
    │                         └──→ Success (next entry)
    │
    │ endpwent()
    ▼
  Closed
```
