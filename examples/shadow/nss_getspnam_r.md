# nss_getspnam_r() — Lookup Shadow Entry by Name

## Rust Signature

```rust
fn getspnam_r(
    result: *mut CShadow,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> NssStatus;
```

The Rust trait method:
```rust
fn get_entry_by_name(name: String) -> Response<Shadow>;
```

## C ABI Signature

```c
extern "C" {
    int nss_<name>_getspnam_r(
        const char *name,           /* input:  username */
        struct spwd *result,        /* output: shadow entry */
        char *buf,                  /* input:  buffer */
        size_t buflen,              /* input:  buffer length */
        int *errnop,                /* output: error code */
    );
}
```

## Parameters

| Parameter | Direction | Type | Description |
|---|---|---|---|
| `name` | in | `*const c_char` | C string of the username. |
| `result` | out | `*mut CShadow` | Pointer to the shadow structure to fill. |
| `buf` | in | `*mut c_char` | Caller-provided buffer. |
| `buflen` | in | `size_t` | Size of `buf`. |
| `errnop` | out | `*mut c_int` | Error number. |

## Return Value

| Value | Constant | Description |
|---|---|---|
| `1` | `NssStatus::Success` | Shadow entry found, `result` filled. |
| `0` | `NssStatus::NotFound` | No shadow entry for this name. |
| `-2` | `NssStatus::TryAgain` | Buffer too small. |
| `-1` | `NssStatus::Unavail` | Temporary failure. |

## How It Works

```
┌───────────────────────────────────────────────────────────┐
│  getspnam_r("test") call sequence                         │
│                                                           │
│  1. Application:                                          │
│     struct spwd sp;                                       │
│     char buf[2048];                                       │
│     int err;                                              │
│     nss_example_getspnam_r("test", &sp, buf,              │
│                            2048, &err);                   │
│                                                           │
│  2. libnss-rs flow:                                       │
│     CStr::from_ptr(name_)                                 │
│         → from_utf8()  →  "test"                          │
│         → ShadowHooks::get_entry_by_name("test")          │
│         → Response::to_c(result, buf, buflen)             │
│                                                           │
│  3. Result:                                               │
│     sp.name     → "test"       sp.last_change  → 18660    │
│     sp.passwd   → "$6$hash"    sp.min_days     → 0        │
└───────────────────────────────────────────────────────────┘
```

## Integration Examples

### 1. `getent shadow test` — lookup single entry

```bash
getent shadow test
  │
  ├── getspnam_r("test")
  │
  └── output:
       test:$6$KEnq4G3CxkA2iU$l/BBqPJlzPvXDfa9...:18660:0:99999:7:::0
```

### 2. PAM authentication

```
pam_authenticate(PAM_USER="test")
  │
  ├── getpwnam_r("test")        → uid, dir, shell
  ├── getspnam_r("test")        → password hash
  │
  ├── pam_get_authtok()         → user types password
  ├── crypt(password, sp.passwd) → hash match
  │
  └── PAM_AUTH_SUCCESS
```

### 3. `sudo` — privilege escalation

```
sudo -u test command
  │
  ├── getspnam_r("test")
  │   ├── sp.passwd = "$6$hash"
  │   ├── sp.last_change = 18660
  │   └── sp.expire_date = -1
  │
  ├── Check password aging constraints
  ├── Verify password hash matches
  │
  └── Grant sudo access
```

### 4. `passwd` — password update

```
passwd test
  │
  ├── getspnam_r("test")    → read current shadow entry
  │   ├── Old: sp.passwd = "$6$oldhash"
  │   └── Old: sp.last_change = 18660
  │
  ├── User types new password
  ├── Hash new password: crypt(new_pass, salt)
  │
  ├── getpwnam_r("test")    → update passwd field in /etc/passwd
  ├── setspent()             → reset iterator
  │
  └── Write new shadow entry:
       sp.name = "test"
       sp.passwd = "$6$newhash"
       sp.last_change = current_date (days since 1970)
```

## Rust Implementation Example

```rust
use libnss::shadow::{Shadow, ShadowHooks};
use libnss::interop::Response;
use libnss::libnss_shadow_hooks;

impl ShadowHooks for ExampleShadow {
    fn get_entry_by_name(name: String) -> Response<Shadow> {
        let entry = YOUR_DATA_SOURCE.iter()
            .find(|e| e.name == name)
            .cloned();

        match entry {
            Some(shadow) => Response::Success(shadow),
            None => Response::NotFound,
        }
    }
}
```

## C Caller Example

```c
#include <shadow.h>
#include <stdio.h>

void lookup_shadow(const char *username) {
    struct spwd sp;
    char buf[2048];
    int err;

    int rc = nss_example_getspnam_r(username, &sp, buf, sizeof(buf), &err);

    if (rc == 1) {
        printf("Shadow entry for %s:\n", sp.name);
        printf("  password hash: %s\n", sp.passwd);
        printf("  last change:   %ld\n", sp.last_change);
        printf("  min days:      %ld\n", sp.change_min_days);
        printf("  max days:      %ld\n", sp.change_max_days);
        printf("  warn days:     %ld\n", sp.change_warn_days);
        printf("  inactive:      %ld\n", sp.change_inactive_days);
        printf("  expire:        %ld\n", sp.expire_date);
    } else if (rc == 0) {
        printf("Shadow entry for '%s' not found\n", username);
    }
}
```
