# nss_getpwnam_r() — Lookup passwd Entry by Name

## Rust Signature

```rust
fn getpwnam_r(
    result: *mut CPasswd,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> NssStatus;
```

The Rust trait method is:
```rust
fn get_entry_by_name(name: String) -> Response<Passwd>;
```

## C ABI Signature

```c
extern "C" {
    int nss_<name>_getpwnam_r(
        const char *name,           /* input:  username (C string) */
        struct passwd *result,      /* output: the passwd entry */
        char *buf,                  /* input:  caller's buffer */
        size_t buflen,              /* input:  buffer length */
        int *errnop,                /* output: error code */
    );
}
```

## Parameters

| Parameter | Direction | Type | Description |
|---|---|---|---|
| `name` | in | `*const c_char` | C string of the username to look up. |
| `result` | out | `*mut CPasswd` | Pointer to the passwd structure to fill. |
| `buf` | in | `*mut c_char` | Caller-provided buffer for C-string allocation. |
| `buflen` | in | `size_t` | Size of `buf` in bytes. |
| `errnop` | out | `*mut c_int` | Error number (0 = success, non-zero = error). |

## Return Value

| Value | Constant | Description |
|---|---|---|
| `1` | `NssStatus::Success` | Entry with matching name found, `result` filled. |
| `0` | `NssStatus::NotFound` | No entry with this name exists. |
| `-2` | `NssStatus::TryAgain` | Buffer too small, retry with larger buffer. |
| `-1` | `NssStatus::Unavail` | Temporary server failure. |

## How It Works

```
┌───────────────────────────────────────────────────────────────┐
│  getpwnam_r("test") call sequence                             │
│                                                               │
│  1. Application:                                              │
│     struct passwd pw;                                         │
│     char buf[2048];                                           │
│     int err;                                                  │
│     nss_example_getpwnam_r("test", &pw, buf, 2048, &err);     │
│                                                               │
│  2. libnss-rs internal flow:                                  │
│     ┌───────────────────────────────────────────────┐         │
│     │ Step 1: CStr::from_ptr(name_)                 │         │
│     │ Step 2: from_utf8(cstr.to_bytes())  → "test"  │         │
│     │ Step 3: PasswdHooks::get_entry_by_name("test")│         │
│     │         └── Your data source iterates         │         │
│     │ Step 4: Response::to_c(result, buf, ...)      │         │
│     └───────────────────────────────────────────────┘         │
│                                                               │
│  3. Result when name="test" matches:                          │
│     pw.name   → "test"         pw.uid   → 1005                │
│     pw.passwd → "$6$xyz"       pw.gid   → 1005                │
│     pw.gecos  → "Test User"    pw.dir   → "/home/test"        │
│     pw.shell  → "/bin/bash"                                   │
└───────────────────────────────────────────────────────────────┘
```

**Step-by-step:**

1. **glibc passes a C string** (`*const c_char`) containing the username.
2. **`CStr::from_ptr()`** converts the C string to a Rust `&CStr`.
3. **`from_utf8()`** validates and converts it to a Rust `String`.
4. **`PasswdHooks::get_entry_by_name()`** is called — your implementation looks up
   the entry by comparing `entry.name == name`.
5. **`Response::to_c()`** converts the Rust `Passwd` struct to C layout:
   - Copies all string fields into `buf` via `CBuffer.write_str()`.
   - Sets pointers in `result` to point into `buf`.
6. **Return `NssStatus`** — glibc interprets success, not-found, or error.

## Integration Examples

### 1. `getent passwd test` — named lookup

```bash
getent passwd test
  │
  ├── glibc: nss_getpwnam_r("test", &pw, buf, 2048, &err)
  │
  ├── libnss-rs: get_entry_by_name("test")
  │
  └── output: test:x:1005:1005:Test User:/home/test:/bin/bash
```

### 2. Login authentication

```
login(3)
  │
  ├── getpwnam_r("alice")  → uid=2000
  │
  ├── open("/etc/shadow")  → getspnam_r("alice")
  │   │
  │   └── compare password hash
  │
  ├── getpwnam_r("alice")  → dir="/home/alice", shell="/bin/zsh"
  │
  └── create session with uid=2000, gid=2000
```

### 3. `su` command — switch user

```
su - alice
  │
  ├── getpwnam_r("alice")
  │   ├── result.name   → "alice"
  │   ├── result.dir    → "/home/alice"
  │   ├── result.shell  → "/bin/zsh"
  │   └── result.uid    → 2000
  │
  ├── chdir("/home/alice")
  ├── setuid(2000)
  └── exec("/bin/zsh")
```

### 4. `cron` — user-specific crontab

```
cron
  │
  ├── getpwnam_r("alice")
  │   ├── result.uid  → 2000
  │   └── result.dir  → "/home/alice"
  │
  ├── open crontab: /var/spool/cron/crontabs/alice
  │
  └── execute jobs with uid=2000
```

### 5. `getent group` — group membership

```
getent group --all
  │
  ├── for each group:
  │   ├── members = ["alice", "bob"]
  │   └── for each member:
  │       ├── getpwnam_r(member)
  │       └── resolve uid/gid
  │
  └── output: groupname::gid:alice,bob
```

## Rust Implementation Example

```rust
use libnss::passwd::{Passwd, PasswdHooks};
use libnss::interop::Response;
use libnss::libnss_passwd_hooks;

impl PasswdHooks for ExamplePasswd {
    fn get_entry_by_name(name: String) -> Response<Passwd> {
        // This is the trait method called by the generated function
        let entry = YOUR_DATA_SOURCE.iter()
            .find(|e| e.name == name)
            .cloned();

        match entry {
            Some(passwd) => Response::Success(passwd),
            None => Response::NotFound,
        }
    }
}
```

## C Caller Example

```c
#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>

void lookup_user_by_name(const char *username) {
    struct passwd pw;
    char buf[2048];
    int err;

    int rc = nss_example_getpwnam_r(username, &pw, buf, sizeof(buf), &err);

    if (rc == 1) {  /* NssStatus::Success */
        printf("Found: %s (uid=%u, gid=%u)\n",
               pw.name, pw.uid, pw.gid);
        printf("  home: %s\n", pw.dir);
        printf("  shell: %s\n", pw.shell);
    } else if (rc == 0) {  /* NssStatus::NotFound */
        printf("User '%s' not found\n", username);
    }
}
```
