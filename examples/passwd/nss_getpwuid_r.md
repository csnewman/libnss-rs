# nss_getpwuid_r() — Lookup passwd Entry by UID

## Rust Signature

```rust
fn getpwuid_r(
    result: *mut CPasswd,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> NssStatus;
```

The Rust trait method is:
```rust
fn get_entry_by_uid(uid: c_uint) -> Response<Passwd>;
```

## C ABI Signature

```c
extern "C" {
    int nss_<name>_getpwuid_r(
        uid_t uid,               /* input:  user ID to look up */
        struct passwd *result,   /* output: the passwd entry */
        char *buf,               /* input:  caller's buffer */
        size_t buflen,           /* input:  buffer length */
        int *errnop,             /* output: error code */
    );
}
```

## Parameters

| Parameter | Direction | Type | Description |
|---|---|---|---|
| `uid` | in | `c_uint` | User ID to look up (e.g., `0` for root). |
| `result` | out | `*mut CPasswd` | Pointer to the passwd structure to fill. |
| `buf` | in | `*mut c_char` | Caller-provided buffer for C-string allocation. |
| `buflen` | in | `size_t` | Size of `buf` in bytes. |
| `errnop` | out | `*mut c_int` | Error number (0 = success, non-zero = error). |

## Return Value

| Value | Constant | Description |
|---|---|---|
| `1` | `NssStatus::Success` | Entry with matching UID found, `result` filled. |
| `0` | `NssStatus::NotFound` | No entry with this UID exists. |
| `-2` | `NssStatus::TryAgain` | Buffer too small, retry with larger buffer. |
| `-1` | `NssStatus::Unavail` | Temporary server failure. |

## How It Works

```
┌───────────────────────────────────────────────────────────────┐
│  getpwuid_r(uid=1005) call sequence                           │
│                                                               │
│  1. Application:                                              │
│     uid_t target = 1005;                                      │
│     struct passwd pw;                                         │
│     char buf[2048];                                           │
│     int err;                                                  │
│     nss_example_getpwuid_r(target, &pw, buf, 2048, &err);     │
│                                                               │
│  2. libnss-rs internal flow:                                  │
│     PasswdHooks::get_entry_by_uid(uid)                        │
│        │                                                      │
│        ├── Iterate all entries from your data source          │
│        ├── Compare entry.uid == uid                           │
│        │                                                      │
│        ├── If found: Response::Success(entry)                 │
│        │   │                                                  │
│        │   └── Response::to_c() → fill result via CBuffer     │
│        │                                                      │
│        └── If not found: Response::NotFound                   │
│                                                               │
│  3. Result when uid=1005 matches:                             │
│     pw.name   → "test"         pw.uid   → 1005                │
│     pw.passwd → "$6$xyz"       pw.gid   → 1005                │
│     pw.gecos  → "Test User"    pw.dir   → "/home/test"        │
│     pw.shell  → "/bin/bash"                                   │
└───────────────────────────────────────────────────────────────┘
```

## Integration Examples

### 1. `whoami` — resolve UID to username

```bash
whoami
  │
  ├── getuid()    → 1005
  ├── getpwuid_r(1005)  → "test"
  │
  └── prints "test"
```

### 2. `ps -u` — list processes by owner

```
ps -u test
  │
  ├── getpwnam("test")  → uid=1005
  │
  ├── For each process:
  │   ├── getpwuid_r(proc->uid)  → pass if uid==1005
  │   └── display process info
  │
  └── output: processes owned by test
```

### 3. File ownership check (`stat`)

```
stat /home/test/file.txt
  │
  ├── stat()  → inode with uid=1005, gid=1005
  │
  ├── getpwuid_r(1005)  → "test"
  ├── getgrgid_r(1005)  → "test" (group)
  │
  └── output: test test file.txt
```

### 4. PAM session setup

```
pam_open_session()
  │
  ├── getpwnam_r("test")  → uid=1005, dir="/home/test", shell="/bin/bash"
  │
  ├── chdir("/home/test")
  ├── setuid(1005)
  ├── setgid(1005)
  │
  └── exec("/bin/bash")
```

### 5. `id` command — user and group IDs

```
id test
  │
  ├── getpwnam_r("test")  → uid=1005, gid=1005
  ├── getgrgid_r(1005)   → group name "test"
  ├── getpwuid_r(1005)   → confirms uid→name
  │
  └── output: uid=1005(test) gid=1005(test)
```

## Rust Implementation Example

```rust
use libnss::passwd::{Passwd, PasswdHooks};
use libnss::interop::Response;
use libnss::libnss_passwd_hooks;

impl PasswdHooks for ExamplePasswd {
    fn get_entry_by_uid(uid: c_uint) -> Response<Passwd> {
        // This is the trait method called by the generated function
        let entry = YOUR_DATA_SOURCE.iter()
            .find(|e| e.uid == uid)
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

void lookup_user(uid_t target_uid) {
    struct passwd pw;
    char buf[2048];
    int err;

    int rc = nss_example_getpwuid_r(target_uid, &pw, buf, sizeof(buf), &err);

    if (rc == 1) {  /* NssStatus::Success */
        printf("Found: %s (uid=%u, gid=%u, dir=%s, shell=%s)\n",
               pw.name, pw.uid, pw.gid, pw.dir, pw.shell);
    } else if (rc == 0) {  /* NssStatus::NotFound */
        printf("UID %u not found\n", target_uid);
    } else if (rc == -2) {  /* NssStatus::TryAgain */
        printf("Buffer too small, retry with larger buffer\n");
    }
}
```
