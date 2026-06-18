# nss_getgrnam_r() — Lookup Group Entry by Name

## Rust Signature

```rust
fn getgrnam_r(
    result: *mut CGroup,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> NssStatus;
```

The Rust trait method:
```rust
fn get_entry_by_name(name: String) -> Response<Group>;
```

## C ABI Signature

```c
extern "C" {
    int nss_<name>_getgrnam_r(
        const char *name,           /* input:  group name */
        struct group *result,       /* output: group entry */
        char *buf,                  /* input:  buffer */
        size_t buflen,              /* input:  buffer length */
        int *errnop,                /* output: error code */
    );
}
```

## Parameters

| Parameter | Direction | Type | Description |
|---|---|---|---|
| `name` | in | `*const c_char` | C string of the group name. |
| `result` | out | `*mut CGroup` | Pointer to the group structure to fill. |
| `buf` | in | `*mut c_char` | Caller-provided buffer. |
| `buflen` | in | `size_t` | Buffer size. |
| `errnop` | out | `*mut c_int` | Error number. |

## Return Value

| Value | Constant | Description |
|---|---|---|
| `1` | `NssStatus::Success` | Group entry found. |
| `0` | `NssStatus::NotFound` | No group with this name. |
| `-2` | `NssStatus::TryAgain` | Buffer too small. |
| `-1` | `NssStatus::Unavail` | Temporary failure. |

## How It Works

```
┌────────────────────────────────────────────────────┐
│  getgrnam_r("test") call sequence                  │
│                                                    │
│  1. Application:                                   │
│     struct group gr;                               │
│     nss_example_getgrnam_r("test", &gr, buf,       │
│                            sizeof(buf), &err);     │
│                                                    │
│  2. libnss-rs flow:                                │
│     CStr::from_ptr(name_)                          │
│         → from_utf8()  →  "test"                   │
│         → GroupHooks::get_entry_by_name("test")    │
│         → Response::to_c(result, buf, buflen)      │
│                                                    │
│  3. Result:                                        │
│     gr.name     → "test"       gr.gid      → 1005  │
│     gr.members  → ["someone"]                      │
└────────────────────────────────────────────────────┘
```

## Integration Examples

### 1. `getent group test` — lookup by name

```bash
getent group test
  │
  ├── getgrnam_r("test")
  │
  └── output: test::1005:someone
```

### 2. `newgrp` — switch group

```
newgrp test
  │
  ├── getgrnam_r("test")  → gid=1005
  ├── setgid(1005)
  └── effective group = test
```

### 3. `chgrp` — change file group

```
chgrp test file.txt
  │
  ├── getgrnam_r("test")  → gid=1005
  ├── chown(fd, -1, 1005)
  └── file.group = 1005
```

### 4. PAM group-based authorization

```
pam_authz_check(user="test")
  │
  ├── getgrnam_r("wheel")  → members=["root", "test"]
  │
  ├── Check if user in group members
  │
  └── PAM_AUTHZ_SUCCESS if "test" in members
```

## Rust Implementation Example

```rust
use libnss::group::{Group, GroupHooks};
use libnss::interop::Response;
use libnss::libnss_group_hooks;

impl GroupHooks for ExampleGroup {
    fn get_entry_by_name(name: String) -> Response<Group> {
        let entry = YOUR_DATA_SOURCE.iter()
            .find(|e| e.name == name)
            .cloned();

        match entry {
            Some(group) => Response::Success(group),
            None => Response::NotFound,
        }
    }
}
```

## C Caller Example

```c
#include <grp.h>
#include <stdio.h>

void lookup_group_by_name(const char *groupname) {
    struct group gr;
    char buf[2048];
    int err;

    int rc = nss_example_getgrnam_r(groupname, &gr, buf, sizeof(buf), &err);

    if (rc == 1) {
        printf("Group '%s': gid=%u\n", gr.gr_name, gr.gr_gid);
        printf("  Members:");
        for (int i = 0; gr.gr_mem[i] != NULL; i++) {
            printf(" %s", gr.gr_mem[i]);
        }
        printf("\n");
    }
}
```
