# nss_getgrgid_r() — Lookup Group Entry by GID

## Rust Signature

```rust
fn getgrgid_r(
    gid: c_uint,
    result: *mut CGroup,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> NssStatus;
```

The Rust trait method:
```rust
fn get_entry_by_gid(gid: c_uint) -> Response<Group>;
```

## C ABI Signature

```c
extern "C" {
    int nss_<name>_getgrgid_r(
        gid_t uid,                /* input:  group ID */
        struct group *result,     /* output: group entry */
        char *buf,                /* input:  buffer */
        size_t buflen,            /* input:  buffer length */
        int *errnop,              /* output: error code */
    );
}
```

## Parameters

| Parameter | Direction | Type | Description |
|---|---|---|---|
| `gid` | in | `c_uint` | Group ID to look up. |
| `result` | out | `*mut CGroup` | Pointer to the group structure to fill. |
| `buf` | in | `*mut c_char` | Caller-provided buffer. |
| `buflen` | in | `size_t` | Buffer size in bytes. |
| `errnop` | out | `*mut c_int` | Error number. |

## Return Value

| Value | Constant | Description |
|---|---|---|
| `1` | `NssStatus::Success` | Group entry found. |
| `0` | `NssStatus::NotFound` | No group with this GID. |
| `-2` | `NssStatus::TryAgain` | Buffer too small. |
| `-1` | `NssStatus::Unavail` | Temporary failure. |

## How It Works

```
┌────────────────────────────────────────────────────┐
│  getgrgid_r(1005) call sequence                    │
│                                                    │
│  1. Application:                                   │
│     struct group gr;                               │
│     char buf[2048];                                │
│     int err;                                       │
│     nss_example_getgrgid_r(1005, &gr, buf, 2048,   │
│                            &err);                  │
│                                                    │
│  2. libnss-rs flow:                                │
│     GroupHooks::get_entry_by_gid(1005)             │
│         ├── Iterate all entries                    │
│         ├── Compare entry.gid == gid               │
│         └── Response::to_c(result, buf, buflen)    │
│                                                    │
│  3. Result:                                        │
│     gr.name     → "test"       gr.gid      → 1005  │
│     gr.members  → ["someone"]                      │
└────────────────────────────────────────────────────┘
```

## Integration Examples

### 1. `id -g` — get group ID

```
id -g
  │
  ├── getegid()   → 1005
  ├── getgrgid_r(1005)  → "test"
  └── output: 1005 (test)
```

### 2. `ls -l` — file group name

```
ls -l /home/test/file.txt
  │
  ├── stat()  → st_gid = 1005
  │
  ├── getgrgid_r(1005)  → "test"
  │
  └── output: -rw-r--r-- 1 user test ... file.txt
```

### 3. `chown` — change file group

```
chown :test /home/test/file.txt
  │
  ├── getgrnam_r("test")  → gid=1005
  ├── chown(fd, -1, 1005)
  └── file.group = 1005
```

### 4. File creation with setgid

```
mkdir /var/sandbox  /* setgid bit set, gid=1005 */
touch /var/sandbox/new_file

/* new_file inherits gid=1005 */
ls -l /var/sandbox/new_file
  │
  ├── getgrgid_r(1005)  → "test"
  └── output: -rw-rw-r-- 1 user test ... new_file
```

## Rust Implementation Example

```rust
use libnss::group::{Group, GroupHooks};
use libnss::interop::Response;
use libnss::libnss_group_hooks;

impl GroupHooks for ExampleGroup {
    fn get_entry_by_gid(gid: c_uint) -> Response<Group> {
        let entry = YOUR_DATA_SOURCE.iter()
            .find(|e| e.gid == gid)
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

void lookup_group(gid_t target_gid) {
    struct group gr;
    char buf[2048];
    int err;

    int rc = nss_example_getgrgid_r(target_gid, &gr, buf, sizeof(buf), &err);

    if (rc == 1) {
        printf("Group %u: name=%s, members=%zu\n",
               target_gid, gr.gr_name, gr.gr_nmems);
        for (int i = 0; gr.gr_mem[i] != NULL; i++) {
            printf("  member[%d]: %s\n", i, gr.gr_mem[i]);
        }
    }
}
```
