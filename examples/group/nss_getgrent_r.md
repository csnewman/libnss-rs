# nss_getgrent_r() — Get Next Group Entry

## Rust Signature

```rust
fn getgrent_r(
    result: *mut CGroup,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> NssStatus;
```

## C ABI Signature

```c
extern "C" {
    int nss_<name>_getgrent_r(
        struct group *result,    /* output: group entry */
        char *buf,               /* input:  buffer */
        size_t buflen,           /* input:  buffer length */
        int *errnop,             /* output: error code */
    );
}
```

## Parameters

| Parameter | Direction | Type | Description |
|---|---|---|---|
| `result` | out | `*mut CGroup` | Pointer to the group structure to fill. |
| `buf` | in | `*mut c_char` | Caller-provided buffer. |
| `buflen` | in | `size_t` | Buffer size in bytes. |
| `errnop` | out | `*mut c_int` | Error number. |

## Return Value

| Value | Constant | Description |
|---|---|---|
| `1` | `NssStatus::Success` | Entry found. |
| `2` | `NssStatus::Return` | No more entries. |
| `-2` | `NssStatus::TryAgain` | Buffer too small. |
| `-1` | `NssStatus::Unavail` | Temporary failure. |

## C Group Struct Layout

```rust
#[repr(C)]
pub struct CGroup {
    pub name:    *mut c_char,         /* group name        */
    pub passwd:  *mut c_char,         /* group password    */
    pub gid:     gid_t,               /* group ID           */
    pub members: *mut *mut c_char,   /* null-terminated array of members */
}
```

## How It Works

```
┌────────────────────────────────────────────────────┐
│  getgrent_r() call sequence                        │
│                                                    │
│  1. Application:                                   │
│     struct group gr;                               │
│     char buf[2048];                                │
│     int err;                                       │
│     nss_example_getgrent_r(&gr, buf, 2048, &err);  │
│                                                    │
│  2. libnss-rs flow:                                │
│     Iterator::next()  →  Response<Group>           │
│         ├── items.get(index)  →  Some(Group)       │
│         ├── index += 1                             │
│         └── Group::to_c(result, buf, buflen)       │
│                                                    │
│  3. Result:                                        │
│     gr.name     → "test"   gr.gid     → 1005       │
│     gr.passwd   → ""       gr.members → ["someone"]|
└────────────────────────────────────────────────────┘
```

## Integration Examples

### 1. `getent group` — enumerate all groups

```bash
getent group
  │
  ├── setgrent()     — load entries
  ├── getgrent_r()  — "test::1005:someone"
  ├── getgrent_r()  — "root::0:root"
  └── endgrent()
```

### 2. `groups` — list user groups

```
groups test
  │
  ├── setgrent()
  ├── getgrent_r()  — for each group:
  │   ├── check if "test" in gr.members
  │   └── collect matching group names
  │
  └── output: test : test wheel users
```

### 3. `newgrp` — change effective group

```
newgrp test
  │
  ├── getgrnam_r("test")  → gid=1005
  ├── setgid(1005)        — change effective GID
  └── new processes have gid=1005
```

## Rust Implementation Example

```rust
#[no_mangle]
unsafe extern "C" fn nss_example_getgrent_r(
    result: *mut CGroup,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> c_int {
    let mut iter: MutexGuard<Iterator<Group>> =
        GROUP_EXAMPLE_ITERATOR.lock().unwrap();
    let code: c_int = iter.next().to_c(result, buf, buflen, errnop) as c_int;
    if code == NssStatus::TryAgain as c_int {
        iter.previous();
    }
    code
}
```
