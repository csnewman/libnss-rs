# nss_getpwent_r() — Get Next passwd Entry

## Rust Signature

```rust
fn getpwent_r(
    result: *mut CPasswd,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> NssStatus;
```

## C ABI Signature

```c
extern "C" {
    int nss_<name>_getpwent_r(
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
| `result` | out | `*mut CPasswd` | Pointer to the passwd structure to fill. |
| `buf` | in | `*mut c_char` | Caller-provided buffer for C-string allocation. |
| `buflen` | in | `size_t` | Size of `buf` in bytes. |
| `errnop` | out | `*mut c_int` | Error number (0 = success, non-zero = error). |

## Return Value

| Value | Constant | Description |
|---|---|---|
| `1` | `NssStatus::Success` | Entry found, `result` filled. |
| `2` | `NssStatus::Return` | No more entries (iterator exhausted). |
| `-2` | `NssStatus::TryAgain` | Buffer too small, retry with larger buffer. |
| `-1` | `NssStatus::Unavail` | Temporary server failure. |

## C Passwd Struct Layout (Linux)

```rust
#[repr(C)]
pub struct CPasswd {
    pub name:   *mut c_char,   /* username                        */
    pub passwd: *mut c_char,   /* user password (shadowed hash)  */
    pub uid:    uid_t,         /* user ID                       */
    pub gid:    gid_t,         /* group ID                      */
    pub gecos:  *mut c_char,   /* GECOS / comment field          */
    pub dir:    *mut c_char,   /* home directory                 */
    pub shell:  *mut c_char,   /* login shell                   */
}
```

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│  getpwent_r() call sequence                                 │
│                                                             │
│  1. Application:                                            │
│     struct passwd pw;                                       │
│     char buf[2048];                                         │
│     int err;                                                │
│     nss_example_getpwent_r(&pw, buf, 2048, &err);           │
│                                                             │
│  2. libnss-rs internal flow:                                │
│     ┌────────────────────────────────────────────────────┐  │
│     │ PASSWD_EXAMPLE_ITERATOR.lock()                     │  │
│     │ iter.next():                                       │  │
│     │   2a. items.get(index)  →  Some(Passwd)            │  │
│     │   2b. index += 1                                   │  │
│     │   2c. Passwd.to_c(result, buf, buflen, errnop)     │  │
│     │       → name, passwd, gecos, dir, shell copied     │  │
│     │         into buf via CBuffer.write_str()           │  │
│     │       → pointers in result set to buf addresses    │  │
│     └────────────────────────────────────────────────────┘  │
│                                                             │
│  3. Result in result struct:                                │
│     pw.name   → "root"       (in buf)                       │
│     pw.passwd → "$6$xyz"     (in buf)                       │
│     pw.uid    → 0                                           │
│     pw.gid    → 0                                           │
│     pw.gecos  → "Root"       (in buf)                       │
│     pw.dir    → "/root"      (in buf)                       │
│     pw.shell  → "/bin/bash"  (in buf)                       │
└─────────────────────────────────────────────────────────────┘
```

**Step-by-step:**

1. **Lock the global `lazy_static` iterator** — thread-safe access to the shared state.
2. **`Iterator::next()` returns `Response<Passwd>`** — if entries exist, returns `Success(entry)`;
   if exhausted, returns `NotFound`; if no entries loaded, returns `Unavail`.
3. **`Response::to_c()` converts the Rust struct to C layout** — calls `Passwd.to_c()` which:
   - Allocates space in `buf` via `CBuffer.write_str()` for each `String` field.
   - Copies C-string bytes into `buf`.
   - Sets pointers in `result` to point into `buf`.
4. **If buffer too small**, returns `TryAgain` and the application should retry with a larger
   `buflen`. If `TryAgain`, the iterator index is decremented so the next call re-reads the
   same entry.
5. **Return `NssStatus`** as a `c_int` — glibc interprets the code.

## Integration Examples

### 1. `getent passwd` — sequential enumeration

```bash
# Application calls getpwent_r() in a loop:
while ((rc = nss_example_getpwent_r(&pw, buf, sizeof(buf), &err)) == 1) {
    printf("%s:%s:%d:%d:%s:%s:%s\n",
           pw.name, pw.passwd, pw.uid, pw.gid,
           pw.gecos, pw.dir, pw.shell);
}
# rc == 2 (Return) → done iterating
```

### 2. `su - test` — login with passwd lookup

```
su command → getpwnam_r("test")
                │
                ├── result.uid = 1005
                ├── result.dir = "/home/test"
                └── result.shell = "/bin/bash"
                │
                ▼
mount /home/test (owned by uid 1005)
create process with uid=1005, gid=1005
```

### 3. PAM authentication chain

```
pam_authenticate(user, password)
    │
    ├── nss_getpwnam_r(user)    → Passwd entry
    ├── nss_getspnam_r(user)    → Shadow entry
    └── compare hashes
```

## Buffer Management

```
┌────────────────────────────────────────────────────────┐
│ Caller's buf (buflen bytes)                            │
│                                                        │
│  name      │ passwd  │ gecos   │ dir      │ shell      │
│ "root\0"   │ "$6$..  │ "Root\0"│ "/root   │ "/bin..    │
│ ↑          │ ↑       │ ↑       │ ↑        │ ↑          │
│ result→name│result   │result   │result.dir│result→shell│
│ (in buf)   │ (in buf)│(in buf) │ (in buf) │(in buf)    │
└────────────────────────────────────────────────────────┘
          ↑
     CBuffer::pos points here (next free byte)
```

## Rust Implementation Example

```rust
#[no_mangle]
unsafe extern "C" fn nss_example_getpwent_r(
    result: *mut CPasswd,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> c_int {
    let mut iter: MutexGuard<Iterator<Passwd>> =
        PASSWD_EXAMPLE_ITERATOR.lock().unwrap();
    let code: c_int = iter.next().to_c(result, buf, buflen, errnop) as c_int;
    if code == NssStatus::TryAgain as c_int {
        iter.previous();   /* backtrack on retry */
    }
    code
}
```
