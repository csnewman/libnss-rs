# nss_getspent_r() — Get Next Shadow Entry

## Rust Signature

```rust
fn getspent_r(
    result: *mut CShadow,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> NssStatus;
```

The Rust trait method:
```rust
fn get_all_entries() -> Response<Vec<Shadow>>;
```

## C ABI Signature

```c
extern "C" {
    int nss_<name>_getspent_r(
        struct spwd *result,     /* output: shadow entry */
        char *buf,               /* input:  caller's buffer */
        size_t buflen,           /* input:  buffer length */
        int *errnop,             /* output: error code */
    );
}
```

## Parameters

| Parameter | Direction | Type | Description |
|---|---|---|---|
| `result` | out | `*mut CShadow` | Pointer to the shadow structure to fill. |
| `buf` | in | `*mut c_char` | Caller-provided buffer for C-string allocation. |
| `buflen` | in | `size_t` | Size of `buf` in bytes. |
| `errnop` | out | `*mut c_int` | Error number (0 = success). |

## Return Value

| Value | Constant | Description |
|---|---|---|
| `1` | `NssStatus::Success` | Entry found, `result` filled. |
| `2` | `NssStatus::Return` | No more entries. |
| `-2` | `NssStatus::TryAgain` | Buffer too small. |
| `-1` | `NssStatus::Unavail` | Temporary failure. |

## C Shadow Struct Layout

```rust
#[repr(C)]
pub struct CShadow {
    pub name:            *mut c_char,   /* username              */
    pub passwd:          *mut c_char,   /* encrypted password   */
    pub last_change:     c_long,        /* days since 1970-01-01 */
    pub change_min_days: c_long,        /* min days between changes */
    pub change_max_days: c_long,        /* max days between changes */
    pub change_warn_days: c_long,       /* days to warn          */
    pub change_inactive_days: c_long,   /* days after expiry until disable */
    pub expire_date:     c_long,        /* absolute expiry date */
    pub reserved:        c_ulong,       /* reserved (unused)    */
}
```

## How It Works

```
┌──────────────────────────────────────────────────────────┐
│  getspent_r() call sequence                              │
│                                                          │
│  1. Application:                                         │
│     struct spwd sp;                                      │
│     char buf[2048];                                      │
│     int err;                                             │
│     nss_example_getspent_r(&sp, buf, 2048, &err);        │
│                                                          │
│  2. libnss-rs flow:                                      │
│     Iterator::next()  →  Response<Shadow>                │
│         ├── items.get(index)  →  Some(Shadow)            │
│         ├── index += 1                                   │
│         └── Shadow::to_c(result, buf, buflen)            │
│              → name, passwd → buf (CStrings)             │
│              → last_change → c_long                      │
│              → change_min/max → c_long                   │
│              → change_warn/expire → c_long               │
│                                                          │
│  3. Result:                                              │
│     sp.name     → "test"      sp.last_change  → 18660    │
│     sp.passwd   → "$6$hash"   sp.min_days     → 0        │
│     sp.max_days → 99999       sp.warn_days   → 7         │
│     sp.inact_days → -1        sp.expire_date → -1        │
└──────────────────────────────────────────────────────────┘
```

## Integration Examples

### 1. `passwd` — password management

```
passwd test
  │
  ├── setspent()       — load entries
  ├── getspent_r()    — find "test" entry
  │   │
  │   ├── sp.name = "test"
  │   ├── sp.passwd = "$6$oldhash"
  │   ├── sp.last_change = 18660
  │   └── sp.max_days = 99999
  │
  ├── validate password
  ├── update passwd field
  │
  └── Write back to backend
```

### 2. PAM account validation

```
pam_acct_mgmt(PAM_USER="test")
  │
  ├── getspnam_r("test")
  │   ├── sp.last_change → 18660
  │   ├── sp.expire_date → -1
  │   └── sp.inactive → -1
  │
  ├── Check if account expired:
  │   ├── if expire_date != -1  &&  days_since(1970) > expire_date
  │   │   → PAM_ACCT_EXPIRED
  │   ├── if inactive != -1     &&  days_since(last_change) > expire + inactive
  │   │   → PAM_ACCT_EXPIRED
  │   └── else
  │       → PAM_SUCCESS
  │
  └── endspent()
```

### 3. `chage` — change password aging

```
chage -l test
  │
  ├── getspnam_r("test")
  │
  └── output:
       Last password change       : Jan 01, 2024
       Password expires           : never
       Password inactive          : never
       Minimum password age       : 0
       Maximum password age       : 99999
       Warning period               : 7
```

## Rust Implementation Example

```rust
#[no_mangle]
unsafe extern "C" fn nss_example_getspent_r(
    result: *mut CShadow,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> c_int {
    let mut iter: MutexGuard<Iterator<Shadow>> =
        SHADOW_EXAMPLE_ITERATOR.lock().unwrap();
    let code: c_int = iter.next().to_c(result, buf, buflen, errnop) as c_int;
    if code == NssStatus::TryAgain as c_int {
        iter.previous();
    }
    code
}
```
