# nss_gethostent_r() — Get Next Host Entry

## Rust Signature

```rust
fn gethostent_r(
    result: *mut CHost,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> NssStatus;
```

## C ABI Signature

```c
extern "C" {
    int nss_<name>_gethostent_r(
        struct hostent *result,   /* output: host entry */
        char *buf,                /* input:  buffer */
        size_t buflen,            /* input:  buffer length */
        int *errnop,              /* output: error code */
    );
}
```

## Parameters

| Parameter | Direction | Type | Description |
|---|---|---|---|
| `result` | out | `*mut CHost` | Pointer to the host structure. |
| `buf` | in | `*mut c_char` | Caller-provided buffer. |
| `buflen` | in | `size_t` | Buffer size. |
| `errnop` | out | `*mut c_int` | Error number. |

## Return Value

| Value | Constant | Description |
|---|---|---|
| `1` | `NssStatus::Success` | Entry found. |
| `2` | `NssStatus::Return` | No more entries. |
| `-2` | `NssStatus::TryAgain` | Buffer too small. |

## C Host Struct Layout

```rust
#[repr(C)]
pub struct CHost {
    pub name:       *mut c_char,       /* canonical name     */
    pub h_aliases:  *mut *mut c_char,  /* alias list         */
    pub h_addrtype: c_int,             /* AF_INET or AF_INET6 */
    pub h_length:   c_int,             /* 4 (V4) or 16 (V6) */
    pub h_addr_list: *mut *mut c_char, /* address list       */
}
```

## How It Works

```
┌────────────────────────────────────────────────────┐
│  gethostent_r() call sequence                      │
│                                                    │
│  1. Application:                                   │
│     struct hostent he;                             │
│     char buf[4096];                                │
│     int err;                                       │
│     nss_example_gethostent_r(&he, buf,             │
│                              sizeof(buf), &err);   │
│                                                    │
│  2. libnss-rs flow:                                │
│     Iterator::next()  →  Response<Host>            │
│         ├── items.get(index)  →  Some(Host)        │
│         ├── index += 1                             │
│         └── Host::to_c(result, buf, buflen)        │
│              → name → buf (CString)                │
│              → aliases → buf (string array)        │
│              → addresses → buf (binary bytes)      │
│              → h_addrtype = AF_INET or AF_INET6    │
│              → h_length = 4 or 16                  │
│                                                    │
│  3. Result:                                        │
│     he.h_name       → "test.example"               │
│     he.h_aliases    → ["other.example", NULL]      │
│     he.h_addrtype   → AF_INET (=2)                 │
│     he.h_length     → 4                            │
│     he.h_addr_list  → [177.42.42.42, NULL]         │
└────────────────────────────────────────────────────┘
```

## Integration Examples

### 1. `getent hosts` — sequential enumeration

```bash
getent hosts
  │
  ├── sethostent()     — load entries
  ├── gethostent_r()   — "177.42.42.42 test.example"
  ├── gethostent_r()   — "127.0.0.1 localhost"
  └── endhostent()
```

### 2. `ping` — resolve hostname to IP

```
ping test.example
  │
  ├── gethostbyname_r("test.example", AF_UNSPEC)
  │
  ├── result:
  │   he.h_name = "test.example"
  │   he.h_addr_list[0] = 177.42.42.42
  │   he.h_addrtype = AF_INET
  │   he.h_length = 4
  │
  └── connect("177.42.42.42")
```

### 3. `traceroute` — resolve multiple hosts

```
traceroute test.example
  │
  ├── gethostbyname_r("test.example")
  │
  └── send packets to resolved IP
```

### 4. `nslookup` / `dig` — DNS-like lookup

```
nslookup test.example
  │
  ├── gethostbyname2_r("test.example", AF_INET)
  │
  └── output:
       Name: test.example
       Address: 177.42.42.42
```

## Rust Implementation Example

```rust
#[no_mangle]
unsafe extern "C" fn nss_example_gethostent_r(
    result: *mut CHost,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
) -> c_int {
    let mut iter: MutexGuard<Iterator<Host>> =
        HOST_EXAMPLE_ITERATOR.lock().unwrap();
    let code: c_int = iter.next().to_c(result, buf, buflen, errnop) as c_int;
    if code == NssStatus::TryAgain as c_int {
        iter.previous();
    }
    code
}
```
