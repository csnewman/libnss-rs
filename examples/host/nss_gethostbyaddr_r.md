# nss_gethostbyaddr_r() — Lookup Host by IP Address

## Rust Signature

```rust
fn gethostbyaddr_r(
    addr: *const c_char,
    len: size_t,
    format: c_int,
    result: *mut CHost,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
) -> NssStatus;
```

## C ABI Signature

```c
extern "C" {
    struct hostent *nss_<name>_gethostbyaddr_r(
        const char *addr,           /* input:  IP address bytes */
        int len,                    /* input:  address length (4 or 16) */
        int format,                 /* input:  AF_INET or AF_INET6 */
        struct hostent *result,     /* output: host entry */
        char *buf,                  /* input:  buffer */
        size_t buflen,              /* input:  buffer length */
        int *errnop,                /* output: errno code */
        int *h_errnop,              /* output: host error code */
    );
}
```

Note: While the C ABI declares `struct hostent *`, the actual Rust implementation returns
`c_int` (status code). The NSS convention uses the return value as a status code while
the `result` pointer serves as the output hostent.

## Parameters

| Parameter | Direction | Type | Description |
|---|---|---|---|
| `addr` | in | `*const c_char` | IP address bytes (4 for IPv4, 16 for IPv6). |
| `len` | in | `size_t` | Length of `addr` in bytes. |
| `format` | in | `c_int` | Address family (AF_INET=2, AF_INET6=10). |
| `result` | out | `*mut CHost` | Pointer to the host structure. |
| `buf` | in | `*mut c_char` | Caller-provided buffer. |
| `buflen` | in | `size_t` | Buffer size. |
| `errnop` | out | `*mut c_int` | Standard errno. |
| `h_errnop` | out | `*mut c_int` | Host-specific error code. |

## herrno Values (internal)

| Value | Constant | Description |
|---|---|---|
| `-1` | `NetDbInternal` | Internal error. |
| `0` | `NetDbSuccess` | Success. |
| `2` | `TryAgain` | Try again later. |
| `3` | `NoRecovery` | Non-recoverable error. |
| `4` | `NoData` | No address for name. |

## How It Works

```
┌────────────────────────────────────────────────────┐
│  gethostbyaddr_r("177.42.42.42", 4, AF_INET)       │
│                                                    │
│  1. Application:                                   │
│     char addr[4] = {177, 42, 42, 42};              │
│     struct hostent he;                             │
│     char buf[4096];                                │
│     int err, h_err;                                │
│     nss_example_gethostbyaddr_r(                   │
│         addr, 4, AF_INET, &he, buf, 4096,          │
│         &err, &h_err);                             │
│                                                    │
│  2. libnss-rs flow:                                │
│     ┌──────────────────────────────────────────┐   │
│     │ Step 1: memcpy(addr, buf, 4)             │   │
│     │ Step 2: IpAddr::V4(Ipv4Addr::from(buf))  │   │
│     │ Step 3: HostHooks::get_host_by_addr()    │   │
│     │         → Compare addr == stored addr    │   │
│     │ Step 4: Response::to_c(result, buf)      │   │
│     └──────────────────────────────────────────┘   │
│                                                    │
│  3. Result:                                        │
│     he.h_name       → "test.example"               │
│     he.h_addrtype   → AF_INET (2)                  │
│     he.h_length     → 4                            │
│     he.h_addr_list  → [177.42.42.42]               │
│     *h_errnop       → NetDbSuccess (0)             │
└────────────────────────────────────────────────────┘
```

## Integration Examples

### 1. `getent hosts` — reverse lookup

```bash
getent hosts 177.42.42.42
  │
  ├── gethostbyaddr_r("177.42.42.42", 4, AF_INET)
  │
  └── output:
       177.42.42.42 test.example test.example other.example
```

### 2. DNS reverse resolution

```
nslookup 177.42.42.42
  │
  ├── gethostbyaddr_r("177.42.42.42", 4, AF_INET)
  │   ├── h_name = "test.example"
  │   ├── h_aliases = ["other.example"]
  │   └── h_addr_list = [177.42.42.42]
  │
  └── output:
       42.42.42.177.in-addr.arpa   name = test.example
```

### 3. IPv6 address lookup

```
gethostbyaddr_r(::1, 16, AF_INET6)
  │
  ├── len = 16 (IPv6)
  ├── format = AF_INET6 (10)
  ├── memcpy into Ipv6Addr
  └── HostHooks::get_host_by_addr()
```

## Rust Implementation Example

```rust
#[no_mangle]
unsafe extern "C" fn nss_example_gethostbyaddr_r(
    addr: *const c_char,
    len: size_t,
    format: c_int,
    result: *mut CHost,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
) -> c_int {
    *h_errnop = Herrno::NetDbInternal;

    let a = match (len, format) {
        (4, libc::AF_INET) => {
            let mut p = [0u8; 4];
            libc::memcpy(p.as_ptr() as *mut c_void, addr as *mut c_void, 4);
            IpAddr::V4(Ipv4Addr::from(p))
        },
        (16, libc::AF_INET6) => {
            let mut p = [0u8; 16];
            libc::memcpy(p.as_ptr() as *mut c_void, addr as *mut c_void, 16);
            IpAddr::V6(Ipv6Addr::from(p))
        },
        _ => return NssStatus::NotFound,
    };

    match ExampleHost::get_host_by_addr(a) {
        response @ Response::Success(..) => {
            *h_errnop = Herrno::NetDbSuccess;
            response
        },
        response => response,
    }.to_c(result, buf, buflen, errnop)
}
```
