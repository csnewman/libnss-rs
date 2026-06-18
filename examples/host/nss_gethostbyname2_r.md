# nss_gethostbyname2_r() — Lookup Host by Name with Address Family

## Rust Signature

```rust
fn gethostbyname2_r(
    name: *const c_char,
    family: c_int,
    result: *mut CHost,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
) -> c_int;
```

## C ABI Signature

```c
extern "C" {
    struct hostent *nss_<name>_gethostbyname2_r(
        const char *name,           /* input:  hostname */
        int family,                 /* input:  AF_INET, AF_INET6, AF_UNSPEC */
        struct hostent *result,     /* output: host entry */
        char *buf,                  /* input:  buffer */
        size_t buflen,              /* input:  buffer length */
        int *errnop,                /* output: errno */
        int *h_errnop,              /* output: host error */
    );
}
```

## Parameters

| Parameter | Direction | Type | Description |
|---|---|---|---|
| `name` | in | `*const c_char` | C string of hostname. |
| `family` | in | `c_int` | Address family filter. |
| `result` | out | `*mut CHost` | Pointer to the host structure. |
| `buf` | in | `*mut c_char` | Buffer for string allocation. |
| `buflen` | in | `size_t` | Buffer size. |
| `errnop` | out | `*mut c_int` | Standard errno. |
| `h_errnop` | out | `*mut c_int` | Host error code. |

## Address Family Constants

| Constant | Value | Description |
|---|---|---|
| `AF_INET` | `2` | IPv4 only. |
| `AF_INET6` | `10` | IPv6 only. |
| `AF_UNSPEC` | `0` | Try both (IPv4 first, then IPv6). |

## How It Works

```
┌────────────────────────────────────────────────────┐
│  gethostbyname2_r("test.example", AF_INET)         │
│                                                    │
│  1. Application:                                   │
│     struct hostent he;                             │
│     int family = AF_INET;                          │
│     char buf[4096];                                │
│     int err, h_err;                                │
│     nss_example_gethostbyname2_r(                  │
│         "test.example", family, &he, buf, 4096,    │
│         &err, &h_err);                             │
│                                                    │
│  2. libnss-rs flow:                                │
│     ┌──────────────────────────────────────────┐   │
│     │ Step 1: CStr::from_ptr(name_)            │   │
│     │ Step 2: HostHooks::get_host_by_name(     │   │
│     │           name, AddressFamily)           │   │
│     │ Step 3: Family mapping:                  │   │
│     │   AF_INET  → AddressFamily::IPv4         │   │
│     │   AF_INET6 → AddressFamily::IPv6         │   │
│     │   AF_UNSPEC → try IPv4, then IPv6        │   │
│     │ Step 4: Response::to_c(result, buf, ...) │   │
│     └──────────────────────────────────────────┘   │
│                                                    │
│  3. Result (IPv4):                                 │
│     he.h_name       → "test.example"               │
│     he.h_addrtype   → AF_INET                      │
│     he.h_length     → 4                            │
│     he.h_addr_list  → [177.42.42.42]               │
└────────────────────────────────────────────────────┘
```

## Family Resolution Logic

```
                    family = AF_UNSPEC
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
    get_host_by_name(V4)    if not found
              │                 ▼
              ▼            get_host_by_name(V6)
    if found?            (try IPv6)
    /       \
   yes       no        ┌──────────────┐
    │         │        │ Return       │
    │         │        │ V6 result    │
    ▼         ▼        └──────────────┘
 Return V4  Return V6
```

## Integration Examples

### 1. Explicit family lookup

```c
// IPv4 only
struct hostent he4;
nss_example_gethostbyname2_r(
    "test.example", AF_INET, &he4, buf, sizeof(buf), &err, &h_err
);
// he4.h_addrtype = AF_INET, he4.h_length = 4

// IPv6 only
struct hostent he6;
nss_example_gethostbyname2_r(
    "test.example", AF_INET6, &he6, buf, sizeof(buf), &err, &h_err
);
// he6.h_addrtype = AF_INET6, he6.h_length = 16
```

### 2. getent with explicit family

```bash
getent hosts test.example
  │
  ├── gethostbyname2_r("test.example", AF_UNSPEC)
  │   └── tries IPv4 first, then IPv6
  │
  └── output:
       177.42.42.42 test.example
```

### 3. Dual-stack resolution

```
gethostbyname2_r("test.example", AF_UNSPEC)
  │
  ├── IPv4 found → return immediately
  ├── IPv4 not found → try IPv6
  │
  └── Returns:
       if IPv4: {name, aliases, [v4_addr], AF_INET, 4}
       if IPv6: {name, aliases, [v6_addr], AF_INET6, 16}
```

## Rust Implementation Example

```rust
#[no_mangle]
unsafe extern "C" fn nss_example_gethostbyname2_r(
    name: *const c_char,
    family: c_int,
    result: *mut CHost,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
) -> c_int {
    let cstr = CStr::from_ptr(name);
    let status = match str::from_utf8(cstr.to_bytes()) {
        Ok(name) => {
            use AddressFamily::{IPv4, IPv6};

            let status = match family {
                libc::AF_INET =>
                    ExampleHost::get_host_by_name(&name, IPv4),
                libc::AF_INET6 =>
                    ExampleHost::get_host_by_name(&name, IPv6),
                libc::AF_UNSPEC =>
                    match ExampleHost::get_host_by_name(&name, IPv4) {
                        Response::NotFound =>
                            ExampleHost::get_host_by_name(&name, IPv6),
                        val => val,
                    },
                _ => {
                    *h_errnop = Herrno::NoRecovery;
                    Response::Unavail
                },
            }.to_c(result, buf, buflen, errnop);

            match status {
                NssStatus::Success => {
                    *h_errnop = Herrno::NetDbSuccess
                }
                NssStatus::TryAgain => {
                    *h_errnop = Herrno::TryAgain
                }
                NssStatus::Unavail => {
                    *h_errnop = Herrno::NoRecovery
                }
                NssStatus::NotFound => {
                    *h_errnop = Herrno::NoData
                }
                _ => {
                    *h_errnop = Herrno::NetDbInternal
                }
            };

            status
        }
        Err(_) => NssStatus::NotFound
    };

    status
}
```
