# nss_gethostbyname3_r() — Lookup Host with TTL and Canonical Name

## Rust Signature

```rust
fn gethostbyname3_r(
    name: *const c_char,
    family: c_int,
    result: *mut CHost,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
    ttlp: *mut i32,
    canonp: *mut *const c_char,
) -> c_int;
```

## C ABI Signature

```c
extern "C" {
    struct hostent *nss_<name>_gethostbyname3_r(
        const char *name,           /* input:  hostname */
        int family,                 /* input:  address family */
        struct hostent *result,     /* output: host entry */
        char *buf,                  /* input:  buffer */
        size_t buflen,              /* input:  buffer length */
        int *errnop,                /* output: errno */
        int *h_errnop,              /* output: host error */
        int *ttlp,                  /* output: TTL (0 if null) */
        const char **canonp,        /* output: canonical name */
    );
}
```

## Parameters

| Parameter | Direction | Type | Description |
|---|---|---|---|
| `name` | in | `*const c_char` | Hostname to look up. |
| `family` | in | `c_int` | Address family (AF_INET, AF_INET6, AF_UNSPEC). |
| `result` | out | `*mut CHost` | Host entry structure. |
| `buf` | in | `*mut c_char` | Buffer for string allocation. |
| `buflen` | in | `size_t` | Buffer size. |
| `errnop` | out | `*mut c_int` | Standard errno. |
| `h_errnop` | out | `*mut c_int` | Host error code. |
| `ttlp` | out | `*mut i32` | TTL value (written as 0 when pointer is non-null). |
| `canonp` | out | `*mut *const c_char` | Canonical name pointer. |

## Additional Fields

| Field | Description |
|---|---|
| `ttlp` | Time-to-live for the resolved address. If null, not set. |
| `canonp` | Pointer to the canonical (official) hostname. If null, `name` is used. |

**Note:** TTL is always written as 0 when the pointer is non-null.

## How It Works

```
┌────────────────────────────────────────────────────┐
│  gethostbyname3_r("test.example", AF_UNSPEC)       │
│                                                    │
│  1. Application:                                   │
│     struct hostent he;                             │
│     int ttl;                                       │
│     const char *canon;                             │
│     char buf[4096];                                │
│     int err, h_err;                                │
│     nss_example_gethostbyname3_r(                  │
│         "test.example", AF_UNSPEC, &he, buf, 4096, │
│         &err, &h_err, &ttl, &canon);               │
│                                                    │
│  2. libnss-rs flow:                                │
│     gethostbyname3_r() delegates to:               │
│     gethostbyname2_r("test.example", AF_UNSPEC)    │
│         │                                          │
│         ├── Resolves hostname                      │
│         ├── Sets *ttlp = 0 (TTL value)             │
│         └── Sets *canonp = name (canonical name)   │
│                                                    │
│  3. Result:                                        │
│     he.h_name       → "test.example"               │
│     he.h_addrtype   → AF_INET                      │
│     he.h_length     → 4                            │
│     he.h_addr_list  → [177.42.42.42]               │
│     *ttlp           → 0                            │
│     *canonp         → "test.example"               │
└────────────────────────────────────────────────────┘
```

## Integration Examples

### 1. DNS-like resolution with TTL

```c
int ttl;
const char *canon;
struct hostent he;

struct hostent *result = gethostbyname3_r(
    "test.example", AF_INET, &he, buf, sizeof(buf),
    &err, &h_err, &ttl, &canon
);

if (result) {
    printf("Name: %s\n", result->h_name);
    printf("TTL: %d\n", ttl);           // 0 = no TTL info
    printf("Canonical: %s\n", canon);     // official hostname
}
```

### 2. Caching layer

```
// Applications use gethostbyname3_r() for DNS caching:
// 1. Check cache for (name, family)
// 2. If found, return cached TTL
// 3. If TTL expired, call gethostbyname3_r() to refresh
```

### 3. getent hosts with extended info

```bash
getent hosts test.example
  │
  ├── gethostbyname3_r("test.example", AF_UNSPEC)
  │   ├── gethostbyname2_r()  — resolve
  │   ├── *ttlp = 0            — TTL
  │   └── *canonp = name       — canonical name
  │
  └── output:
       177.42.42.42 test.example other.example
```

## Rust Implementation Example

```rust
#[no_mangle]
unsafe extern "C" fn nss_example_gethostbyname3_r(
    name: *const c_char,
    family: c_int,
    result: *mut CHost,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
    ttlp: *mut i32,
    canonp: *mut *const c_char,
) -> c_int {
    let name2_res = nss_example_gethostbyname2_r(
        name, family, result, buf, buflen, errnop, h_errnop
    );

    // Set TTL (0 = no TTL)
    if !ttlp.is_null() {
        *ttlp = 0;
    }

    // Set canonical name pointer
    if !canonp.is_null() {
        *canonp = name;
    }

    name2_res
}
```
