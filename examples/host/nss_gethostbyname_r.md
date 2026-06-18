# nss_gethostbyname_r() — Lookup Host by Name

## Rust Signature

```rust
fn gethostbyname_r(
    name: *const c_char,
    result: *mut CHost,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
) -> c_int;
```

Delegates to `gethostbyname2_r(name, AF_UNSPEC, ...)`.

## C ABI Signature

```c
extern "C" {
    struct hostent *nss_<name>_gethostbyname_r(
        const char *name,           /* input:  hostname */
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
| `result` | out | `*mut CHost` | Pointer to the host structure. |
| `buf` | in | `*mut c_char` | Caller-provided buffer. |
| `buflen` | in | `size_t` | Buffer size. |
| `errnop` | out | `*mut c_int` | Standard errno. |
| `h_errnop` | out | `*mut c_int` | Host error code. |

## How It Works

```
┌────────────────────────────────────────────────────┐
│  gethostbyname_r("test.example")                   │
│                                                    │
│  1. Application:                                   │
│     struct hostent he;                             │
│     char buf[4096];                                │
│     int err, h_err;                                │
│     nss_example_gethostbyname_r(                   │
│         "test.example", &he, buf, 4096,            │
│         &err, &h_err);                             │
│                                                    │
│  2. libnss-rs flow:                                │
│     gethostbyname_r("test.example")                │
│         │                                          │
│         └── delegates to gethostbyname2_r(         │
│               "test.example",                      │
│               AF_UNSPEC  ← try both V4 and V6)     │
│         │                                          │
│         ├── try AF_INET (IPv4) first               │
│         ├── if not found, try AF_INET6 (IPv6)      │
│         └── return first match                     │
│                                                    │
│  3. Result:                                        │
│     he.h_name       → "test.example"               │
│     he.h_aliases    → ["other.example", NULL]      │
│     he.h_addrtype   → AF_INET (2)                  │
│     he.h_length     → 4                            │
│     he.h_addr_list  → [177.42.42.42, NULL]         │
│     *h_errnop       → NetDbSuccess (0)             │
└────────────────────────────────────────────────────┘
```

## Integration Examples

### 1. Standard hostname resolution

```c
// gethostbyname_r is the traditional POSIX function
struct hostent *he = gethostbyname_r("test.example", &buf, &h_err);
if (he) {
    printf("%s → %s\n", he->h_name, inet_ntoa(*he->h_addr_list));
    // output: test.example → 177.42.42.42
}
```

### 2. getent hosts lookup

```bash
getent hosts test.example
  │
  ├── gethostbyname_r("test.example")
  │
  └── output:
       177.42.42.42 test.example other.example
```

### 3. Connection establishment

```
connect("test.example", port=80)
  │
  ├── gethostbyname_r("test.example")
  │   ├── h_name = "test.example"
  │   ├── h_addr_list[0] = 177.42.42.42
  │
  └── connect(AF_INET, 177.42.42.42:80)
```

## Rust Implementation Example

```rust
#[no_mangle]
unsafe extern "C" fn nss_example_gethostbyname_r(
    name: *const c_char,
    result: *mut CHost,
    buf: *mut c_char,
    buflen: size_t,
    errnop: *mut c_int,
    h_errnop: *mut c_int,
) -> c_int {
    // Delegates to gethostbyname2_r with AF_UNSPEC
    nss_example_gethostbyname2_r(
        name, libc::AF_UNSPEC, result, buf, buflen, errnop, h_errnop
    )
}
```
