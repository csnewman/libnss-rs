# nss_sethostent() — Start/Reset Host Enumeration

## Rust Signature

```rust
fn sethostent() -> NssStatus;
// Called via:
// <super::$hooks_ident as HostHooks>::get_all_entries()
// iter.open(entries)
```

## C ABI Signature

```c
extern "C" {
    int nss_<name>_sethostent(void);
}
```

## Parameters

| Parameter | Direction | Type | Description |
|---|---|---|---|
| *(none)* | — | — | No input parameters. |

## Return Value

| Value | Constant | Description |
|---|---|---|
| `1` | `NssStatus::Success` | Entries loaded. |
| `-2` | `NssStatus::TryAgain` | Buffer too small. |
| `-1` | `NssStatus::Unavail` | Temporary failure. |

## How It Works

```
┌────────────────────────────────────────────────────┐
│  sethostent() — Reset host iterator                │
│                                                    │
│  Application (getent hosts)                        │
│      │                                             │
│      ▼  Calls nss_<name>_sethostent()              │
│  glibc NSS dispatcher                              │
│      │                                             │
│      ▼  HostHooks::get_all_entries()               │
│  Your Rust implementation                          │
│      │                                             │
│      ▼  iter.open(Vec<Host>)                       │
│  lazy_static Mutex<Iterator<Host>>                 │
│      │                                             │
│      ▼  Iterator ready for gethostent_r()          │
└────────────────────────────────────────────────────┘
```

## Integration Examples

### 1. `getent hosts` — enumerate all hosts

```bash
getent hosts
  │
  ├── sethostent()   — load entries
  ├── gethostent_r()  — host 1
  ├── gethostent_r()  — host 2
  │
  └── endhostent()   — close
```

### 2. `ping` — hostname resolution

```
ping test.example
  │
  ├── gethostbyname_r("test.example", AF_UNSPEC)
  │
  └── 177.42.42.42 test.example
```

## Rust Implementation Example

```rust
#[no_mangle]
extern "C" fn nss_example_sethostent() -> c_int {
    let mut iter: MutexGuard<Iterator<Host>> =
        HOST_EXAMPLE_ITERATOR.lock().unwrap();
    let status = match(ExampleHost::get_all_entries()) {
        Response::Success(entries) => iter.open(entries),
        response => response.to_status(),
    };
    status as c_int
}
```
