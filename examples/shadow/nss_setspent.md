# nss_setspent() — Start/Reset shadow Enumeration

## Rust Signature

```rust
fn spent() -> NssStatus;
// Called via:
// <super::$hooks_ident as ShadowHooks>::get_all_entries()
// iter.open(entries)
```

## C ABI Signature

```c
extern "C" {
    int nss_<name>_setspent(void);
}
```

## Parameters

| Parameter | Direction | Type | Description |
|---|---|---|---|
| *(none)* | — | — | No input parameters. |

## Return Value

| Value | Constant | Description |
|---|---|---|
| `1` | `NssStatus::Success` | Entries loaded successfully, iterator ready. |
| `-2` | `NssStatus::TryAgain` | Buffer too small, retry. |
| `-1` | `NssStatus::Unavail` | Temporary server failure. |
| `0` | `NssStatus::NotFound` | No entries available. |

## How It Works

```
┌──────────────────────────────────────────────────────────┐
│  setspent() — Reset shadow iterator                      │
│                                                          │
│  Application (e.g., getent shadow)                       │
│      │                                                   │
│      ▼  Calls nss_<name>_setspent()                      │
│  glibc NSS dispatcher                                    │
│      │                                                   │
│      ▼  ShadowHooks::get_all_entries()                   │
│  Your Rust implementation                                │
│      │                                                   │
│      ▼  iter.open(Vec<Shadow>)                           │
│  lazy_static Mutex<Iterator<Shadow>>                     │
│      │                                                   │
│      ▼  Iterator ready for getspent_r() calls            │
└──────────────────────────────────────────────────────────┘
```

**Step-by-step:**

1. Application calls `nss_<name>_setspent()`.
2. Your `ShadowHooks::get_all_entries()` fetches all shadow entries.
3. The `lazy_static Mutex<Iterator<Shadow>>` is updated — entries loaded, index reset to 0.
4. Subsequent `getspent_r()` calls return entries sequentially.

## Integration Examples

### 1. `getent shadow` — enumerate all shadow entries

```bash
# Application calls:
# 1. setspent()     — load all entries
# 2. getspent_r()  — get entry 1
# 3. getspent_r()  — get entry 2
# ...
# n. getspent_r()  — TryAgain (exhausted)
# n+1. endspent()  — close iterator
```

### 2. `passwd` command — password change

```
passwd test
  │
  ├── setspent()     — load shadow entries
  ├── getspent_r()  — find entry with name=="test"
  │
  ├── verify current password hash
  ├── setspent()     — reset for write
  ├── getspent_r()  — get "test" entry
  │
  └── Write new password to backend
```

### 3. Privileged password access

```
// Shadow entries are only visible to privileged users.
// The NSS module can check geteuid() == 0 before returning results.

// Example: unprivileged process sees:
setspent()  →  Response::Unavail  // (no shadow data)

// Privileged process sees:
setspent()  →  Response::Success(entries)
```

## Rust Implementation Example

```rust
use libnss::shadow::{Shadow, ShadowHooks};
use libnss::interop::Response;
use libnss::libnss_shadow_hooks;

struct ExampleShadow;
libnss_shadow_hooks!(example, ExampleShadow);

impl ShadowHooks for ExampleShadow {
    fn get_all_entries() -> Response<Vec<Shadow>> {
        Response::Success(vec![
            Shadow {
                name: "root".to_string(),
                passwd: "$6$rounds=656000$salt$hash".to_string(),
                last_change: 18660,
                change_min_days: 0,
                change_max_days: 99999,
                change_warn_days: 7,
                change_inactive_days: -1,
                expire_date: -1,
                reserved: 0,
            },
            Shadow {
                name: "test".to_string(),
                passwd: "$6$KEnq4G3CxkA2iU$hash".to_string(),
                last_change: 18660,
                change_min_days: 0,
                change_max_days: 99999,
                change_warn_days: 7,
                change_inactive_days: -1,
                expire_date: -1,
                reserved: 0,
            },
        ])
    }
    // ... get_entry_by_name
}
```
