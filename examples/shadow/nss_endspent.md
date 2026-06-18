# nss_endspent() — Terminate shadow Enumeration

## Rust Signature

```rust
fn endspent() -> NssStatus;
// Called via:
// iter.close()
```

## C ABI Signature

```c
extern "C" {
    int nss_<name>_endspent(void);
}
```

## Parameters

| Parameter | Direction | Type | Description |
|---|---|---|---|
| *(none)* | — | — | No input parameters. |

## Return Value

| Value | Constant | Description |
|---|---|---|
| `1` | `NssStatus::Success` | Iterator closed successfully. |

## How It Works

```
┌──────────────────────────────────────────────────────────┐
│  endspent() — Close shadow iterator                      │
│                                                          │
│  Application (getent shadow)                             │
│      │                                                   │
│      ▼  Calls nss_<name>_endspent()                      │
│  glibc NSS dispatcher                                    │
│      │                                                   │
│      ▼  iter.close()                                     │
│  lazy_static Mutex<Iterator<Shadow>>                     │
│      │                                                   │
│      ▼  items = None, index = 0                          │
│  Memory freed, iterator ready for next spent() call      │
└──────────────────────────────────────────────────────────┘
```

## Integration Examples

### 1. `getent shadow` — cleanup after enumeration

```bash
getent shadow
  │
  ├── setspent()     — load entries
  ├── getspent_r()  — iterate all entries
  │
  └── endspent()     — free iterator, done
```

### 2. PAM shadow validation

```
pam_acct_mgmt()
  │
  ├── getspnam_r("test")  — lookup shadow entry
  ├── Compare expire_date, inactive_days          │
  │
  └── endspent()     — clean up
```

## Rust Implementation Example

```rust
#[no_mangle]
extern "C" fn nss_example_endspent() -> c_int {
    let mut iter: MutexGuard<Iterator<Shadow>> =
        SHADOW_EXAMPLE_ITERATOR.lock().unwrap();
    iter.close() as c_int  // Returns 1 (Success)
}
```
