# nss_setgrent() — Start/Reset group Enumeration

## Rust Signature

```rust
fn setgrent() -> NssStatus;
// Called via:
// <super::$hooks_ident as GroupHooks>::get_all_entries()
// iter.open(records)
```

## C ABI Signature

```c
extern "C" {
    int nss_<name>_setgrent(void);
}
```

## Parameters

| Parameter | Direction | Type | Description |
|---|---|---|---|
| *(none)* | — | — | No input parameters. |

## Return Value

| Value | Constant | Description |
|---|---|---|
| `1` | `NssStatus::Success` | Entries loaded, iterator ready. |
| `-2` | `NssStatus::TryAgain` | Buffer too small. |
| `-1` | `NssStatus::Unavail` | Temporary failure. |

## How It Works

```
┌──────────────────────────────────────────────────────────┐
│  setgrent() — Reset group iterator                       │
│                                                          │
│  Application (getent group)                              │
│      │                                                   │
│      ▼  Calls nss_<name>_setgrent()                      │
│  glibc NSS dispatcher                                    │
│      │                                                   │
│      ▼  GroupHooks::get_all_entries()                    │
│  Your Rust implementation                                │
│      │                                                   │
│      ▼  iter.open(Vec<Group>)                            │
│  lazy_static Mutex<Iterator<Group>>                      │
│      │                                                   │
│      ▼  Iterator ready for getgrent_r() calls            │
└──────────────────────────────────────────────────────────┘
```

## Integration Examples

### 1. `getent group` — enumerate all groups

```bash
getent group
  │
  ├── setgrent()      — load all entries
  ├── getgrent_r()   — group 1
  ├── getgrent_r()   — group 2
  │
  └── endgrent()      — close
```

### 2. Group membership resolution

```
id test
  │
  ├── setgrent()     — load groups
  ├── getgrent_r()  — find group where members contains "test"
  └── return all matching groups
```

## Rust Implementation Example

```rust
#[no_mangle]
extern "C" fn nss_example_setgrent() -> c_int {
    let mut iter: MutexGuard<Iterator<Group>> =
        GROUP_EXAMPLE_ITERATOR.lock().unwrap();
    let status = match(ExampleGroup::get_all_entries()) {
        Response::Success(records) => iter.open(records),
        response => response.to_status(),
    };
    status as c_int
}
```
