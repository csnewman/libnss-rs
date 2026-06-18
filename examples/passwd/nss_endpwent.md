# nss_endpwent() — Terminate passwd Enumeration

## Rust Signature

```rust
fn endpwent() -> NssStatus;
// Called via:
// iter.close()
```

## C ABI Signature

```c
extern "C" {
    int nss_<name>_endpwent(void);
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
│  Application (getent, login, etc.)                       │
│      │                                                   │
│      ▼  Calls nss_<name>_endpwent()                      │
│  glibc NSS dispatcher                                    │
│      │                                                   │
│      ▼  iter.close()                                     │
│  lazy_static Mutex<Iterator<Passwd>>                     │
│      │                                                   │
│      ▼  items = None, index = 0                          │
│  Iterator state cleared — memory freed, ready for next   │
│  setpwent() to reopen a fresh iterator                   │
└──────────────────────────────────────────────────────────┘
```

**Step-by-step:**

1. **Application calls `nss_<name>_endpwent()`** — After finishing a series of
   `getpwent_r()` calls, the application signals it is done iterating.
2. **The `Iterator<Passwd>::close()` method is called** — This sets `items = None`
   (releasing the `VecDeque`) and resets `index = 0`.
3. **The next call to `getpwent_r()` will return `Unavail`** — Because `items` is `None`,
   the iterator reports that no entries are available.
4. **`setpwent()` can be called again to restart** — The iterator is reset to a clean state.

## Integration Examples

### 1. `getent passwd` — after iteration completes

```bash
# getent calls:
# 1. setpwent()      — load entries, iterator = Active
# 2. getpwent_r()     — entry 1
# 3. getpwent_r()     — entry 2
# ...
# n. getpwent_r()     — entry N (NotFound)
# n+1. endpwent()     — iterator = Closed, memory freed
```

### 2. Race condition handling

```
Thread A                  Thread B
──────                  ──────
getpwent_r() ────→      │
(same iterator)         │
                        │
                        setpwent()  — Thread A gets new entries
                        │
getpwent_r() ────→      │
(entries from Thread A) │
```

Because the iterator is protected by a `Mutex`, concurrent NSS calls on different threads
do not corrupt each other's state.

### 3. Cleanup before exit

```
Application shutdown flow:
1. setpwent()     — prepare for final read
2. getpwent_r()   — collect last entries
3. endpwent()     — clean up
4. exit()         — shared library unloaded
```

## Rust Implementation Example

```rust
#[no_mangle]
extern "C" fn nss_example_endpwent() -> c_int {
    let mut iter: MutexGuard<Iterator<Passwd>> =
        PASSWD_EXAMPLE_ITERATOR.lock().unwrap();
    iter.close() as c_int  // Returns NssStatus::Success (= 1)
}
```

## State Diagram

```
  Active ─────── endpwent() ──────→  Closed
   │                                        │
   │                                        │
   ▼                                        ▼
 getpwent_r()                             Closed
 returns NotFound                     (ready for setpwent)
```
