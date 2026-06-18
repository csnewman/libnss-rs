# NssStatus — NSS Return Status Codes

## Rust Definition

```rust
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NssStatus {
    TryAgain  = -2,   // Buffer too small, caller should retry with larger buffer
    Unavail   = -1,   // Temporary server failure, try again later
    NotFound  = 0,    // Entry not found
    Success   = 1,    // Operation succeeded
    Return    = 2,    // No more data (iterator exhausted)
}
```

## Mapping to C

The NSS library maps Rust's `NssStatus` enum to C-compatible integer values that glibc
interprets as standard NSS status codes.

| Rust Variant | C Value | C Equivalent | Meaning |
|---|---|---|---|
| `TryAgain` | `-2` | `NSS_TRYAGAIN` | Buffer too small, retry with larger buffer. |
| `Unavail` | `-1` | `NSS_UNAVAIL` | Temporary server failure. |
| `NotFound` | `0` | `NSS_NOTFOUND` | Entry does not exist. |
| `Success` | `1` | `NSS_SUCCESS` | Operation completed successfully. |
| `Return` | `2` | `NSS_RETURN` | No more data available (iterator done). |

## Usage Pattern

```rust
use libnss::interop::NssStatus;

// Check status code returned from NSS call
fn handle_status(status: NssStatus) {
    match status {
        NssStatus::Success   => { /* Got result, entry filled */ },
        NssStatus::Return    => { /* Done iterating, no more entries */ },
        NssStatus::TryAgain  => { /* Need larger buffer, retry */ },
        NssStatus::Unavail   => { /* Temporary issue, may succeed on retry */ },
        NssStatus::NotFound  => { /* Entry exists but was not found */ },
    }
}
```

## Integration

### 1. glibc NSS dispatcher

```
glibc calls NSS module:
  rc = nss_example_getpwent_r(&pw, buf, buflen, &errnop)

glibc interprets:
  rc == 1  → NSS_SUCCESS → use pw
  rc == 0  → NSS_NOTFOUND → no matching entry
  rc == -2 → NSS_TRYAGAIN → enlarge buf, retry
  rc == -1 → NSS_UNAVAIL → try again later
  rc == 2  → NSS_RETURN → done iterating
```

### 2. Error chain in Rust

```
Response<T>  maps to  NssStatus:

  Response::Success(t)  →  NssStatus::Success
  Response::NotFound    →  NssStatus::NotFound
  Response::TryAgain    →  NssStatus::TryAgain
  Response::Unavail     →  NssStatus::Unavail
  Response::Return      →  NssStatus::Return
```

### 3. to_c() — Rust Response to C conversion

```rust
// When Response::Success(entity) is returned:
// 1. entity.to_c(result, buf, buflen, errnop) converts Rust struct to C layout
// 2. If conversion succeeds → NssStatus::Success
// 3. If conversion fails (buffer overflow) → NssStatus::TryAgain
// 4. If raw_os_error is None → NssStatus::Unavail

// When Response::NotFound is returned:
// 1. No buffer conversion needed
// 2. Returns NssStatus::NotFound directly

// When Response::TryAgain is returned:
// 1. Returns NssStatus::TryAgain directly
// 2. Caller should retry with larger buffer
```
