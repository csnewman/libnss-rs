# Response\<R\> — NSS Response Wrapper

## Rust Definition

```rust
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Response<R> {
    TryAgain,
    Unavail,
    NotFound,
    Success(R),
    Return,
}
```

## Type Parameters

| Parameter | Type | Description |
|---|---|---|
| `R` | `Passwd`, `Shadow`, `Group`, `Host`, `Vec<Passwd>` | The actual data payload. |

## Variant Mapping

| Variant | Data | C NssStatus | Use Case |
|---|---|---|---|
| `Success(R)` | Contains data | `1` (Success) | Entry found, result populated. |
| `NotFound` | None | `0` (NotFound) | No entry matching the query. |
| `TryAgain` | None | `-2` (TryAgain) | Buffer too small, retry with larger. |
| `Unavail` | None | `-1` (Unavail) | Temporary failure, may succeed later. |
| `Return` | None | `2` (Return) | Iterator exhausted, no more data. |

## Conversion to C

```rust
impl<R> Response<R> {
    pub fn to_status(&self) -> NssStatus;

    pub unsafe fn to_c<C>(
        &self,
        result: *mut C,
        buf: *mut c_char,
        buflen: size_t,
        errnop: *mut c_int,
    ) -> NssStatus
    where
        R: ToC<C>,
    {
        if let Self::Success(entity) = self {
            let mut buffer = CBuffer::new(buf as *mut c_void, buflen);
            buffer.clear();

            match entity.to_c(result, &mut buffer) {
                Ok(()) => {
                    *errnop = 0;
                    self.to_status()
                }
                Err(e) => match e.raw_os_error() {
                    Some(e) => {
                        *errnop = e;
                        Self::TryAgain.to_status()
                    }
                    None => {
                        *errnop = libc::ENOENT;
                        Self::Unavail.to_status()
                    }
                },
            }
        } else {
            self.to_status()
        }
    }
}
```

## Integration Examples

### 1. Error handling chain

```
Application call → Your Rust impl → Response → C NssStatus

passwd lookup:
  getpwuid_r(1005)
    → get_entry_by_uid(1005)
      → Response::Success(Passwd { name: "test", ... })
        → NssStatus::Success (1)
        → errnop = 0

shadow lookup:
  getspnam_r("unknown")
    → get_entry_by_name("unknown")
      → Response::NotFound
        → NssStatus::NotFound (0)
        → errnop = 0
```

### 2. Buffer overflow handling

```
getpwent_r(&pw, small_buf, 100, &err)
  → Success(Passwd)
    → to_c() called with small buffer
    → CBuffer.write_str() detects overflow
    → Response::TryAgain
      → NssStatus::TryAgain (-2)
      → errnop = ERANGE

Application should retry:
  getpwent_r(&pw, large_buf, 4096, &err)
    → Success(Passwd)
      → NssStatus::Success (1)
      → errnop = 0
```

### 3. Iterator lifecycle

```
setpwent()   → Response::Success(Vec<Passwd>)  — load entries
  │
  ├── getpwent_r()  → Response::Success(Passwd)  — entry 1
  ├── getpwent_r()  → Response::Success(Passwd)  — entry 2
  │
  └── getpwent_r()  → Response::Return            — done
```
