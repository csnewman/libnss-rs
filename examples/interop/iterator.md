# Iterator\<T\> — Thread-Safe Entry Iterator

## Rust Definition

```rust
pub struct Iterator<T> {
    items: Option<VecDeque<T>>,
    index: usize,
}

impl<T: Clone> Iterator<T> {
    pub fn new() -> Self;
    pub fn open(&mut self, items: Vec<T>) -> NssStatus;
    pub fn next(&mut self) -> Response<T>;
    pub fn previous(&mut self);
    pub fn close(&mut self) -> NssStatus;
}
```

## State Machine

```
         new()
           │
           ▼
       ┌────────┐
       │ empty  │  index=0, items=None
       └────┬───┘
            │ open()
            ▼
       ┌─────────┐
       │ active  │  items=Some(VecDeque), index=0
       └────┬────┘
            │ next()
            ▼
       ┌──────────┐
       │ iterating │  index advances
       └────┬─────┘
            │ next() → None
            ▼
       ┌────────┐
       │ done   │  items=Some, index > len
       └────┬───┘
            │ close()
            ▼
       ┌─────────┐
       │ closed  │  items=None, index=0
       └─────────┘
```

## Integration Examples

### 1. set*/get* pattern — the standard NSS sequence

```
Application:                  NSS Module:
───────────                   ─────────

1. setpwent()                 ├── get_all_entries() → Vec<Passwd>
                               ├── Iterator::open(entries)
                               └── state = Active

2. getpwent_r()               ├── Iterator::next()
                               ├── Returns Success(entry)
                               └── index++

3. getpwent_r()               ├── Iterator::next()
                               ├── Returns Success(entry)
                               └── index++

4. getpwent_r()               ├── Iterator::next()
                               └── Returns Return (exhausted)

5. endpwent()                 └── Iterator::close()
                                └── state = Closed
```

### 2. Thread safety via lazy_static Mutex

```
Thread A                    Thread B
────────                    ────────

setpwent() ──→ open           │
getpwent_r() ──→ entry 1      │
                         ─────┤ setpwent() → reopen
getpwent_r() ──→ entry 2      │
                         ─────┤ getpwent_r() → entry 1
endpwent() ──→ close          │
                         ─────┤ getpwent_r() → entry 2
                              │
                              └── endpwent() → close
```

### 3. Retry on TryAgain

```
getpwent_r()  →  TryAgain (buffer full)
     │
     ├── iter.previous()  — go back to previous entry
     └── Application enlarges buffer

getpwent_r()  →  Success (re-read same entry into new buffer)
```

## Rust Implementation Example

```rust
impl<T: Clone> Iterator<T> {
    pub fn new() -> Self {
        Iterator { items: None, index: 0 }
    }

    pub fn open(&mut self, items: Vec<T>) -> NssStatus {
        self.items = Some(VecDeque::from(items));
        self.index = 0;
        NssStatus::Success
    }

    pub fn next(&mut self) -> Response<T> {
        let response = match self.items {
            Some(ref mut items) => match items.get(self.index) {
                Some(entity) => Response::Success(entity.clone()),
                None => Response::NotFound,
            },
            None => Response::Unavail,
        };
        self.index += 1;
        response
    }

    pub fn close(&mut self) -> NssStatus {
        self.items = None;
        self.index = 0;
        NssStatus::Success
    }
}
```
