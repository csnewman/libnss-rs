# CBuffer — Contiguous String Memory Manager

## Rust Definition

```rust
pub struct CBuffer {
    start: *mut c_void,  /* Base address of the buffer */
    pos: *mut c_void,    /* Current write position */
    free: size_t,        /* Bytes remaining (free space) */
    len: size_t,         /* Total buffer length */
}
```

## How CBuffer Works

CBuffer manages a contiguous block of memory (the caller's `buf` array) and:
1. **Copies C-strings** into the buffer sequentially.
2. **Returns pointers** into the buffer for each string.
3. **Tracks remaining space** — if the buffer is full, returns `ERANGE`.
4. **Resets position** on `clear()` for reuse.

## Core Operations

```rust
impl CBuffer {
    pub fn new(ptr: *mut c_void, len: size_t) -> Self;
    pub unsafe fn clear(&mut self);
    pub unsafe fn write_str(&mut self, string: &str) -> Result<*mut c_char>;
    pub unsafe fn write_strs<S: AsRef<str>>(
        &mut self, strings: &[S]
    ) -> Result<*mut *mut c_char>;
    pub unsafe fn reserve(&mut self, len: isize) -> Result<*mut c_char>;
}
```

## Memory Layout

```
Caller's buf (2048 bytes):
┌──────────┬───────────────────────────────────────────────┐
│ "root"   │ "$6$xyz123..." │ "/root"     │ "/bin/bash"    │
│ 5B       │ 13B            │ 6B          │ 10B            │
│ ↑        │ ↑              │ ↑           │ ↑              │
│ ptr→name │ ptr→passwd     │ ptr→dir     │ ptr→shell      │
└──────────┴───────────────────────────────────────────────┘
         ↑
    CBuffer::pos (next free byte)

CBuffer state:
  start = buf base address
  pos   = current position (next write)
  free  = 2048 - (pos - start)
  len   = 2048
```

## Integration Examples

### 1. String allocation for passwd entry

```
Passwd.to_c(result, buffer)
  │
  ├── buffer.write_str(&self.name)   → "root"
  ├── buffer.write_str(&self.passwd) → "$6$xyz"
  ├── buffer.write_str(&self.gecos)  → "Root"
  ├── buffer.write_str(&self.dir)    → "/root"
  └── buffer.write_str(&self.shell)  → "/bin/bash"

Each write_str() returns a pointer into buffer that is set in result.
```

### 2. String array allocation for group members

```
Group.to_c(result, buffer)
  │
  ├── buffer.write_strs(&self.members)  → ["someone", NULL]
  │   │
  │   ├── reserve(ptr_size * (count + 1))  — space for pointers
  │   ├── write_str("someone")  — actual string content
  │   └── memset(last_ptr, 0, ptr_size)  — null terminator
  │
  └── result→members points to the pointer array
```

### 3. Buffer overflow detection

```
write_str("very_long_username")
  │
  ├── len = strlen(string)
  ├── if free < len + 1:
  │   └── return ERANGE  → TryAgain
  │
  └── else:
      ├── memcpy string into buf
      ├── pos += len + 1
      ├── free -= len + 1
      └── return pointer to string
```

## Rust Implementation Example

```rust
impl CBuffer {
    pub fn new(ptr: *mut c_void, len: size_t) -> Self {
        CBuffer {
            start: ptr,
            pos: ptr,
            free: len,
            len,
        }
    }

    pub unsafe fn write_str(&mut self, string: &str) -> io::Result<*mut c_char> {
        let str_start = self.pos;
        let cstr = CString::new(string).expect("Failed to convert string");
        let ptr = cstr.as_ptr();
        let len = libc::strlen(ptr);

        if self.free < len + 1 {
            return Err(io::Error::from_raw_os_error(libc::ERANGE));
        }

        libc::memcpy(self.pos, ptr as *mut c_void, len);
        self.pos = self.pos.offset(len as isize + 1);
        self.free -= len as usize + 1;

        Ok(str_start as *mut c_char)
    }
}
```
