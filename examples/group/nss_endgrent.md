# nss_endgrent() — Terminate group Enumeration

## Rust Signature

```rust
fn endgrent() -> NssStatus;
// Called via:
// iter.close()
```

## C ABI Signature

```c
extern "C" {
    int nss_<name>_endgrent(void);
}
```

## Parameters

| Parameter | Direction | Type | Description |
|---|---|---|---|
| *(none)* | — | — | No input parameters. |

## Return Value

| Value | Constant | Description |
|---|---|---|
| `1` | `NssStatus::Success` | Iterator closed. |

## Integration Examples

### 1. `getent group` — cleanup

```
getent group
  │
  ├── setgrent()     — load
  ├── getgrent_r()  — iterate
  └── endgrent()     — close, free memory
```

### 2. PAM group validation

```
pam_setcred()
  │
  ├── setgrent()
  ├── getgrent_r()  — iterate groups
  ├── check if user in required group
  └── endgrent()
```
