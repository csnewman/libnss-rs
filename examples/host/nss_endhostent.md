# nss_endhostent() — Terminate Host Enumeration

## Rust Signature

```rust
fn endhostent() -> NssStatus;
// Called via:
// iter.close()
```

## C ABI Signature

```c
extern "C" {
    int nss_<name>_endhostent(void);
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

### 1. `getent hosts` — cleanup

```
getent hosts
  │
  ├── sethostent()   — load
  ├── gethostent_r()  — iterate
  └── endhostent()   — free
```
