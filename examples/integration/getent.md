# getent — Utility Integration

## Overview

`getent` is the primary tool for querying NSS databases. It supports three modes:
1. **Lookup by name/GID/UID** — single entry lookup
2. **Enumeration** — iterate all entries
3. **Database selection** — query specific or all databases

## Database Selection

```bash
# Query specific database
getent passwd test
getent shadow test
getent group test
getent hosts test.example

# Query all databases
getent --all
```

## getent passwd — Passwd Database

### Single entry lookup (getpwnam_r)

```bash
getent passwd test
  │
  ├── nss_setpwent()
  ├── nss_getpwnam_r("test")  — lookup by name
  │   └── Response::Success(Passwd {
  │       name: "test",
  │       passwd: "x",
  │       uid: 1005,
  │       gid: 1005,
  │       gecos: "Test User",
  │       dir: "/home/test",
  │       shell: "/bin/bash",
  │   })
  │
  └── Output:
       test:x:1005:1005:Test User:/home/test:/bin/bash
```

### Enumeration (getpwent_r)

```bash
getent passwd  — no argument
  │
  ├── nss_setpwent()  — load all entries
  ├── nss_getpwent_r()  — entry 1
  ├── nss_getpwent_r()  — entry 2
  │   │
  │   └── ... continue until TryAgain
  │
  └── nss_endpwent()  — close
```

### Lookup by UID (getpwuid_r)

```bash
getent passwd 1005
  │
  ├── nss_getpwuid_r(1005)
  │   └── Find entry where uid == 1005
  │
  └── Output:
       test:x:1005:1005:Test User:/home/test:/bin/bash
```

## getent shadow — Shadow Database

```bash
getent shadow test
  │
  ├── nss_setspent()  — load entries
  ├── nss_getspnam_r("test")
  │   └── Response::Success(Shadow {
  │       name: "test",
  │       passwd: "$6$KEnq4G3CxkA2iU$hash",
  │       last_change: 0,
  │       min_days: 0,
  │       max_days: 99999,
  │       warn_days: 7,
  │       inactive_days: -1,
  │       expire_date: -1,
  │   })
  │
  └── Output:
       test:$6$KEnq4G3CxkA2iU$hash:0:0:99999:7:::0
```

## getent group — Group Database

### Single entry lookup (getgrnam_r)

```bash
getent group test
  │
  ├── nss_setgrent()
  ├── nss_getgrnam_r("test")
  │   └── Response::Success(Group {
  │       name: "test",
  │       gid: 1005,
  │       members: ["someone"],
  │   })
  │
  └── Output:
       test::1005:someone
```

### Lookup by GID (getgrgid_r)

```bash
getent group 1005
  │
  ├── nss_getgrgid_r(1005)
  └── Output:
       test::1005:someone
```

### Enumeration (getgrent_r)

```bash
getent group
  │
  ├── nss_setgrent()
  ├── nss_getgrent_r()  — iterate all
  └── nss_endgrent()
```

## getent hosts — Host Database

### Single entry lookup (gethostbyname_r)

```bash
getent hosts test.example
  │
  ├── nss_sethostent()
  ├── nss_gethostbyname_r("test.example")
  │   └── Response::Success(Host {
  │       name: "test.example",
  │       addresses: V4([177.42.42.42]),
  │       aliases: ["other.example"],
  │   })
  │
  └── Output:
       177.42.42.42 test.example other.example
```

### Enumeration (gethostent_r)

```bash
getent hosts
  │
  ├── nss_sethostent()
  ├── nss_gethostent_r()  — iterate all
  └── nss_endhostent()
```

## getent — All Databases

```bash
getent --all
  │
  ├── passwd:  setpwent → getpwnam_r / getpwent_r → endpwent
  ├── shadow:  spent → getspnam_r / getspent_r → endspent
  ├── group:   setgrent → getgrnam_r / getgrent_r → endgrent
  ├── hosts:   sethostent → gethostbyname_r / gethostent_r → endhostent
  └── initgroups: initgroups_dyn
```

## Integration with /etc/nsswitch.conf

```bash
# nsswitch.conf configuration:
passwd:     hardcoded files systemd
shadow:     hardcoded files
group:      hardcoded files [SUCCESS=merge]
hosts:      hardcoded files dns
initgroups: hardcoded

# getent queries each database:
# 1. Check hardcoded module (libnss_hardcoded.so)
# 2. If not found, check files (/etc/passwd, etc.)
# 3. If enabled, check systemd (systemd-nss)
# 4. Merge results if [SUCCESS=merge]
```

## getent Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success — entry found |
| `1` | No matching entry |
| `2` | Malformed command line |
| `3` | NSS module returned TryAgain |
| `4` | NSS module returned Unavail |
| `5` | No module for the database |
