# PAM / NSS Integration

## Overview

PAM (Pluggable Authentication Modules) uses NSS as its backend for resolving user and group
information. The integration spans authentication, account management, authorization, and
session setup phases.

## PAM Module Stack

```
┌───────────────────────────────────────────────────────┐
│  Application (login, sshd, sudo, etc.)                │
│         │                                             │
│         ▼                                             │
│  ┌─────────────────────┐                              │
│  │ PAM Stack (libpam)  │                              │
│  │                     │                              │
│  │ 1. pam_authenticate │ — verify credentials         │
│  │ 2. pam_acct_mgmt    │ — check account validity     │
│  │ 3. pam_setcred      │ — manage credentials         │
│  │ 4. pam_open_session │ — prepare session            │
│  │ 5. pam_close_session│ — cleanup session            │
│  │ 6. pam_end          │ — finalize session           │
│  └──────┬──────────────┘                              │
│         │                                             │
│         ▼                                             │
│  ┌─────────────────────┐                              │
│  │  NSS (libnss.so.2)  │                              │
│  │                     │                              │
│  │  passwd database    │ — user identity              │
│  │  shadow database    │ — password hash              │
│  │  group database     │ — group membership           │
│  │  initgroups database│ — supplementary groups       │
│  │  host database      │ — hostname resolution        │
│  └──────┬──────────────┘                              │
│         │                                             │
│         ▼                                             │
│  ┌─────────────────────┐                              │
│  │ Your NSS Module     │                              │
│  │                     │                              │
│  │  libnss_hardcoded.so│                              │
│  └─────────────────────┘                              │
│         │                                             │
│         ▼                                             │
│  /etc/passwd           │ — local file backend         │
│  /etc/group            │                              │
│  /etc/shadow           │                              │
│  /etc/hosts            │                              │
└───────────────────────────────────────────────────────┘
```

## PAM Phase: pam_authenticate

```
pam_authenticate(PAM_USER="test", PAM_AUTHTOK="password123")
  │
  ├── Get user entry from NSS:
  │   ├── nss_getpwnam_r("test")  → Passwd entry
  │   │   ├── name: "test"
  │   │   ├── uid: 1005
  │   │   ├── gid: 1005
  │   │   ├── passwd: "x" (shadowed)
  │   │   ├── dir: "/home/test"
  │   │   └── shell: "/bin/bash"
  │   │
  │   └── nss_getspnam_r("test")  → Shadow entry
  │       ├── passwd: "$6$KEnq4G3CxkA2iU$hash"
  │       ├── last_change: 18660
  │       └── max_days: 99999
  │
  ├── Verify password:
  │   ├── crypt(password, "$6$KEnq4G3CxkA2iU$hash")
  │   └── compare with stored hash
  │
  └── PAM_AUTH_SUCCESS
```

## PAM Phase: pam_acct_mgmt

```
pam_acct_mgmt(PAM_USER="test")
  │
  ├── nss_getspnam_r("test")  → Shadow entry
  │   ├── last_change: 18660  (days since 1970)
  │   ├── expire_date: -1     (no expiry)
  │   ├── inactive_days: -1   (no inactive period)
  │   └── max_days: 99999     (practically unlimited)
  │
  ├── Validate aging constraints:
  │   ├── if expire_date != -1  &&  current_days > expire_date
  │   │   → PAM_ACCT_EXPIRED
  │   ├── if inactive != -1  &&  (current_days - last_change) > expire + inactive
  │   │   → PAM_ACCT_EXPIRED
  │   └── if password_age > max_days
  │       → PAM_CRED_EXPIRED
  │
  └── PAM_SUCCESS
```

## PAM Phase: pam_setcred

```
pam_setcred(PAM_AUTHTOK="password123")
  │
  ├── nss_initgroups_dyn("test", 1005)
  │   ├── Get all groups for user
  │   ├── Filter out primary group (gid=1005)
  │   ├── Collect supplementary GIDs
  │   │   → groups = [3005, 3006, 3007]
  │   └── Return via groupsp, start, size
  │
  ├── setgroups(3, groups)  — apply to current process
  │
  └── PAM_SUCCESS
```

## PAM Phase: pam_open_session

```
pam_open_session(PAM_USER="test")
  │
  ├── nss_getpwnam_r("test")  → uid, dir, shell
  ├── nss_getspnam_r("test")  → password info
  ├── nss_initgroups_dyn("test", 1005)  → groups
  │
  ├── Set credentials:
  │   ├── setuid(1005)
  │   ├── setgid(1005)
  │   └── setgroups(3, groups)
  │
  ├── Set environment:
  │   ├── setenv("USER", "test")
  │   ├── setenv("HOME", "/home/test")
  │   ├── setenv("SHELL", "/bin/bash")
  │   └── setenv("LOGNAME", "test")
  │
  ├── chdir("/home/test")
  │
  └── PAM_SUCCESS
```

## Full PAM Session Flow

```
Login sequence:
────────────

1. User enters username: "test"
2. PAM calls pam_authenticate():
   ├── getpwnam_r("test")    → uid=1005
   ├── getspnam_r("test")    → hash=$6$...
   ├── verify password
3. PAM calls pam_acct_mgmt():
   ├── getspnam_r("test")    → check expiry
   └── account valid
4. PAM calls pam_setcred():
   ├── initgroups_dyn("test", 1005)
   └── setgroups applied
5. PAM calls pam_open_session():
   ├── getpwnam_r("test")    → dir, shell
   ├── setuid(1005)
   ├── setgid(1005)
   ├── chdir("/home/test")
   ├── setenv("HOME", "/home/test")
   ├── setenv("SHELL", "/bin/bash")
6. exec("/bin/bash")
7. User session active
8. User logs out
9. PAM calls pam_close_session():
   ├── cleanup environment
   └── PAM_SUCCESS
```

## Integration with /etc/nsswitch.conf

```
nsswitch.conf configuration determines module order:

passwd:     hardcoded files systemd
              │           │         │
              ├── nss_hardcoded.so ── primary
              ├── /etc/passwd    ── fallback
              └── libnss_systemd.so ── systemd units

When getent passwd test queries:
1. libnss_hardcoded.so → nss_getpwnam_r("test")
2. If not found → /etc/passwd
3. If still not → systemd
```

## Integration with /etc/pam.d/

```
/etc/pam.d/login configuration:
───────────────────────────────

auth       required     pam_env.so
auth       sufficient   pam_unix.so   ← uses NSS for user lookup
auth       required     pam_nss.so    ← NSS module
account    required     pam_unix.so   ← uses NSS for expiry
account    required     pam_nss.so
password   sufficient   pam_unix.so
session    required     pam_nss.so    ← initgroups, env setup
session    required     pam_limits.so
```

## SSH Login — initgroups Sets the Groups

SSH is the most common path for initgroups to be called. When `sshd` handles a login,
the sequence is:

```
SSH Client                    sshd                         PAM / NSS
───────                    ────                         ──────────

authenticate()
  │                         │
  ├── nss_getpwnam_r()      │
  │   → uid, gid, dir       │
  │                         │
  ├── nss_getspnam_r()      │
  │   → password hash       │
  │                         │
  │                         │  ★ KEY CALL:
  │                         │
  ├── nss_initgroups_dyn()  │
  │   │                     │
  │   ├── InitgroupsHooks:: │
  │   │   get_entries_by_user()
  │   │   → [wheel, adm, sudo, docker]
  │   │
  │   ├── Filter primary gid
  │   ├── Set group array
  │   │
  │   └── setgroups(ngroups, groups)
  │       → process groups set
  │
  ├── pam_open_session()    │
  │   → env, dir, shell     │
  │                         │
  └── exec(shell)           │
      → session starts      │
```

**After initgroups completes, the SSH session has the complete group list:**

| GID | Group   | Source                  |
|---|---|---|
| 2000 | alice (primary) | `/etc/passwd` |
| 10   | wheel   | `nss_initgroups_dyn()`  |
| 27   | adm     | `nss_initgroups_dyn()`  |
| 30   | sudo    | `nss_initgroups_dyn()`  |
| 44   | docker  | `nss_initgroups_dyn()`  |

This is why `id` inside an SSH session shows all groups — they were applied
by `initgroups_dyn()` before the shell was executed.

## Integration with systemd

```
systemd-nss integration:
────────────────────────

1. systemd exposes user entries via D-Bus
2. libnss_systemd.so queries D-Bus
3. libnss_hardcoded.so is checked first (nsswitch.conf order)
4. If not found, systemd-nss provides the entry
```
