# User Login — Complete Flow

## Overview

When a user logs in (via `login`, `su`, SSH, or PAM), the system performs a series of
NSS lookups to verify identity and set up the session. This document traces the complete
flow through all five NSS databases.

## Complete Login Flow

```
┌─────────────────────────────────────────────────────────────┐
│                      login(3) call                          │
│                                                             │
│  1. Get user entry                                          │
│     ├── nss_getpwnam_r("alice")                             │
│     │     ├── Passwd::name → "alice"                        │
│     │     ├── Passwd::uid → 2000                            │
│     │     ├── Passwd::gid → 2000                            │
│     │     ├── Passwd::dir → "/home/alice"                   │
│     │     └── Passwd::shell → "/bin/zsh"                    │
│     │                                                       │
│     ├── nss_getspnam_r("alice")                             │
│     │     ├── Shadow::passwd → "$6$abc$"                    │
│     │     ├── Shadow::last_change → 19000                   │
│     │     └── Shadow::expire_date → -1                      │
│     │                                                       │
│     └── Verify password hash                                │
│                                                             │
│  2. Initialize groups                                       │
│     ├── nss_initgroups_dyn("alice", 2000)                   │
│     │     ├── Returns: [2000, 10, 27, 30, 44]               │
│     │     │   (primary: 2000, supplementary: wheel,         │
│     │     │    adm, sudo, docker)                           │
│     │     └── ngroups = 5                                   │
│     │                                                       │
│     └── setgroups(5, groups)                                │
│                                                             │
│  3. Set up session                                          │
│     ├── setuid(2000)                                        │
│     ├── setgid(2000)                                        │
│     ├── chdir("/home/alice")                                │
│     └── exec("/bin/zsh")                                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Step-by-Step NSS Calls

### Step 1: Username Lookup (passwd)

```
nss_getpwnam_r("alice")
  │
  ├── CStr::from_ptr("alice")
  ├── PasswdHooks::get_entry_by_name("alice")
  │   ├── Search data source for name == "alice"
  │   └── Response::Success(Passwd {
  │       name: "alice",
  │       passwd: "x",
  │       uid: 2000,
  │       gid: 2000,
  │       gecos: "Alice Smith",
  │       dir: "/home/alice",
  │       shell: "/bin/zsh",
  │   })
  │
  └── C buffer allocation:
      ┌───────┬──────────┬───────┬──────────┬───────┐
      │name   │ passwd   │ gecos │ dir      │ shell │
      │"alice"│ "x"      │ "Al.."│ "/home/  │ "/bin/│
      └───────┴──────────┴───────┴──────────┴───────┘
```

### Step 2: Password Hash Lookup (shadow)

```
nss_getspnam_r("alice")
  │
  ├── ShadowHooks::get_entry_by_name("alice")
  │   ├── Response::Success(Shadow {
  │   │   passwd: "$6$abc123$hashed_value",
  │   │   last_change: 19000,  /* days since 1970-01-01 */
  │   │   min_days: 0,
  │   │   max_days: 99999,
  │   │   warn_days: 7,
  │   │   inactive_days: -1,
  │   │   expire_date: -1,
  │   │ })
  │   │
  │   └── Password verification:
  │       ├── crypt(password, "$6$abc123$")  → hash
  │       └── compare with stored hash
  │
  └── Account validation:
      ├── if expire_date != -1 && days_since(1970) > expire_date
      │   └── PAM_ACCT_EXPIRED
      └── if inactive != -1 && days_since(last_change) > expire + inactive
          └── PAM_ACCT_EXPIRED
```

### Step 3: Group Membership (initgroups)

```
nss_initgroups_dyn("alice", 2000)
  │
  ├── InitgroupsHooks::get_entries_by_user("alice")
  │   ├── Returns: [
  │   │   Group { name: "alice", gid: 2000 },
  │   │   Group { name: "wheel", gid: 10 },
  │   │   Group { name: "adm", gid: 27 },
  │   │   Group { name: "sudo", gid: 30 },
  │   │   Group { name: "docker", gid: 44 },
  │   │ ]
  │   │
  │   └── Filter: gid != skipgroup (2000)
  │       → [10, 27, 30, 44] (supplementary groups)
  │   └── realloc(groupsp, new_size)
  │   └── Copy GIDs into groupsp[start:]
  │
  └── setgroups(5, groups)  — apply group membership
```

### Step 4: Home Directory (passwd)

```
nss_getpwnam_r("alice")  →  dir = "/home/alice"

chdir("/home/alice")

Verify directory exists:
  stat("/home/alice", &st)
    ├── S_ISDIR(st.st_mode) → true
    └── Check ownership matches uid
```

### Step 5: Shell Execution

```
nss_getpwnam_r("alice")  →  shell = "/bin/zsh"

exec("/bin/zsh", args, env)
  ├── Process.uid = 2000
  ├── Process.gid = 2000
  ├── Process.groups = [2000, 10, 27, 30, 44]
  └── CWD = "/home/alice"
```

## System Integration Points

### PAM Stack Integration

```
pam_sm_authenticate()
  ├── pam_get_item(PAM_USER)  → "alice"
  ├── pam_get_authtok()       → user enters password
  │
  ├── NSS lookup:
  │   ├── nss_getpwnam_r("alice")
  │   ├── nss_getspnam_r("alice")
  │   └── verify password
  │
  ├── pam_acct_mgmt()
  │   ├── nss_getspnam_r("alice")
  │   └── check account expiration
  │
  └── pam_open_session()
      ├── nss_getpwnam_r("alice")
      ├── nss_initgroups_dyn("alice", 2000)
      └── set up session
```

### SSH Authentication Integration (initgroups sets groups on login)

When a user SSHs in, `sshd` authenticates them via PAM, then uses the
`nss_initgroups_dyn()` call to build and apply the full group membership
list. This is the **critical step** that gives an SSH session the correct
supplementary groups — without it, the session would have only its primary
group.

```
SSH login flow (initgroups at the core):
──────────────────────────────────────────

1. sshd receives connection
   │
   ├── User: "alice"
   ├── Auth: publickey or password
   │
2. pam_authenticate(PAM_USER="alice")
   ├── nss_getpwnam_r("alice")     → uid=2000, gid=2000, dir="/home/alice"
   ├── nss_getspnam_r("alice")     → password hash "$6$..."
   └── verify password hash
   │
3. ★ pam_setcred()                   ← **initgroups_dyn is called here**
   │
   ├── nss_initgroups_dyn("alice", 2000)
   │   │
   │   ├── InitgroupsHooks::get_entries_by_user("alice")
   │   │   ├── Returns: [
   │   │   │   Group { name: "alice",    gid: 2000 },  ← primary (filtered out)
   │   │   │   Group { name: "wheel",   gid: 10  },   ← supplementary
   │   │   │   Group { name: "adm",     gid: 27  },   ← supplementary
   │   │   │   Group { name: "sudo",    gid: 30  },   ← supplementary
   │   │   │   Group { name: "docker",  gid: 44  },   ← supplementary
   │   │   │ ]
   │   │
   │   ├── Filter out primary group: gid != 2000
   │   │   → supplementary GIDs = [10, 27, 30, 44]
   │   │
   │   ├── realloc(groupsp, new_size)   — grow array if needed
   │   └── Copy GIDs into groupsp[start:]
   │
   ├── setgroups(4, [10, 27, 30, 44])  — apply to sshd child process
   │
   └── ★ After this call, the SSH session process has:
       ├─ uid = 2000
       ├─ gid = 2000
       └─ groups = [2000, 10, 27, 30, 44]  ← 5 groups total
   │
4. pam_open_session()
   ├── nss_getpwnam_r("alice")     → confirm dir="/home/alice"
   ├── nss_getpwnam_r("alice")     → confirm shell="/bin/zsh"  (cached)
   └── setenv("HOME", "/home/alice")
   
   **Note:** While two `getpwnam_r` calls are shown, most real implementations
   cache the result of the first lookup, so the second call returns the cached entry
   without re-querying the database.
   │
5. exec("/bin/zsh")
   │
   └── ★ sshd child process now has all groups set:
       ├─ uid  = 2000
       ├─ gid  = 2000
       ├─ groups = [2000, 10, 27, 30, 44]
       ├─ CWD = /home/alice
       └─ shell = /bin/zsh
```

**Key point:** The `nss_initgroups_dyn()` call is what populates the session's
group list. Without it, the SSH process would only have its primary group (gid=2000).
With it, the session inherits all supplementary groups — which controls file access
permissions, `groups` command output, and group-based authorization.

```
Verification after SSH login:
$ id
uid=2000(alice) gid=2000(alice) groups=2000(alice),10(wheel),27(adm),30(sudo),44(docker)
```

### su Command Integration

```
su - alice
  │
  ├── getpwnam_r("alice")  → uid=2000, dir="/home/alice", shell="/bin/zsh"
  ├── getspnam_r("alice")  → password hash
  ├── getgrnam_r("alice")  → primary group
  ├── initgroups_dyn("alice", 2000)
  │
  └── exec("/bin/zsh", ["-l", "-c", "exec $SHELL"])
```
