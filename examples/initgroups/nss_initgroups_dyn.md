# nss_initgroups_dyn() — Supplemental Group Initialization

## Rust Signature

```rust
fn initgroups_dyn(
    name: *const c_char,
    skipgroup: gid_t,
    start: *mut size_t,
    size: *mut size_t,
    groupsp: *mut *mut gid_t,
    limit: size_t,
    errnop: *mut c_int,
) -> c_int;
```

## C ABI Signature

```c
extern "C" {
    int nss_<name>_initgroups_dyn(
        const char *name,           /* input:  username */
        gid_t skipgroup,             /* input:  primary GID to exclude */
        size_t *start,              /* in/out: current offset in array */
        size_t *size,               /* in/out: current array capacity */
        gid_t **groupsp,            /* in/out: group ID array */
        size_t limit,               /* input:  max groups to return */
        int *errnop,                /* output: error code */
    );
}
```

## Parameters

| Parameter | Direction | Type | Description |
|---|---|---|---|
| `name` | in | `*const c_char` | Username to resolve. |
| `skipgroup` | in | `gid_t` | Primary group ID to exclude from the list. |
| `start` | in/out | `*mut size_t` | Current offset — where to write next group. |
| `size` | in/out | `*mut size_t` | Current array capacity. |
| `groupsp` | in/out | `*mut *mut gid_t` | Pointer to the group ID array (may be realloc'd). |
| `limit` | in | `size_t` | Maximum number of groups to return. |
| `errnop` | out | `*mut c_int` | Error number. |

## Return Value

| Value | Constant | Description |
|---|---|---|
| `1` | `NssStatus::Success` | Groups written successfully. |
| `1` | `NssStatus::Success` | No more groups (empty result). |
| `-2` | `NssStatus::TryAgain` | Buffer too small. |
| `-1` | `NssStatus::Unavail` | Temporary failure. |

## How It Works

```
┌────────────────────────────────────────────────────┐
│  initgroups_dyn("test", 1000, &start, &size,       │
│                  &groupsp, 64, &errnop)            │
│                                                    │
│  1. Application:                                   │
│     gid_t *groups = NULL;                          │
│     size_t start = 0, size = 0;                    │
│     int err;                                       │
│     nss_example_initgroups_dyn("test", 1000,       │
│         &start, &size, &groups, 64, &err);         │
│                                                    │
│  2. libnss-rs flow:                                │
│     ┌──────────────────────────────────────────┐   │
│     │ Step 1: CStr::from_ptr(name_)            │   │
│     │ Step 2: InitgroupsHooks::                │   │
│     │          get_entries_by_user("test")     │   │
│     │ Step 3: Filter: gid != skipgroup         │   │
│     │ Step 4: Collect GIDs into Vec<gid_t>     │   │
│     │ Step 5: realloc(groupsp, new_size)       │   │
│     │ Step 6: Copy GIDs into groupsp[start:]   │   │
│     │ Step 7: start = group_array.len()        │   │
│     └──────────────────────────────────────────┘   │
│                                                    │
│  3. Result:                                        │
│     groups = [3005, 3006, 3007]  (excluding 1000)  │
│     start = 3                                      │
│     size = 3                                       │
│     err = 0                                        │
└────────────────────────────────────────────────────┘
```

## Integration Examples

### 1. User login — group initialization

```
login("test")
  │
  ├── getpwnam_r("test")  → uid=1005, primary_gid=1005
  │
  ├── initgroups_dyn("test", 1005, &start, &size, &groups, 64, &err)
  │   │
  │   ├── get_entries_by_user("test")  → Vec<Group>
  │   ├── Filter out primary gid (1005)
  │   ├── Collect supplementary GIDs
  │   │
  │   └── Result:
  │       groups = [3005, 3006, 3007]
  │       ngroups = 3
  │
  ├── setgroups(3, groups)  — set supplementary groups
  └── user now has 4 groups: primary(1005) + supplementary
```

### 2. `id` command — group listing

```
id test
  │
  ├── getpwnam_r("test")  → uid=1005, gid=1005
  ├── initgroups_dyn("test", 1005)  → supplementary groups
  │
  └── output:
       uid=1005(test) gid=1005(test)
       groups=1005(test),3005(initgroup1),3006(initgroup2),3007(initgroup3)
```

### 3. PAM session setup

```
pam_open_session()
  │
  ├── getpwnam_r(user)
  ├── initgroups_dyn(user, primary_gid)
  ├── setgroups(ngroups, groups)
  │
  └── User session has full group membership
```

### 4. SSH login — groups set on connection

SSH is the most common trigger for `initgroups_dyn()`. When a user SSHs in, `sshd` resolves the
user via NSS, then calls `initgroups_dyn()` to build the full supplementary group list.

```
SSH login sequence:
──────────────────────────────────────────

1. sshd starts a new child process
   │
   ├── nss_getpwnam_r("alice")
   │   └── uid=2000, gid=2000 (primary), dir="/home/alice"
   │
   ├── nss_getspnam_r("alice")
   │   └── password hash verified
   │
   └── ★ nss_initgroups_dyn("alice", 2000)
       │
       ├── InitgroupsHooks::get_entries_by_user("alice")
       │   ├── Returns: [
       │   │   Group { name: "alice",   gid: 2000 },   ← primary
       │   │   Group { name: "wheel",   gid: 10  },    ← supplementary
       │   │   Group { name: "adm",    gid: 27  },    ← supplementary
       │   │   Group { name: "sudo",   gid: 30  },    ← supplementary
       │   │   Group { name: "docker", gid: 44  },    ← supplementary
       │   │ ]
       │
       ├── Filter: gid != skipgroup (2000)
       │   → supplementary GIDs = [10, 27, 30, 44]
       │
       ├── realloc(groupsp, new_size)
       └── Copy GIDs into groupsp[start:]
       │
       └── setgroups(4, [10, 27, 30, 44])
           → SSH process now has 5 groups total

2. Session established
   ├── setuid(2000)
   ├── chdir("/home/alice")
   └── exec("/bin/zsh")

3. Result inside the SSH session:
   $ id
   uid=2000(alice) gid=2000(alice) groups=2000(alice),10(wheel),27(adm),30(sudo),44(docker)
                  ▲                         ▲
                  └─ primary                  └─ all set by initgroups_dyn() during SSH login
```

**Why initgroups matters for SSH:**

| Without initgroups_dyn() | With initgroups_dyn() |
|---|---|
| SSH process has only primary group (gid) | SSH process has ALL groups the user belongs to |
| `id` shows: uid=2000 gid=2000 | `id` shows: uid=2000 gid=2000 groups=2000,10,27,30,44 |
| Group-based permissions limited | Full group membership for file access |
| `groups` shows: alice | `groups` shows: alice wheel adm sudo docker |

```
SSH connection lifecycle:
───────────────────────────

  ssh client                          sshd
  ──────────                        ────
     │                                │
     ├── SSH connection established   │
     │   → authentication             │
     │                                │
     │                   nss_getpwnam_r(user)
     │                   nss_getspnam_r(user)
     │                   ★ nss_initgroups_dyn(user, gid)
     │                                │
     │                   setgroups(ngroups, groups)
     │                   chdir(dir)
     │                   exec(shell)
     │                                │
     │   ← shell session              │
     │   (full group membership)      │
     │                                │
     └── disconnect ──────────────────┘
```

### 5. PAM group-based authorization

```
pam_authz_check(user="alice")
  │
  ├── nss_getpwnam_r("alice")  → primary gid=2000
  ├── nss_initgroups_dyn("alice", 2000)
  │
  ├── Check if user in required group:
  │   ├── e.g., sudoers check
  │   ├── e.g., wheel group membership
  │   └── Uses groupsp from initgroups_dyn()
  │
  └── PAM_AUTHZ_SUCCESS if group criteria met
```

## Rust Implementation Example

```rust
use libnss::initgroups::InitgroupsHooks;
use libnss::group::Group;
use libnss::libnss_initgroups_hooks;
use libnss::interop::Response;

struct ExampleInitgroups;
libnss_initgroups_hooks!(example, ExampleInitgroups);

impl InitgroupsHooks for ExampleInitgroups {
    fn get_entries_by_user(user: String) -> Response<Vec<Group>> {
        // Return all groups the user belongs to
        // The generated function filters out skipgroup
        if user == "test" {
            Response::Success(vec![
                Group { name: "test".to_string(), gid: 1005, .. },
                Group { name: "initgroup1".to_string(), gid: 3005, .. },
                Group { name: "initgroup2".to_string(), gid: 3006, .. },
                Group { name: "initgroup3".to_string(), gid: 3007, .. },
            ])
        } else {
            Response::NotFound
        }
    }
}
```

## C Caller Example

```c
#include <sys/types.h>
#include <sysgrp.h>
#include <stdio.h>

void init_user_groups(const char *username, gid_t primary_gid) {
    gid_t *groups = NULL;
    size_t start = 0, size = 0;
    int err;

    int rc = nss_example_initgroups_dyn(
        username, primary_gid,
        &start, &size, &groups, 64, &err
    );

    if (rc == 1) {
        printf("User %s has %zu groups (starting at %zu):\n",
               username, start - primary_gid, start);
        for (size_t i = 0; i < start; i++) {
            printf("  group[%zu] = %u\n", i, groups[i]);
        }
    }
}
```
