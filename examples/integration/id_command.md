# id(1) — Command Integration

## Overview

The `id` command displays user and group identity information by querying the NSS layer.
It uses multiple NSS calls to build a complete picture.

## id Command Flow

```
┌─────────────────────────────────────────────────────────────┐
│                      id test                                │
│                                                             │
│  1. Look up user by name                                    │
│     ├── nss_getpwnam_r("test")                              │
│     │   → uid = 1005, gid = 1005                            │
│     │   → name = "test"                                     │
│     │   → dir = "/home/test"                                │
│     │   └── shell = "/bin/bash"                             │
│     │                                                       │
│  2. Get supplementary groups                                │
│     ├── nss_initgroups_dyn("test", 1005)                    │
│     │   → groups = [1005, 3005, 3006, 3007]                 │
│     │   └── ngroups = 4                                     │
│     │                                                       │
│  3. Format output                                           │
│     └── "uid=1005(test) gid=1005(test)                      │
│           groups=1005(test),3005(initgroup1),               │
│                      3006(initgroup2),3007(initgroup3)"     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Detailed NSS Calls

### getpwnam_r — Primary Identity

```
id command → nss_getpwnam_r("test")
  │
  ├── NSS internal:
  │   ├── PasswdHooks::get_entry_by_name("test")
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
  └── Result:
      uid = 1005
      gid = 1005
```

### getgrgid_r — Group Name Resolution

```
id command → nss_getgrgid_r(1005)
  │
  ├── NSS internal:
  │   ├── GroupHooks::get_entry_by_gid(1005)
  │   └── Response::Success(Group {
  │       name: "test",
  │       gid: 1005,
  │       members: ["someone"],
  │   })
  │
  └── Result:
      group name = "test"
```

### initgroups_dyn — Supplementary Groups

```
id command → nss_initgroups_dyn("test", 1005)
  │
  ├── NSS internal:
  │   ├── InitgroupsHooks::get_entries_by_user("test")
  │   │   └── Returns: [
  │   │       Group { name: "initgroup1", gid: 3005 },
  │   │       Group { name: "initgroup2", gid: 3006 },
  │   │       Group { name: "initgroup3", gid: 3007 },
  │   │   ]
  │   │
  │   ├── Filter: gid != skipgroup (1005)
  │   ├── Collect GIDs: [3005, 3006, 3007]
  │   ├── For each GID: nss_getgrgid_r(gid)  → group name
  │   │
  │   └── Result:
  │       groups = [1005, 3005, 3006, 3007]
  │       ngroups = 4
  │
  └── Format:
      uid=1005(test) gid=1005(test)
      groups=1005(test),3005(initgroup1),
             3006(initgroup2),3007(initgroup3)
```

## Integration with Other Commands

### id -u — print only UID

```
id -u test
  │
  ├── getpwnam_r("test")
  │   └── Return uid only
  │
  └── Output: 1005
```

### id -g — print only effective GID

```
id -g test
  │
  ├── getegid()  → 1005
  ├── getgrgid_r(1005)  → "test"
  │
  └── Output: 1005 (test)
```

### id -G — print all group IDs

```
id -G test
  │
  ├── initgroups_dyn("test", 1005)
  │   └── Returns GIDs: [1005, 3005, 3006, 3007]
  │
  └── Output: 1005 3005 3006 3007
```

### id -n — print names instead of numbers

```
id -nG test
  │
  ├── initgroups_dyn("test", 1005)
  │   ├── For each GID: getgrgid_r(gid)  → name
  │   └── Names: [test, initgroup1, initgroup2, initgroup3]
  │
  └── Output: test initgroup1 initgroup2 initgroup3
```

## C Caller Example

```c
#include <pwd.h>
#include <grp.h>
#include <stdio.h>

void id_command(const char *username) {
    struct passwd pw;
    struct group gr;
    gid_t *groups;
    size_t ngroups, start = 0, size = 0;
    char buf[2048];
    int err;

    /* Get user entry */
    nss_example_getpwnam_r(username, &pw, buf, sizeof(buf), &err);
    printf("uid=%u(%s) gid=%u(%s)",
           pw.pw_uid, pw.pw_name, pw.pw_gid, gr.gr_name);

    /* Get supplementary groups */
    nss_example_initgroups_dyn(
        username, pw.pw_gid,
        &start, &size, &groups, 64, &err
    );

    printf(" groups=");
    for (size_t i = 0; i < start; i++) {
        if (i > 0) printf(",");
        printf("%u", groups[i]);
    }
    printf("\n");
}
```
