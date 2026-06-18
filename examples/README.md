# libnss-rs — Examples

This directory contains detailed examples for every NSS call produced by `libnss-rs` macros.
Each example is in its own file with the function signature, system interaction, and integration use cases.

## Directory Structure

```
examples/
├── README.md                          # This index
├── passwd/                            — User account database
│   ├── nss_setpwent.md               — nss_<name>_setpwent()
│   ├── nss_endpwent.md               — nss_<name>_endpwent()
│   ├── nss_getpwent_r.md             — nss_<name>_getpwent_r()
│   ├── nss_getpwuid_r.md             — nss_<name>_getpwuid_r()
│   └── nss_getpwnam_r.md             — nss_<name>_getpwnam_r()
├── shadow/                            — Password / shadow database
│   ├── nss_setspent.md               — nss_<name>_setspent()
│   ├── nss_endspent.md               — nss_<name>_endspent()
│   ├── nss_getspent_r.md             — nss_<name>_getspent_r()
│   └── nss_getspnam_r.md             — nss_<name>_getspnam_r()
├── group/                             — Group membership database
│   ├── nss_setgrent.md               — nss_<name>_setgrent()
│   ├── nss_endgrent.md               — nss_<name>_endgrent()
│   ├── nss_getgrent_r.md             — nss_<name>_getgrent_r()
│   ├── nss_getgrgid_r.md             — nss_<name>_getgrgid_r()
│   └── nss_getgrnam_r.md             — nss_<name>_getgrnam_r()
├── host/                              — Hostname resolution database
│   ├── nss_sethostent.md             — nss_<name>_sethostent()
│   ├── nss_endhostent.md             — nss_<name>_endhostent()
│   ├── nss_gethostent_r.md           — nss_<name>_gethostent_r()
│   ├── nss_gethostbyaddr_r.md        — nss_<name>_gethostbyaddr_r()
│   ├── nss_gethostbyname_r.md        — nss_<name>_gethostbyname_r()
│   ├── nss_gethostbyname2_r.md       — nss_<name>_gethostbyname2_r()
│   └── nss_gethostbyname3_r.md       — nss_<name>_gethostbyname3_r()
├── initgroups/                        — Supplemental group initialization
│   └── nss_initgroups_dyn.md         — nss_<name>_initgroups_dyn() (SSH login groups)
├── interop/                           — Core interop types (shared across all databases)
│   ├── nss_status.md                  — NssStatus enum
│   ├── response.md                    — Response<R> enum
│   ├── cbuffer.md                    — CBuffer memory management
│   └── iterator.md                   — Iterator<T> for set*/get* patterns
└── integration/                       — Real-world integration examples
    ├── user_login.md                  — Complete user login flow (incl. SSH initgroups)
    ├── id_command.md                  — id(1) command integration
    ├── getent.md                      — getent utility integration
    └── pam_integration.md             — PAM / NSS integration (incl. SSH groups)
```
