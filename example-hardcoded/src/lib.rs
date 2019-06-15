extern crate libc;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate libnss;

use libnss::passwd::{PasswdHooks, Passwd};
use libnss::group::{GroupHooks, Group};
use libnss::shadow::{ShadowHooks, Shadow};
use libnss::host::{HostHooks, Host};

struct HardcodedPasswd;
libnss_passwd_hooks!(hardcoded, HardcodedPasswd);

// Creates an account with username "test", and password "pass"
// Ensure the home directory "/home/test" exists, and is owned by 1007:1007
impl PasswdHooks for HardcodedPasswd {
    fn get_all_entries() -> Vec<Passwd> {
        vec![
            Passwd {
                name: "test".to_string(),
                passwd: "x".to_string(),
                uid: 1005,
                gid: 1005,
                gecos: "Test Account".to_string(),
                dir: "/home/test".to_string(),
                shell: "/bin/bash".to_string(),
            }
        ]
    }

    fn get_entry_by_uid(uid: libc::uid_t) -> Option<Passwd> {
        if uid == 1005 {
            return Some(Passwd {
                name: "test".to_string(),
                passwd: "x".to_string(),
                uid: 1005,
                gid: 1005,
                gecos: "Test Account".to_string(),
                dir: "/home/test".to_string(),
                shell: "/bin/bash".to_string(),
            });
        }

        None
    }

    fn get_entry_by_name(name: String) -> Option<Passwd> {
        if name == "test" {
            return Some(Passwd {
                name: "test".to_string(),
                passwd: "x".to_string(),
                uid: 1005,
                gid: 1005,
                gecos: "Test Account".to_string(),
                dir: "/home/test".to_string(),
                shell: "/bin/bash".to_string(),
            });
        }

        None
    }
}

struct HardcodedGroup;
libnss_group_hooks!(hardcoded, HardcodedGroup);

impl GroupHooks for HardcodedGroup {
    fn get_all_entries() -> Vec<Group> {
        vec![
            Group {
                name: "test".to_string(),
                passwd: "".to_string(),
                gid: 1005,
                members: vec!["someone".to_string()],
            }
        ]
    }

    fn get_entry_by_gid(gid: libc::gid_t) -> Option<Group> {
        if gid == 1005 {
            return Some(Group {
                name: "test".to_string(),
                passwd: "".to_string(),
                gid: 1005,
                members: vec!["someone".to_string()],
            });
        }

        None
    }

    fn get_entry_by_name(name: String) -> Option<Group> {
        if name == "test" {
            return Some(Group {
                name: "test".to_string(),
                passwd: "".to_string(),
                gid: 1005,
                members: vec!["someone".to_string()],
            });
        }

        None
    }
}

struct HardcodedShadow;
libnss_shadow_hooks!(hardcoded, HardcodedShadow);

impl ShadowHooks for HardcodedShadow {
    fn get_all_entries() -> Vec<Shadow> {
        // TODO: Ensure we are a privileged user before returning results
        vec![
            Shadow {
                name: "test".to_string(),
                passwd: "$6$KEnq4G3CxkA2iU$l/BBqPJlzPvXDfa9ZQ2wUM4fr9CluB.65MLVhLxhjv1jVluZphzY1J6EBtxEa5/n4IDqamJ5cvvek3CtXNYSm1".to_string(),
                last_change: 0,
                change_min_days: 0,
                change_max_days: 99999,
                change_warn_days: 7,
                change_inactive_days: -1,
                expire_date: -1,
                reserved: 0,
            }
        ]
    }

    fn get_entry_by_name(name: String) -> Option<Shadow> {
        // TODO: Ensure we are a privileged user before returning results
        if name == "test" {
            return Some(Shadow {
                name: "test".to_string(),
                passwd: "$6$KEnq4G3CxkA2iU$l/BBqPJlzPvXDfa9ZQ2wUM4fr9CluB.65MLVhLxhjv1jVluZphzY1J6EBtxEa5/n4IDqamJ5cvvek3CtXNYSm1".to_string(),
                last_change: 0,
                change_min_days: 0,
                change_max_days: 99999,
                change_warn_days: 7,
                change_inactive_days: -1,
                expire_date: -1,
                reserved: 0,
            });
        }

        None
    }
}

use std::net::IpAddr;

struct HardcodedHost;
libnss_host_hooks!(hardcoded, HardcodedHost);

impl HostHooks for HardcodedHost {
    fn get_all_entries() -> Vec<Host> {
        unimplemented!()
    }

    fn get_host_by_name(_name: &str) -> Option<Host> {
        unimplemented!()
    }

    fn get_host_by_addr(_addr: IpAddr) -> Option<Host> {
        unimplemented!()
    }
}