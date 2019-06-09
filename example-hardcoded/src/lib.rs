extern crate libc;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate libnss;

use libnss::passwd::{PasswdHooks, Passwd};

struct HardcodedPasswd;
libnss_passwd_hooks!(hardcoded, HardcodedPasswd);

// Creates an account with username "test", and password "pass"
// Ensure the home directory "/home/test" exists, and is owned by 1007:1007
impl PasswdHooks for HardcodedPasswd {
    fn get_all_entries() -> Vec<Passwd> {
        vec![
            Passwd {
                name: "test".to_string(),
                passwd: "xuS4FT0FmfYVI".to_string(),
                uid: 1007,
                gid: 1007,
                gecos: "TestAccount".to_string(),
                dir: "/home/test".to_string(),
                shell: "/bin/bash".to_string(),
            }
        ]
    }

    fn get_entry_by_uid(uid: libc::uid_t) -> Option<Passwd> {
        if uid == 1007 {
            return Some(Passwd {
                name: "test".to_string(),
                passwd: "xuS4FT0FmfYVI".to_string(),
                uid: 1007,
                gid: 1007,
                gecos: "TestAccount".to_string(),
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
                passwd: "xuS4FT0FmfYVI".to_string(),
                uid: 1007,
                gid: 1007,
                gecos: "TestAccount".to_string(),
                dir: "/home/test".to_string(),
                shell: "/bin/bash".to_string(),
            });
        }

        None
    }
}