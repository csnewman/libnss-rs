use crate::interop::CBuffer;
use std::collections::VecDeque;

pub struct Passwd {
    pub name: String,
    pub passwd: String,
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
    pub gecos: String,
    pub dir: String,
    pub shell: String,
}

pub trait PasswdHooks {
    fn get_all_entries() -> Vec<Passwd>;

    fn get_entry_by_uid(uid: libc::uid_t) -> Option<Passwd>;

    fn get_entry_by_name(name: String) -> Option<Passwd>;
}

#[repr(C)]
#[allow(missing_copy_implementations)]
pub struct CPasswd {
    name: *mut libc::c_char,
    passwd: *mut libc::c_char,
    uid: libc::uid_t,
    gid: libc::gid_t,
    gecos: *mut libc::c_char,
    dir: *mut libc::c_char,
    shell: *mut libc::c_char,
}

pub struct PasswdIterator {
    items: Option<VecDeque<Passwd>>,
}

impl PasswdIterator {
    pub fn new() -> Self {
        PasswdIterator {
            items: None,
        }
    }

    pub fn open(&mut self, items: Vec<Passwd>) {
        self.items = Some(VecDeque::from(items));
    }

    pub fn next(&mut self) -> Option<Passwd> {
        match self.items {
            Some(ref mut val) => val.pop_front(),
            None => panic!("Iterator not currently open")
        }
    }

    pub fn close(&mut self) {
        self.items = None;
    }
}

impl Passwd {
    pub unsafe fn to_c_passwd(self, pwbuf: *mut CPasswd, buffer: &mut CBuffer) {
        (*pwbuf).name = buffer.write_str(self.name);
        (*pwbuf).passwd = buffer.write_str(self.passwd);
        (*pwbuf).uid = self.uid;
        (*pwbuf).gid = self.gid;
        (*pwbuf).gecos = buffer.write_str(self.gecos);
        (*pwbuf).dir = buffer.write_str(self.dir);
        (*pwbuf).shell = buffer.write_str(self.shell);
    }
}

#[macro_export]
macro_rules! libnss_passwd_hooks {
($mod_ident:ident, $hooks_ident:ident) => (
    paste::item! {
        pub use self::[<libnss_passwd_ $mod_ident _hooks_impl>]::*;
        mod [<libnss_passwd_ $mod_ident _hooks_impl>] {
            #![allow(non_upper_case_globals)]

            use std::ffi::CStr;
            use std::str;
            use std::sync::{Mutex, MutexGuard};
            use $crate::interop::{CBuffer, NssStatus};
            use $crate::passwd::{CPasswd, PasswdHooks, PasswdIterator};

            lazy_static! {
            static ref [<PASSWD_ $mod_ident _ITERATOR>]: Mutex<PasswdIterator> = Mutex::new(PasswdIterator::new());
            }

            #[no_mangle]
            extern "C" fn [<_nss_ $mod_ident _setpwent>]() -> libc::c_int {
                let mut iter: MutexGuard<PasswdIterator> = [<PASSWD_ $mod_ident _ITERATOR>].lock().unwrap();
                iter.open(super::$hooks_ident::get_all_entries());
                NssStatus::Success.to_c()
            }

            #[no_mangle]
            extern "C" fn [<_nss_ $mod_ident _endpwent>]() -> libc::c_int {
                let mut iter: MutexGuard<PasswdIterator> = [<PASSWD_ $mod_ident _ITERATOR>].lock().unwrap();
                iter.close();

                NssStatus::Success.to_c()
            }

            #[no_mangle]
            unsafe extern "C" fn [<_nss_ $mod_ident _getpwent_r>](pwbuf: *mut CPasswd, buf: *mut libc::c_char, buflen: libc::size_t,
                                                                  _errnop: *mut libc::c_int) -> libc::c_int {
                let mut iter: MutexGuard<PasswdIterator> = [<PASSWD_ $mod_ident _ITERATOR>].lock().unwrap();
                match iter.next() {
                    None => $crate::interop::NssStatus::NotFound.to_c(),
                    Some(entry) => {
                        let mut buffer = CBuffer::new(buf as *mut libc::c_void, buflen);
                        buffer.clear();

                        entry.to_c_passwd(pwbuf, &mut buffer);
                        NssStatus::Success.to_c()
                    }
                }
            }

            #[no_mangle]
            unsafe extern "C" fn [<_nss_ $mod_ident _getpwuid_r>](uid: libc::uid_t, pwbuf: *mut CPasswd, buf: *mut libc::c_char,
                                                           buflen: libc::size_t, _errnop: *mut libc::c_int) -> libc::c_int {
                match super::$hooks_ident::get_entry_by_uid(uid) {
                    Some(val) => {
                        let mut buffer = CBuffer::new(buf as *mut libc::c_void, buflen);
                        buffer.clear();

                        val.to_c_passwd(pwbuf, &mut buffer);
                        NssStatus::Success.to_c()
                    },
                    None => NssStatus::NotFound.to_c()
                }
            }

            #[no_mangle]
            unsafe extern "C" fn [<_nss_ $mod_ident _getpwnam_r>](name_: *const libc::c_char, pwbuf: *mut CPasswd, buf: *mut libc::c_char,
                                                           buflen: libc::size_t, _errnop: *mut libc::c_int) -> libc::c_int {
                let cstr = CStr::from_ptr(name_);

                match str::from_utf8(cstr.to_bytes()) {
                    Ok(name) => match super::$hooks_ident::get_entry_by_name(name.to_string()) {
                        Some(val) => {
                            let mut buffer = CBuffer::new(buf as *mut libc::c_void, buflen);
                            buffer.clear();

                            val.to_c_passwd(pwbuf, &mut buffer);
                            NssStatus::Success.to_c()
                        },
                        None => NssStatus::NotFound.to_c()
                    },
                    Err(_) => NssStatus::NotFound.to_c()
                }
            }
        }
    }
)
}