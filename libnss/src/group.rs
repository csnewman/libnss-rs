use crate::interop::CBuffer;

pub struct Group {
    pub name: String,
    pub passwd: String,
    pub gid: libc::gid_t,
    pub members: Vec<String>,
}

impl Group {
    pub unsafe fn to_c_group(
        self,
        pwbuf: *mut CGroup,
        buffer: &mut CBuffer,
    ) -> std::io::Result<()> {
        (*pwbuf).name = buffer.write_str(self.name)?;
        (*pwbuf).passwd = buffer.write_str(self.passwd)?;
        (*pwbuf).gid = self.gid;
        (*pwbuf).members = buffer.write_strs(&self.members)?;
        Ok(())
    }
}

pub trait GroupHooks {
    fn get_all_entries() -> Vec<Group>;

    fn get_entry_by_gid(gid: libc::gid_t) -> Option<Group>;

    fn get_entry_by_name(name: String) -> Option<Group>;
}

#[repr(C)]
#[allow(missing_copy_implementations)]
pub struct CGroup {
    pub name: *mut libc::c_char,
    pub passwd: *mut libc::c_char,
    pub gid: libc::gid_t,
    pub members: *mut *mut libc::c_char,
}

#[macro_export]
macro_rules! libnss_group_hooks {
($mod_ident:ident, $hooks_ident:ident) => (
    paste::item! {
        pub use self::[<libnss_group_ $mod_ident _hooks_impl>]::*;
        mod [<libnss_group_ $mod_ident _hooks_impl>] {
            #![allow(non_upper_case_globals)]

            use std::ffi::CStr;
            use std::str;
            use std::sync::{Mutex, MutexGuard};
            use $crate::interop::{CBuffer, Iterator, NssStatus};
            use $crate::group::{CGroup, GroupHooks, Group};

            lazy_static! {
            static ref [<GROUP_ $mod_ident _ITERATOR>]: Mutex<Iterator<Group>> = Mutex::new(Iterator::<Group>::new());
            }

            #[no_mangle]
            extern "C" fn [<_nss_ $mod_ident _setgrent>]() -> libc::c_int {
                let mut iter: MutexGuard<Iterator<Group>> = [<GROUP_ $mod_ident _ITERATOR>].lock().unwrap();
                iter.open(super::$hooks_ident::get_all_entries());
                NssStatus::Success.to_c()
            }

            #[no_mangle]
            extern "C" fn [<_nss_ $mod_ident _endgrent>]() -> libc::c_int {
                let mut iter: MutexGuard<Iterator<Group>> = [<GROUP_ $mod_ident _ITERATOR>].lock().unwrap();
                iter.close();

                NssStatus::Success.to_c()
            }

            #[no_mangle]
            unsafe extern "C" fn [<_nss_ $mod_ident _getgrent_r>](pwbuf: *mut CGroup, buf: *mut libc::c_char, buflen: libc::size_t,
                                                                  errnop: *mut libc::c_int) -> libc::c_int {
                let mut iter: MutexGuard<Iterator<Group>> = [<GROUP_ $mod_ident _ITERATOR>].lock().unwrap();
                match iter.next() {
                    None => $crate::interop::NssStatus::NotFound.to_c(),
                    Some(entry) => {
                        let mut buffer = CBuffer::new(buf as *mut libc::c_void, buflen);
                        buffer.clear();

                        match entry.to_c_group(pwbuf, &mut buffer) {
                            Err(e) => {
                                match e.raw_os_error() {
                                   Some(e) =>{
                                       *errnop = e;
                                       NssStatus::TryAgain.to_c()
                                   },
                                   None => {
                                       *errnop = libc::ENOENT;
                                       NssStatus::Unavail.to_c()
                                   }
                               }
                            },
                            Ok(_) => {
                                *errnop = 0;
                                NssStatus::Success.to_c()
                            }
                        }
                    }
                }
            }

            #[no_mangle]
            unsafe extern "C" fn [<_nss_ $mod_ident _getgrgid_r>](uid: libc::gid_t, pwbuf: *mut CGroup, buf: *mut libc::c_char,
                                                                  buflen: libc::size_t, errnop: *mut libc::c_int) -> libc::c_int {
                match super::$hooks_ident::get_entry_by_gid(uid) {
                    Some(val) => {
                        let mut buffer = CBuffer::new(buf as *mut libc::c_void, buflen);
                        buffer.clear();

                        match val.to_c_group(pwbuf, &mut buffer) {
                            Err(e) => {
                                match e.raw_os_error() {
                                   Some(e) =>{
                                       *errnop = e;
                                       NssStatus::TryAgain.to_c()
                                   },
                                   None => {
                                       *errnop = libc::ENOENT;
                                       NssStatus::Unavail.to_c()
                                   }
                               }
                            },
                            Ok(_) => {
                                *errnop = 0;
                                NssStatus::Success.to_c()
                            }
                        }
                    },
                    None => NssStatus::NotFound.to_c()
                }
            }

            #[no_mangle]
            unsafe extern "C" fn [<_nss_ $mod_ident _getgrnam_r>](name_: *const libc::c_char, pwbuf: *mut CGroup, buf: *mut libc::c_char,
                                                                  buflen: libc::size_t, errnop: *mut libc::c_int) -> libc::c_int {
                let cstr = CStr::from_ptr(name_);

                match str::from_utf8(cstr.to_bytes()) {
                    Ok(name) => match super::$hooks_ident::get_entry_by_name(name.to_string()) {
                        Some(val) => {
                            let mut buffer = CBuffer::new(buf as *mut libc::c_void, buflen);
                            buffer.clear();

                            match val.to_c_group(pwbuf, &mut buffer) {
                                Err(e) => {
                                    match e.raw_os_error() {
                                       Some(e) =>{
                                           *errnop = e;
                                           NssStatus::TryAgain.to_c()
                                       },
                                       None => {
                                           *errnop = libc::ENOENT;
                                           NssStatus::Unavail.to_c()
                                       }
                                   }
                                },
                                Ok(_) => {
                                    *errnop = 0;
                                    NssStatus::Success.to_c()
                                }
                            }
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