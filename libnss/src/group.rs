use crate::interop::CBuffer;
use std::collections::VecDeque;
use std::mem;

pub struct Group {
    pub name: String,
    pub passwd: String,
    pub gid: libc::gid_t,
    pub members: Vec<String>,
}

impl Group {
    pub unsafe fn to_c_group(self, pwbuf: *mut CGroup, buffer: &mut CBuffer) {
        (*pwbuf).name = buffer.write_str(self.name);
        (*pwbuf).passwd = buffer.write_str(self.passwd);
        (*pwbuf).gid = self.gid;

        // Allocate array
        let ptr_size = mem::size_of::<*mut libc::c_char>() as isize;
        let mut array_pos = buffer.reserve(ptr_size * ((self.members.len() + 1) as isize)) as *mut *mut libc::c_char;
        (*pwbuf).members = array_pos;

        // Store elements
        for member in self.members {
            // Store string
            let pos = buffer.write_str(member);
            *array_pos = pos;

            // Offset pointer
            array_pos = array_pos.offset(1);
        }
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

pub struct GroupIterator {
    items: Option<VecDeque<Group>>,
}

impl GroupIterator {
    pub fn new() -> Self {
        GroupIterator {
            items: None,
        }
    }

    pub fn open(&mut self, items: Vec<Group>) {
        self.items = Some(VecDeque::from(items));
    }

    pub fn next(&mut self) -> Option<Group> {
        match self.items {
            Some(ref mut val) => val.pop_front(),
            None => panic!("Iterator not currently open")
        }
    }

    pub fn close(&mut self) {
        self.items = None;
    }
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
            use $crate::interop::{CBuffer, NssStatus};
            use $crate::group::{CGroup, GroupHooks, GroupIterator};

            lazy_static! {
            static ref [<GROUP_ $mod_ident _ITERATOR>]: Mutex<GroupIterator> = Mutex::new(GroupIterator::new());
            }

            #[no_mangle]
            extern "C" fn [<_nss_ $mod_ident _setgrent>]() -> libc::c_int {
                let mut iter: MutexGuard<GroupIterator> = [<GROUP_ $mod_ident _ITERATOR>].lock().unwrap();
                iter.open(super::$hooks_ident::get_all_entries());
                NssStatus::Success.to_c()
            }

            #[no_mangle]
            extern "C" fn [<_nss_ $mod_ident _endgrent>]() -> libc::c_int {
                let mut iter: MutexGuard<GroupIterator> = [<GROUP_ $mod_ident _ITERATOR>].lock().unwrap();
                iter.close();

                NssStatus::Success.to_c()
            }

            #[no_mangle]
            unsafe extern "C" fn [<_nss_ $mod_ident _getgrent_r>](pwbuf: *mut CGroup, buf: *mut libc::c_char, buflen: libc::size_t,
                                                                  _errnop: *mut libc::c_int) -> libc::c_int {
                let mut iter: MutexGuard<GroupIterator> = [<GROUP_ $mod_ident _ITERATOR>].lock().unwrap();
                match iter.next() {
                    None => $crate::interop::NssStatus::NotFound.to_c(),
                    Some(entry) => {
                        let mut buffer = CBuffer::new(buf as *mut libc::c_void, buflen);
                        buffer.clear();

                        entry.to_c_group(pwbuf, &mut buffer);
                        NssStatus::Success.to_c()
                    }
                }
            }

            #[no_mangle]
            unsafe extern "C" fn [<_nss_ $mod_ident _getgrgid_r>](uid: libc::gid_t, pwbuf: *mut CGroup, buf: *mut libc::c_char,
                                                                  buflen: libc::size_t, _errnop: *mut libc::c_int) -> libc::c_int {
                match super::$hooks_ident::get_entry_by_gid(uid) {
                    Some(val) => {
                        let mut buffer = CBuffer::new(buf as *mut libc::c_void, buflen);
                        buffer.clear();

                        val.to_c_group(pwbuf, &mut buffer);
                        NssStatus::Success.to_c()
                    },
                    None => NssStatus::NotFound.to_c()
                }
            }

            #[no_mangle]
            unsafe extern "C" fn [<_nss_ $mod_ident _getgrnam_r>](name_: *const libc::c_char, pwbuf: *mut CGroup, buf: *mut libc::c_char,
                                                                  buflen: libc::size_t, _errnop: *mut libc::c_int) -> libc::c_int {
                let cstr = CStr::from_ptr(name_);

                match str::from_utf8(cstr.to_bytes()) {
                    Ok(name) => match super::$hooks_ident::get_entry_by_name(name.to_string()) {
                        Some(val) => {
                            let mut buffer = CBuffer::new(buf as *mut libc::c_void, buflen);
                            buffer.clear();

                            val.to_c_group(pwbuf, &mut buffer);
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