use crate::interop::CBuffer;

pub struct Shadow {
    pub name: String,
    pub passwd: String,
    pub last_change: i64,
    pub change_min_days: i64,
    pub change_max_days: i64,
    pub change_warn_days: i64,
    pub change_inactive_days: i64,
    pub expire_date: i64,
    pub reserved: u64,
}

impl Shadow {
    pub unsafe fn to_c_shadow(self, pwbuf: *mut CShadow, buffer: &mut CBuffer) {
        (*pwbuf).name = buffer.write_str(self.name);
        (*pwbuf).passwd = buffer.write_str(self.passwd);
        (*pwbuf).last_change = self.last_change;
        (*pwbuf).change_min_days = self.change_min_days;
        (*pwbuf).change_max_days = self.change_max_days;
        (*pwbuf).change_warn_days = self.change_warn_days;
        (*pwbuf).change_inactive_days = self.change_inactive_days;
        (*pwbuf).expire_date = self.expire_date;
        (*pwbuf).reserved = self.reserved;
    }
}

pub trait ShadowHooks {
    fn get_all_entries() -> Vec<Shadow>;

    fn get_entry_by_name(name: String) -> Option<Shadow>;
}

#[repr(C)]
#[allow(missing_copy_implementations)]
pub struct CShadow {
    pub name: *mut libc::c_char,
    pub passwd: *mut libc::c_char,
    pub last_change: i64,
    pub change_min_days: i64,
    pub change_max_days: i64,
    pub change_warn_days: i64,
    pub change_inactive_days: i64,
    pub expire_date: i64,
    pub reserved: u64,
}

#[macro_export]
macro_rules! libnss_shadow_hooks {
($mod_ident:ident, $hooks_ident:ident) => (
    paste::item! {
        pub use self::[<libnss_shadow_ $mod_ident _hooks_impl>]::*;
        mod [<libnss_shadow_ $mod_ident _hooks_impl>] {
            #![allow(non_upper_case_globals)]

            use std::ffi::CStr;
            use std::str;
            use std::sync::{Mutex, MutexGuard};
            use $crate::interop::{CBuffer, Iterator, NssStatus};
            use $crate::shadow::{CShadow, ShadowHooks, Shadow};

            lazy_static! {
            static ref [<SHADOW_ $mod_ident _ITERATOR>]: Mutex<Iterator<Shadow>> = Mutex::new(Iterator::<Shadow>::new());
            }

            #[no_mangle]
            extern "C" fn [<_nss_ $mod_ident _setspent>]() -> libc::c_int {
                let mut iter: MutexGuard<Iterator<Shadow>> = [<SHADOW_ $mod_ident _ITERATOR>].lock().unwrap();
                iter.open(super::$hooks_ident::get_all_entries());
                NssStatus::Success.to_c()
            }

            #[no_mangle]
            extern "C" fn [<_nss_ $mod_ident _endspent>]() -> libc::c_int {
                let mut iter: MutexGuard<Iterator<Shadow>> = [<SHADOW_ $mod_ident _ITERATOR>].lock().unwrap();
                iter.close();

                NssStatus::Success.to_c()
            }

            #[no_mangle]
            unsafe extern "C" fn [<_nss_ $mod_ident _getspent_r>](pwbuf: *mut CShadow, buf: *mut libc::c_char, buflen: libc::size_t,
                                                                  _errnop: *mut libc::c_int) -> libc::c_int {
                let mut iter: MutexGuard<Iterator<Shadow>> = [<SHADOW_ $mod_ident _ITERATOR>].lock().unwrap();
                match iter.next() {
                    None => $crate::interop::NssStatus::NotFound.to_c(),
                    Some(entry) => {
                        let mut buffer = CBuffer::new(buf as *mut libc::c_void, buflen);
                        buffer.clear();

                        entry.to_c_shadow(pwbuf, &mut buffer);
                        NssStatus::Success.to_c()
                    }
                }
            }

            #[no_mangle]
            unsafe extern "C" fn [<_nss_ $mod_ident _getspnam_r>](name_: *const libc::c_char, pwbuf: *mut CShadow, buf: *mut libc::c_char,
                                                                  buflen: libc::size_t, _errnop: *mut libc::c_int) -> libc::c_int {
                let cstr = CStr::from_ptr(name_);

                match str::from_utf8(cstr.to_bytes()) {
                    Ok(name) => match super::$hooks_ident::get_entry_by_name(name.to_string()) {
                        Some(val) => {
                            let mut buffer = CBuffer::new(buf as *mut libc::c_void, buflen);
                            buffer.clear();

                            val.to_c_shadow(pwbuf, &mut buffer);
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