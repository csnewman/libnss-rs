use crate::interop::{CBuffer, Response, ToC};

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

impl ToC<CShadow> for Shadow {
    unsafe fn to_c(&self, result: *mut CShadow, buffer: &mut CBuffer) -> std::io::Result<()> {
        (*result).name = buffer.write_str(&self.name)?;
        (*result).passwd = buffer.write_str(&self.passwd)?;
        (*result).last_change = self.last_change;
        (*result).change_min_days = self.change_min_days;
        (*result).change_max_days = self.change_max_days;
        (*result).change_warn_days = self.change_warn_days;
        (*result).change_inactive_days = self.change_inactive_days;
        (*result).expire_date = self.expire_date;
        (*result).reserved = self.reserved;
        Ok(())
    }
}

pub trait ShadowHooks {
    fn get_all_entries() -> Response<Vec<Shadow>>;

    fn get_entry_by_name(name: String) -> Response<Shadow>;
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

            use libc::c_int;
            use std::ffi::CStr;
            use std::str;
            use std::sync::{Mutex, MutexGuard};
            use $crate::interop::{CBuffer, Iterator, Response};
            use $crate::shadow::{CShadow, ShadowHooks, Shadow};

            lazy_static! {
            static ref [<SHADOW_ $mod_ident _ITERATOR>]: Mutex<Iterator<Shadow>> = Mutex::new(Iterator::<Shadow>::new());
            }

            #[no_mangle]
            extern "C" fn [<_nss_ $mod_ident _setspent>]() -> c_int {
                let mut iter: MutexGuard<Iterator<Shadow>> = [<SHADOW_ $mod_ident _ITERATOR>].lock().unwrap();
                let status = match(super::$hooks_ident::get_all_entries()) {
                    Response::Success(entries) => iter.open(entries),
                    response => response.to_status()
                };
                status as c_int
            }

            #[no_mangle]
            extern "C" fn [<_nss_ $mod_ident _endspent>]() -> c_int {
                let mut iter: MutexGuard<Iterator<Shadow>> = [<SHADOW_ $mod_ident _ITERATOR>].lock().unwrap();
                iter.close() as c_int
            }

            #[no_mangle]
            unsafe extern "C" fn [<_nss_ $mod_ident _getspent_r>](
                result: *mut CShadow,
                buf: *mut libc::c_char,
                buflen: libc::size_t,
                errnop: *mut c_int
            ) -> c_int {
                let mut iter: MutexGuard<Iterator<Shadow>> = [<SHADOW_ $mod_ident _ITERATOR>].lock().unwrap();
                iter.next().to_c(result, buf, buflen, errnop) as c_int
            }

            #[no_mangle]
            unsafe extern "C" fn [<_nss_ $mod_ident _getspnam_r>](
                name_: *const libc::c_char,
                result: *mut CShadow,
                buf: *mut libc::c_char,
                buflen: libc::size_t,
                errnop: *mut c_int
            ) -> c_int {
                let cstr = CStr::from_ptr(name_);

                match str::from_utf8(cstr.to_bytes()) {
                    Ok(name) => super::$hooks_ident::get_entry_by_name(name.to_string()),
                    Err(_) => Response::NotFound
                }.to_c(result, buf, buflen, errnop) as c_int
            }
        }
    }
)
}
