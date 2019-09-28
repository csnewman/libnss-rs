use crate::interop::{CBuffer, Response, ToC};

pub struct Passwd {
    pub name: String,
    pub passwd: String,
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
    pub gecos: String,
    pub dir: String,
    pub shell: String,
}

impl ToC<CPasswd> for Passwd {
    unsafe fn to_c(&self, result: *mut CPasswd, buffer: &mut CBuffer) -> std::io::Result<()> {
        (*result).name = buffer.write_str(&self.name)?;
        (*result).passwd = buffer.write_str(&self.passwd)?;
        (*result).uid = self.uid;
        (*result).gid = self.gid;
        (*result).gecos = buffer.write_str(&self.gecos)?;
        (*result).dir = buffer.write_str(&self.dir)?;
        (*result).shell = buffer.write_str(&self.shell)?;
        Ok(())
    }
}

pub trait PasswdHooks {
    fn get_all_entries() -> Response<Vec<Passwd>>;

    fn get_entry_by_uid(uid: libc::uid_t) -> Response<Passwd>;

    fn get_entry_by_name(name: String) -> Response<Passwd>;
}

#[repr(C)]
#[allow(missing_copy_implementations)]
pub struct CPasswd {
    pub name: *mut libc::c_char,
    pub passwd: *mut libc::c_char,
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
    pub gecos: *mut libc::c_char,
    pub dir: *mut libc::c_char,
    pub shell: *mut libc::c_char,
}

#[macro_export]
macro_rules! libnss_passwd_hooks {
($mod_ident:ident, $hooks_ident:ident) => (
    paste::item! {
        pub use self::[<libnss_passwd_ $mod_ident _hooks_impl>]::*;
        mod [<libnss_passwd_ $mod_ident _hooks_impl>] {
            #![allow(non_upper_case_globals)]

            use libc::c_int;
            use std::ffi::CStr;
            use std::str;
            use std::sync::{Mutex, MutexGuard};
            use $crate::interop::{CBuffer, Iterator, Response};
            use $crate::passwd::{CPasswd, Passwd, PasswdHooks};

            lazy_static! {
            static ref [<PASSWD_ $mod_ident _ITERATOR>]: Mutex<Iterator<Passwd>> = Mutex::new(Iterator::<Passwd>::new());
            }

            #[no_mangle]
            extern "C" fn [<_nss_ $mod_ident _setpwent>]() -> c_int {
                let mut iter: MutexGuard<Iterator<Passwd>> = [<PASSWD_ $mod_ident _ITERATOR>].lock().unwrap();

                let status = match(super::$hooks_ident::get_all_entries()) {
                    Response::Success(entries) => iter.open(entries),
                    response => response.to_status()
                };

                status as c_int
            }

            #[no_mangle]
            extern "C" fn [<_nss_ $mod_ident _endpwent>]() -> c_int {
                let mut iter: MutexGuard<Iterator<Passwd>> = [<PASSWD_ $mod_ident _ITERATOR>].lock().unwrap();
                iter.close() as c_int
            }

            #[no_mangle]
            unsafe extern "C" fn [<_nss_ $mod_ident _getpwent_r>](
                result: *mut CPasswd,
                buf: *mut libc::c_char,
                buflen: libc::size_t,
                errnop: *mut c_int
            ) -> c_int {
                let mut iter: MutexGuard<Iterator<Passwd>> = [<PASSWD_ $mod_ident _ITERATOR>].lock().unwrap();
                iter.next().to_c(result, buf, buflen, errnop) as c_int
            }

            #[no_mangle]
            unsafe extern "C" fn [<_nss_ $mod_ident _getpwuid_r>](
                uid: libc::uid_t,
                result: *mut CPasswd,
                buf: *mut libc::c_char,
                buflen: libc::size_t,
                errnop: *mut c_int
            ) -> c_int {
                super::$hooks_ident::get_entry_by_uid(uid).to_c(result, buf, buflen, errnop) as c_int
            }

            #[no_mangle]
            unsafe extern "C" fn [<_nss_ $mod_ident _getpwnam_r>](
                name_: *const libc::c_char,
                result: *mut CPasswd,
                buf: *mut libc::c_char,
                buflen: libc::size_t,
                errnop: *mut c_int
            ) -> c_int {
                let cstr = CStr::from_ptr(name_);

                let response = match str::from_utf8(cstr.to_bytes()) {
                    Ok(name) => super::$hooks_ident::get_entry_by_name(name.to_string()),
                    Err(_) => Response::NotFound
                };

                response.to_c(result, buf, buflen, errnop) as c_int
            }
        }
    }
)
}
