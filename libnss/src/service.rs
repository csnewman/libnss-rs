use crate::interop::{CBuffer, Response, ToC};

#[derive(Clone)]
pub struct Service {
    pub name: String,
    pub aliases: Vec<String>,
    pub port: u16,
    pub proto: String,
}

impl ToC<CService> for Service {
    unsafe fn to_c(&self, result: *mut CService, buffer: &mut CBuffer) -> std::io::Result<()> {
        (*result).s_name = buffer.write_str(&self.name)?;
        (*result).s_aliases = buffer.write_strs(&self.aliases[..])?;
        (*result).s_port = self.port.to_be() as libc::c_int;
        (*result).s_proto = buffer.write_str(&self.proto)?;
        Ok(())
    }
}

pub trait ServiceHooks {
    fn get_all_entries() -> Response<Vec<Service>>;

    fn get_service_by_name(name: &str, proto: Option<&str>) -> Response<Service>;

    fn get_service_by_port(port: u16, proto: Option<&str>) -> Response<Service>;
}

#[repr(C)]
#[allow(missing_copy_implementations)]
pub struct CService {
    pub s_name: *mut libc::c_char,
    pub s_aliases: *mut *mut libc::c_char,
    pub s_port: libc::c_int,
    pub s_proto: *mut libc::c_char,
}

#[macro_export]
macro_rules! libnss_service_hooks {
($mod_ident:ident, $hooks_ident:ident) => (
    $crate::_macro_internal::paste! {
        pub use self::[<libnss_service_ $mod_ident _hooks_impl>]::*;
        mod [<libnss_service_ $mod_ident _hooks_impl>] {
            #![allow(non_upper_case_globals)]

            use libc::c_int;
            use std::ffi::CStr;
            use std::ptr::null_mut;
            use std::str;
            use std::sync::{Mutex, MutexGuard};
            use $crate::interop::{CBuffer, Iterator, Response, NssStatus};
            use $crate::service::{CService, Service, ServiceHooks};

            $crate::_macro_internal::lazy_static! {
            static ref [<SERVICE_ $mod_ident _ITERATOR>]: Mutex<Iterator<Service>> = Mutex::new(Iterator::<Service>::new());
            }

            unsafe fn convert_proto<'a>(proto: *const libc::c_char) -> Response<Option<&'a str>> {
                if proto.is_null() {
                    Response::Success(None)
                } else {
                    if let Ok(proto) = str::from_utf8(CStr::from_ptr(proto).to_bytes()) {
                        Response::Success(Some(proto))
                    } else {
                        Response::NotFound
                    }
                }
            }

            #[no_mangle]
            extern "C" fn [<_nss_ $mod_ident _setservent>]() -> c_int {
                let mut iter: MutexGuard<Iterator<Service>> = [<SERVICE_ $mod_ident _ITERATOR>].lock().unwrap();

                let status = match(<super::$hooks_ident as ServiceHooks>::get_all_entries()) {
                    Response::Success(entries) => iter.open(entries),
                    response => response.to_status()
                };

                status as c_int
            }

            #[no_mangle]
            extern "C" fn [<_nss_ $mod_ident _endservent>]() -> c_int {
                let mut iter: MutexGuard<Iterator<Service>> = [<SERVICE_ $mod_ident _ITERATOR>].lock().unwrap();
                iter.close() as c_int
            }

            #[no_mangle]
            unsafe extern "C" fn [<_nss_ $mod_ident _getservent_r>](
                result_buf: *mut CService,
                buf: *mut libc::c_char,
                buflen: libc::size_t,
                result: *mut *mut CService
            ) -> c_int {
                let mut iter: MutexGuard<Iterator<Service>> = [<SERVICE_ $mod_ident _ITERATOR>].lock().unwrap();
                let code: c_int = iter.next().to_c(result_buf, buf, buflen, None) as c_int;
                if code == NssStatus::TryAgain as c_int {
                    iter.previous();
                }
                if code == NssStatus::Success as c_int {
                    *result = result_buf;
                } else {
                    *result = null_mut();
                }
                return code;
            }

            #[no_mangle]
            unsafe extern "C" fn [<_nss_ $mod_ident _getservbyname_r>](
                name: *const libc::c_char,
                proto: *const libc::c_char,
                result_buf: *mut CService,
                buf: *mut libc::c_char,
                buflen: libc::size_t,
                result: *mut *mut CService
            ) -> c_int {
                let c_name = CStr::from_ptr(name);

                let proto_result = convert_proto(proto);
                let proto = match proto_result {
                    Response::Success(proto) => proto,
                    _ => {
                        return proto_result.to_status() as c_int;
                    }
                };

                let response = match str::from_utf8(c_name.to_bytes()) {
                    Ok(name) => <super::$hooks_ident as ServiceHooks>::get_service_by_name(name, proto),
                    Err(_) => Response::NotFound
                };

                let code: c_int = response.to_c(result_buf, buf, buflen, None) as c_int;
                if code == NssStatus::Success as c_int {
                    *result = result_buf;
                } else {
                    *result = null_mut();
                }
                return code;
            }

           #[no_mangle]
            unsafe extern "C" fn [<_nss_ $mod_ident _getservbyport_r>](
                port: i32,
                proto: *const libc::c_char,
                result_buf: *mut CService,
                buf: *mut libc::c_char,
                buflen: libc::size_t,
                result: *mut *mut CService
            ) -> c_int {
                let proto_result = convert_proto(proto);
                let response = match proto_result {
                    Response::Success(proto) =>
                        <super::$hooks_ident as ServiceHooks>::get_service_by_port(u16::from_be(port as u16), proto),
                    _ => Response::NotFound,
                };

                let code: c_int = response.to_c(result_buf, buf, buflen, None) as c_int;
                if code == NssStatus::Success as c_int {
                    *result = result_buf;
                } else {
                    *result = null_mut();
                }
                return code;
            }
        }
    })
}
