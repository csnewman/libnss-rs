use crate::interop::CBuffer;
use std::collections::VecDeque;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct Host {
    pub name: String,
    pub aliases: Vec<String>,
    pub addresses: Addresses,
}

pub enum Addresses {
    V4(Vec<Ipv4Addr>),
    V6(Vec<Ipv6Addr>),
}

impl Host {
    pub unsafe fn to_c_hostent(self, hostent: *mut CHost, buffer: &mut CBuffer) {
        (*hostent).name = buffer.write_str(self.name);
        (*hostent).h_aliases = buffer.write_strs(&self.aliases);

        let ptr_size = mem::size_of::<*mut libc::c_char>() as isize;

        let (addr_len, count) = match &self.addresses {
            Addresses::V4(addrs) => {
                (*hostent).h_addrtype = libc::AF_INET;
                (*hostent).h_length = 4;

                (4, addrs.len())
            }
            Addresses::V6(addrs) => {
                (*hostent).h_addrtype = libc::AF_INET6;
                (*hostent).h_length = 16;

                (16, addrs.len())
            }
        };

        let mut array_pos =
            buffer.reserve(ptr_size * (count as isize) + 1) as *mut *mut libc::c_char;
        (*hostent).h_addr_list = array_pos;

        match &self.addresses {
            Addresses::V4(addrs) => {
                for a in addrs {
                    let ptr = buffer.reserve(addr_len);

                    let o = a.octets();
                    libc::memcpy(
                        ptr as *mut libc::c_void,
                        o.as_ptr() as *mut libc::c_void,
                        addr_len as usize,
                    );

                    *array_pos = ptr;
                    array_pos = array_pos.offset(1);
                }
            }
            Addresses::V6(addrs) => {
                for a in addrs {
                    let ptr = buffer.reserve(addr_len);

                    let o = a.octets();
                    libc::memcpy(
                        ptr as *mut libc::c_void,
                        o.as_ptr() as *mut libc::c_void,
                        addr_len as usize,
                    );

                    *array_pos = ptr;
                    array_pos = array_pos.offset(1);
                }
            }
        }

        // Write null termination
        libc::memset(array_pos as *mut libc::c_void, 0, 1);

        // Set single / first address
        (*hostent).h_addr = *(*hostent).h_addr_list;
    }
}

pub trait HostHooks {
    fn get_all_entries() -> Vec<Host>;

    fn get_host_by_name(name: &str) -> Option<Host>;

    fn get_host_by_addr(addr: IpAddr) -> Option<Host>;
}

/// NSS C Host object
/// https://ftp.gnu.org/old-gnu/Manuals/glibc-2.2.3/html_chapter/libc_16.html#SEC318
#[repr(C)]
#[allow(missing_copy_implementations)]
pub struct CHost {
    pub name: *mut libc::c_char,
    pub h_aliases: *mut libc::c_char,
    pub h_addrtype: libc::c_int,
    pub h_length: libc::c_int,
    pub h_addr_list: *mut *mut libc::c_char,
    pub h_addr: *mut libc::c_char,
}

pub struct HostIterator {
    items: Option<VecDeque<Host>>,
}

impl HostIterator {
    pub fn new() -> Self {
        HostIterator { items: None }
    }

    pub fn open(&mut self, items: Vec<Host>) {
        self.items = Some(VecDeque::from(items));
    }

    pub fn next(&mut self) -> Option<Host> {
        match self.items {
            Some(ref mut val) => val.pop_front(),
            None => panic!("Iterator not currently open"),
        }
    }

    pub fn close(&mut self) {
        self.items = None;
    }
}

#[macro_export]
macro_rules! libnss_host_hooks {
($mod_ident:ident, $hooks_ident:ident) => (
    paste::item! {
        pub use self::[<libnss_host_ $mod_ident _hooks_impl>]::*;
        mod [<libnss_host_ $mod_ident _hooks_impl>] {
            #![allow(non_upper_case_globals)]

            use std::ffi::CStr;
            use std::str;
            use std::sync::{Mutex, MutexGuard};
            use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
            use $crate::interop::{CBuffer, NssStatus};
            use $crate::host::{CHost, HostHooks, HostIterator};

            lazy_static! {
            static ref [<HOST_ $mod_ident _ITERATOR>]: Mutex<HostIterator> = Mutex::new(HostIterator::new());
            }

            #[no_mangle]
            extern "C" fn [<_nss_ $mod_ident _sethostent>]() -> libc::c_int {
                let mut iter: MutexGuard<HostIterator> = [<HOST_ $mod_ident _ITERATOR>].lock().unwrap();
                iter.open(super::$hooks_ident::get_all_entries());
                NssStatus::Success.to_c()
            }

            #[no_mangle]
            extern "C" fn [<_nss_ $mod_ident _endhostent>]() -> libc::c_int {
                let mut iter: MutexGuard<HostIterator> = [<HOST_ $mod_ident _ITERATOR>].lock().unwrap();
                iter.close();
                NssStatus::Success.to_c()
            }

            #[no_mangle]
            unsafe extern "C" fn [<_nss_ $mod_ident _gethostent_r>](hostbuf: *mut CHost, buf: *mut libc::c_char, buflen: libc::size_t,
                                                                  _errnop: *mut libc::c_int) -> libc::c_int {
                let mut iter: MutexGuard<HostIterator> = [<HOST_ $mod_ident _ITERATOR>].lock().unwrap();
                match iter.next() {
                    None => $crate::interop::NssStatus::NotFound.to_c(),
                    Some(entry) => {
                        let mut buffer = CBuffer::new(buf as *mut libc::c_void, buflen);
                        buffer.clear();

                        entry.to_c_hostent(hostbuf, &mut buffer);
                        NssStatus::Success.to_c()
                    }
                }
            }

            #[no_mangle]
            unsafe extern "C" fn [<_nss_ $mod_ident _gethostbyaddr_r>](addr: *const libc::c_char, len: libc::size_t, format: libc::c_int, hostbuf: *mut CHost, buf: *mut libc::c_char, buflen: libc::size_t, result: *mut *mut CHost, _errnop: *mut libc::c_int) -> libc::c_int {
                // Convert address type
                let a = match (len, format) {
                    (4, libc::AF_INET) => {
                        let mut p = [0u8; 4];
                        libc::memcpy(p.as_ptr() as *mut libc::c_void, addr as *mut libc::c_void, 4);
                        IpAddr::V4(Ipv4Addr::from(p))
                    },
                    (16, libc::AF_INET6) => {
                        let mut p = [0u8; 16];
                        libc::memcpy(p.as_ptr() as *mut libc::c_void, addr as *mut libc::c_void, 16);
                        IpAddr::V6(Ipv6Addr::from(p))
                    },
                    _ => {
                        //error!("address length and format mismatch (length: {}, format: {})", len, format);
                        return NssStatus::NotFound.to_c();
                    }
                };


                match super::$hooks_ident::get_host_by_addr(a) {
                    Some(val) => {
                        let mut buffer = CBuffer::new(buf as *mut libc::c_void, buflen);
                        buffer.clear();

                        val.to_c_hostent(hostbuf, &mut buffer);
                        NssStatus::Success.to_c()
                    },
                    None => NssStatus::NotFound.to_c()
                }
            }

            #[no_mangle]
            unsafe extern "C" fn [<_nss_ $mod_ident _gethostbyname_r>](name_: *const libc::c_char, hostbuf: *mut CHost, buf: *mut libc::c_char, buflen: libc::size_t, result: *mut *mut CHost, _errnop: *mut libc::c_int) -> libc::c_int {
                let cstr = CStr::from_ptr(name_);

                match str::from_utf8(cstr.to_bytes()) {
                    Ok(name) => match super::$hooks_ident::get_host_by_name(&name.to_string()) {
                        Some(val) => {
                            let mut buffer = CBuffer::new(buf as *mut libc::c_void, buflen);
                            buffer.clear();

                            val.to_c_hostent(hostbuf, &mut buffer);
                            NssStatus::Success.to_c()
                        },
                        None => NssStatus::NotFound.to_c()
                    },
                    Err(_) => NssStatus::NotFound.to_c()
                }
            }


        }
    }
)}
