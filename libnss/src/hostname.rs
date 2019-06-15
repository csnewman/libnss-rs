
use crate::interop::CBuffer;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};


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
            },
            Addresses::V6(addrs) => {
                (*hostent).h_addrtype = libc::AF_INET6;
                (*hostent).h_length = 16;

                (16, addrs.len())
            },
        };

        let mut array_pos = buffer.reserve(ptr_size * (count as isize) + 1)  as *mut *mut libc::c_char;
        (*hostent).h_addr_list = array_pos;

        match &self.addresses {
            Addresses::V4(addrs) => {
                for a in addrs {
                    let ptr = buffer.reserve(addr_len);

                    let o = a.octets();
                    libc::memcpy(ptr as *mut libc::c_void, o.as_ptr() as *mut libc::c_void, addr_len as usize);
                    
                    *array_pos = ptr;

                    array_pos = array_pos.offset(1);
                }
            },
            Addresses::V6(addrs) => {
                for a in addrs {
                    let ptr = buffer.reserve(addr_len);

                    let o = a.octets();
                    libc::memcpy(ptr as *mut libc::c_void, o.as_ptr() as *mut libc::c_void, addr_len as usize);
                    
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
