use libc::c_int;
use std::ffi::CString;

#[allow(dead_code)]
pub enum NssStatus {
    TryAgain,
    Unavail,
    NotFound,
    Success,
    Return,
}

impl NssStatus {
    pub fn to_c(&self) -> c_int {
        match *self {
            NssStatus::TryAgain => -2,
            NssStatus::Unavail => -1,
            NssStatus::NotFound => 0,
            NssStatus::Success => 1,
            NssStatus::Return => 2,
        }
    }
}

pub struct CBuffer {
    start: *mut libc::c_void,
    pos: *mut libc::c_void,
    free: libc::size_t,
    len: libc::size_t,
}

impl CBuffer {
    pub fn new(ptr: *mut libc::c_void, len: libc::size_t) -> Self {
        CBuffer {
            start: ptr,
            pos: ptr,
            free: len,
            len,
        }
    }

    pub unsafe fn clear(&mut self) {
        libc::memset(self.start, 0, self.len);
    }

    pub unsafe fn write_str(&mut self, string: String) -> *mut libc::c_char {
        // Capture start address
        let str_start = self.pos;

        // Convert string
        let cstr = CString::new(string).expect("Failed to convert string");
        let ptr = cstr.as_ptr();
        let len = libc::strlen(ptr);

        // Ensure we have enough capacity
        if self.free < len + 1 {
            panic!("Not enough free space in buffer");
        }

        // Copy string
        libc::memcpy(self.pos, ptr as *mut libc::c_void, len);
        self.pos = self.pos.offset(len as isize + 1);
        self.free -= len as usize + 1;

        // Return start of string
        str_start as *mut libc::c_char
    }

    pub unsafe fn reserve(&mut self, len: isize) -> *mut libc::c_char {
        let start = self.pos;

        // Ensure we have enough capacity
        if self.free < len as usize {
            panic!("Not enough free space in buffer");
        }

        // Reserve space
        self.pos = self.pos.offset(len as isize);
        self.free -= len as usize;

        start as *mut libc::c_char
    }
}