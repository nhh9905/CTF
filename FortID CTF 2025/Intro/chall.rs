use std::os::raw::{c_char, c_int, c_void};

#[link_section = ".text.patch"]
static PATCHPOINT: [u8; 2] = [0x5F, 0xC3];

#[repr(C)]
struct FILE {
    _priv: [u8; 0],
}

extern "C" {
    fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize;
    fn puts(s: *const c_char) -> c_int;
    fn system(cmd: *const c_char) -> c_int;
    fn exit(code: c_int) -> !;
    static mut stdout: *mut FILE;
    fn setbuf(stream: *mut FILE, buf: *mut c_char);
}

const WELCOME: &[u8] = b"Welcome to my first Rust program!\n\0";
const PROMPT: &[u8] = b"Say something:\n\0";
const BYE: &[u8] = b"Bye!\n\0";
const NOPE: &[u8] = b"nope\n\0";
const BINSH: &[u8] = b"/bin/sh\0";

#[no_mangle]
pub extern "C" fn win(key: u64) {
    unsafe {
        if key != 0xdeadbeefcafebabeu64 {
            puts(NOPE.as_ptr() as *const c_char);
            exit(1);
        }
        system(BINSH.as_ptr() as *const c_char);
    }
}

pub extern "C" fn vuln() {
    let mut buf = [0u8; 64];
    unsafe {
        setbuf(stdout, std::ptr::null_mut());
        puts(PROMPT.as_ptr() as *const c_char);
        read(0, buf.as_mut_ptr() as *mut c_void, 0x200);
    }
}

fn main() {
    unsafe {
        puts(WELCOME.as_ptr() as *const c_char);
    }
    vuln();
    unsafe {
        puts(BYE.as_ptr() as *const c_char);
    }
}
