#![allow(dead_code, unused_variables)]
// Struct should be declared with #[repr(C)] attribute.
// Use C types from `libc` crate for mapping.
// `rust-bindgen` gen bindings to C libs from C headers.
// Example for testing purpose:
// - Copy C struct def
// - Convert C types to Rust types
// - Impl function interfaces

// E.g. zlib.c
// struct gzFile_s {
//   unsigned have;
//   unsigned char *next;
//   z_off64_t pos;
// };

// Mapping Rust struct after conversion:
use core::ffi::{c_uchar, c_uint};

#[repr(C)]
struct GzFileState {
    have: c_uint,
    next: *mut c_uchar,
    pos: i64,
}

type GzFile = *mut GzFileState;

// #[link(name = "z")]
// extern "C" {
// fn gzopen(path: *const c_char, mode: *const c_char) -> GzFile;
// }

// fn read_gz_file(name: &str) -> String {
//     let mut buffer = [0u8; 0x1000];
//     let mut contents = String::new();
//     unsafe {
//         let c_name = CString::new(name).exp
//     }
// }
