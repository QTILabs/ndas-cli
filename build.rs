use bindgen;
use std::boxed::Box;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

fn main() {
    // Tell cargo to tell rustc to link the system bzip2
    // shared library.
    println!("cargo:rustc-link-lib=static=ndaskernel-hook");
    println!("cargo:rustc-link-lib=static=pcapng");
    println!("cargo:rustc-link-lib=static=z");
    println!("cargo:rustc-link-lib=static=elf");
    println!("cargo:rustc-link-lib=static=bpf");

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=ndas-kernel-ffi.h");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("ndas-kernel-ffi.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let binding_path = out_path.join("bindings.rs");
    let mut binding_file = Box::new(File::create(binding_path.clone()).expect("Couldn't write bindings!"));
    binding_file
        .write(b"#[allow(dead_code)]\n\nmod ndas_kernel_ffi {\n")
        .expect("Couldn't write bindings!");
    Box::new(bindings).write(binding_file).expect("Couldn't write bindings!");
    OpenOptions::new()
        .append(true)
        .open(binding_path)
        .expect("Cannot open bindings.rs!")
        .write(b"}\n")
        .expect("Couldn't write bindings!");
}
