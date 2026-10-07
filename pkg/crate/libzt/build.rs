extern crate bindgen;

use std::env;
use std::path::{Path, PathBuf};

fn main() {
    let dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    // Root of the libzt source tree when the crate is built in-tree
    let repo_root = dir.join("../../..");
    let in_tree = repo_root.join("CMakeLists.txt").exists();

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=LIBZT_LIB_DIR");

    // Native library: use a prebuilt libzt.a from LIBZT_LIB_DIR if given,
    // otherwise build it from the source tree.
    let lib_dir = match env::var("LIBZT_LIB_DIR") {
        Ok(lib_dir) => PathBuf::from(lib_dir),
        Err(_) => {
            if !in_tree {
                panic!(
                    "libzt sources not found at {}. Set LIBZT_LIB_DIR to a directory containing libzt.a",
                    repo_root.display()
                );
            }
            for src in &["CMakeLists.txt", "src", "include", "ext"] {
                println!("cargo:rerun-if-changed={}", repo_root.join(src).display());
            }
            // ZTS_ENABLE_RUST builds only the static library. The project
            // has no install target in this mode, so build the target
            // directly and pick the archive up from the build tree.
            let dst = cmake::Config::new(&repo_root)
                .define("ZTS_ENABLE_RUST", "1")
                .build_target("zt-static")
                .build();
            dst.join("build").join("lib")
        }
    };

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=zt");

    // The core is written in C++, link the platform's C++ runtime
    let target = env::var("TARGET").unwrap();
    if target.contains("apple") || target.contains("freebsd") || target.contains("openbsd") {
        println!("cargo:rustc-link-lib=dylib=c++");
    } else if target.contains("msvc") {
        // The C++ runtime is linked implicitly
    } else {
        println!("cargo:rustc-link-lib=dylib=stdc++");
    }
    if target.contains("windows") {
        for lib in &["ws2_32", "shlwapi", "iphlpapi"] {
            println!("cargo:rustc-link-lib=dylib={}", lib);
        }
    }

    // Prefer the header from the source tree so the bindings never go stale,
    // fall back to the bundled copy (packaged crate)
    let tree_header = repo_root.join("include/ZeroTierSockets.h");
    let header = if tree_header.exists() {
        tree_header
    } else {
        dir.join("src/include/ZeroTierSockets.h")
    };
    println!("cargo:rerun-if-changed={}", header.display());

    let bindings = bindgen::Builder::default()
        .header(header.to_string_lossy())
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .size_t_is_usize(true)
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(Path::new(&out_path).join("libzt.rs"))
        .expect("Couldn't write bindings!");
}
