# libzt - Sockets over ZeroTier

`libzt` replicates the functionality of [std::net](https://doc.rust-lang.org/std/net/index.html) but uses [ZeroTier](https://www.zerotier.com) as its P2P transport layer.

Securely connect application instances, physical devices, and virtual devices as if everything is on a single LAN.

## Dependencies

The `libzt` crate is a binding around a C/C++ native library (`libzt.a`). When the crate is built from within the [libzt source tree](https://github.com/zerotier/libzt) (`pkg/crate/libzt`), `build.rs` builds the native library automatically with CMake (requires CMake and a C/C++ toolchain; check out the git submodules first with `git submodule update --init`) and generates the bindings from `include/ZeroTierSockets.h`.

To link against a prebuilt static library instead, point `LIBZT_LIB_DIR` at the directory containing `libzt.a`:

```
LIBZT_LIB_DIR=/path/to/lib cargo build
```

Run the offline tests with `cargo test` (no network access needed).

*Note: Windows is untested but support is planned.*

## Usage

Add the following to your `Cargo.toml`:

```toml
[dependencies]
libzt = "0.2.0"
```

## Docs

 - See: [docs.zerotier.com/sockets](https://docs.zerotier.com/sockets/tutorial.html)
