# libzt for Apple platforms

`project.yml` is an [XcodeGen](https://github.com/yonaskolb/XcodeGen) spec for
`zt.framework`, a static framework with a `zt` Clang module (see
`module.modulemap`) for macOS and iOS (device and simulator). The Xcode project
itself is generated and not checked in.

## Requirements

- Xcode
- XcodeGen: `brew install xcodegen`
- Submodules: `git submodule update --init`

## Build an xcframework

```sh
./build-xcframework.sh            # Release
./build-xcframework.sh Debug
```

This generates `zt.xcodeproj`, archives the framework for macOS, iOS and the iOS
Simulator, and combines them into `pkg/apple/zt.xcframework`.

## Work in Xcode

```sh
xcodegen generate
open zt.xcodeproj
```

Re-run `xcodegen generate` after changing `project.yml` or adding/removing
source files.

## Keeping in sync with CMake

The source list and compiler flags mirror the static library built by the
top-level `CMakeLists.txt` (ZeroTier core `node/*.cpp`, `OSUtils.cpp`,
`PortMapper.cpp`, libnatpmp, miniupnpc, lwIP and `src/*.cpp`). Most sources are
picked up with globs, so new files in those directories are included
automatically; explicit file lists (osdep, libnatpmp, miniupnpc) need to be
updated by hand.

The CMake build can also produce Apple frameworks (`./build.sh xcframework`),
using CMake's Xcode generator.
