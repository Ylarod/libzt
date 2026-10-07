#!/bin/sh
#
# Build zt.xcframework (macOS, iOS, iOS Simulator) from project.yml
#
# Requires Xcode and XcodeGen (brew install xcodegen)
#
# Usage: ./build-xcframework.sh [Release|Debug]
#

set -e

cd "$(dirname "$0")"

CONFIGURATION=${1:-Release}
BUILD_DIR=build

if ! command -v xcodegen >/dev/null 2>&1; then
    echo "xcodegen not found. Install it with: brew install xcodegen" >&2
    exit 1
fi

if [ ! -f ../../ext/ZeroTierOne/node/Node.cpp ] || [ ! -f ../../ext/lwip/src/core/init.c ]; then
    echo "Submodules missing. Run: git submodule update --init" >&2
    exit 1
fi

xcodegen generate

rm -rf "$BUILD_DIR" zt.xcframework

archive()
{
    xcodebuild archive \
        -project zt.xcodeproj \
        -scheme zt \
        -configuration "$CONFIGURATION" \
        -destination "generic/platform=$1" \
        -archivePath "$BUILD_DIR/$2" \
        SKIP_INSTALL=NO \
        BUILD_LIBRARY_FOR_DISTRIBUTION=YES
}

archive "macOS" macosx
archive "iOS" iphoneos
archive "iOS Simulator" iphonesimulator

xcodebuild -create-xcframework \
    -framework "$BUILD_DIR/macosx.xcarchive/Products/Library/Frameworks/zt.framework" \
    -framework "$BUILD_DIR/iphoneos.xcarchive/Products/Library/Frameworks/zt.framework" \
    -framework "$BUILD_DIR/iphonesimulator.xcarchive/Products/Library/Frameworks/zt.framework" \
    -output zt.xcframework

rm -rf "$BUILD_DIR"

echo "Created $(pwd)/zt.xcframework"
