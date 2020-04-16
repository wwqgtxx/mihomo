#!/bin/bash
#
# Build:
#   - git clone -b dev https://github.com/wwqgtxx/clashr
#   - cd clash
#   - ANDROID_NDK_HOME=/path/to/android/ndk /path/to/this/script
#

export ANDROID_NDK_HOME=/Users/asd/Library/Android/sdk/android-ndk-r20
# export GOPATH=/usr/lib/go

NAME=clash
BINDIR=bin
VERSION=$(git describe --tags || echo "unknown version")
BUILDTIME=$(LANG=C date -u)
cd ..

ANDROID_CC=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android21-clang
ANDROID_CXX=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android21-clang++
ANDROID_LD=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android-ld
export GOARCH=arm64 
export GOOS=android 
export CXX=$ANDROID_CXX
export CC=$ANDROID_CC 
export LD=$ANDROID_LD 
export CGO_ENABLED=1
go build -ldflags "-X \"github.com/wwqgtxx/clashr/constant.Version=$VERSION\" -X \"github.com/wwqgtxx/clashr/constant.BuildTime=$BUILDTIME\" -w -s" \
            -o "build4android/clash_arm64"


ANDROID_CC=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/armv7a-linux-androideabi21-clang
ANDROID_CXX=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/armv7a-linux-androideabi21-clang++
ANDROID_LD=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/armv7a-linux-android-ld
export GOARCH=arm
export GOOS=android 
export CXX=$ANDROID_CXX
export CC=$ANDROID_CC 
export LD=$ANDROID_LD 
export CGO_ENABLED=1
go build -ldflags "-X \"github.com/wwqgtxx/clashr/constant.Version=$VERSION\" -X \"github.com/wwqgtxx/clashr/constant.BuildTime=$BUILDTIME\" -w -s" \
            -o "build4android/clash_armv7a"


ANDROID_CC=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/i686-linux-android21-clang
ANDROID_CXX=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/i686-linux-android21-clang++
ANDROID_LD=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/i686-linux-android-ld
export GOOS=android 
export CXX=$ANDROID_CXX
export CC=$ANDROID_CC 
export LD=$ANDROID_LD 
export CGO_ENABLED=1
export GOARCH=386
go build -ldflags "-X \"github.com/wwqgtxx/clashr/constant.Version=$VERSION\" -X \"github.com/wwqgtxx/clashr/constant.BuildTime=$BUILDTIME\" -w -s" \
            -o "build4android/clash_x86"


ANDROID_CC=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/x86_64-linux-android21-clang
ANDROID_CXX=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/x86_64-linux-android21-clang++
ANDROID_LD=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/x86_64-linux-android-ld
export GOOS=android 
export CXX=$ANDROID_CXX
export CC=$ANDROID_CC 
export LD=$ANDROID_LD 
export CGO_ENABLED=1
export GOARCH=amd64
go build -ldflags "-X \"github.com/wwqgtxx/clashr/constant.Version=$VERSION\" -X \"github.com/wwqgtxx/clashr/constant.BuildTime=$BUILDTIME\" -w -s" \
            -o "build4android/clash_amd64"



