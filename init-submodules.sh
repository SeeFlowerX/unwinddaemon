BRANCH=android14-release

git submodule add -b "$BRANCH" https://android.googlesource.com/platform/art external/art
git submodule add -b "$BRANCH" https://android.googlesource.com/platform/system/libbase external/libbase
# git submodule add -b "$BRANCH" https://android.googlesource.com/platform/system/logging external/logging
git submodule add -b "$BRANCH" https://android.googlesource.com/platform/libnativehelper external/libnativehelper
git submodule add -b "$BRANCH" https://android.googlesource.com/platform/system/libprocinfo external/libprocinfo
git submodule add -b "$BRANCH" https://android.googlesource.com/platform/system/unwinding external/unwinding
git submodule add -b "$BRANCH" https://android.googlesource.com/platform/external/lzma external/lzma
git submodule add -b "$BRANCH" https://android.googlesource.com/platform/bionic external/bionic