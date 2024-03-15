#/bin/bash

export ANDROID_NDK=/home/kali/Desktop/android-ndk-r25b

rm -r build
mkdir build && cd build 

cmake -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
	-DANDROID=1 \
	-DANDROID_ABI="arm64-v8a" \
	-DANDROID_NDK=$ANDROID_NDK \
	-DANDROID_PLATFORM=android-30 \
	..

make

cd ..
