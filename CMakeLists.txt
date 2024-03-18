cmake_minimum_required(VERSION 3.22.1)
project("stackplz")

enable_language(C CXX ASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_C_STANDARD 11)

set(C_FLAGS "-Wall -Wextra -fvisibility=hidden -fvisibility-inlines-hidden -fno-exceptions -fno-rtti -flto=thin")
set(LINKER_FLAGS "-fuse-ld=lld -flto=thin -ffixed-x18 -Wl,--hash-style=both -Wl,--unresolved-symbols=ignore-all")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -fvisibility=hidden")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -fvisibility=hidden")

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,text,-z,defs,-z,now,-z,relro")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-omit-frame-pointer")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-omit-frame-pointer -Werror=non-virtual-dtor -Werror=delete-non-virtual-dtor")

set(EXTERNAL_SRC "external")
set(LOGGING_SRC "external/logging")
set(UNWINDING_SRC "external/unwinding")

if (DEFINED ANDROID_ABI)
    if (ANDROID_ABI STREQUAL "x86")
        set(UNWINDSTACK_ARCH "x86")
    elseif (ANDROID_ABI STREQUAL "x86_64")
        set(UNWINDSTACK_ARCH "x86_64")
    elseif (ANDROID_ABI STREQUAL "armeabi-v7a")
        set(UNWINDSTACK_ARCH "arm")
    elseif (ANDROID_ABI STREQUAL "arm64-v8a")
        set(UNWINDSTACK_ARCH "arm64")
    else ()
        message(FATAL_ERROR "Unsupported ANDROID_ABI: ${ANDROID_ABI}")
    endif ()
else ()
    if (CMAKE_SYSTEM_PROCESSOR STREQUAL "x86" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "i686")
        set(UNWINDSTACK_ARCH "x86")
    elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "amd64")
        set(UNWINDSTACK_ARCH "x86_64")
    elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "armv7l" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "armv7-a")
        set(UNWINDSTACK_ARCH "arm")
    elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "armv8-a")
        set(UNWINDSTACK_ARCH "arm64")
    else ()
        message(FATAL_ERROR "Unsupported CMAKE_SYSTEM_PROCESSOR: ${CMAKE_SYSTEM_PROCESSOR}")
    endif ()
endif ()

# architecture-specific sources
if (UNWINDSTACK_ARCH STREQUAL "x86")
    set(UNWINDSTACK_ARCH_SRC "${UNWINDING_SRC}/libunwindstack/AsmGetRegsX86.S")
elseif (UNWINDSTACK_ARCH STREQUAL "x86_64")
    set(UNWINDSTACK_ARCH_SRC "${UNWINDING_SRC}/libunwindstack/AsmGetRegsX86_64.S")
else ()
    set(UNWINDSTACK_ARCH_SRC "")
endif ()

if (UNWINDSTACK_ARCH STREQUAL "x86")
    list(APPEND ART_COMPILE_C_FLAGS "-DART_ENABLE_CODEGEN_x86")
elseif (UNWINDSTACK_ARCH STREQUAL "x86_64")
    list(APPEND ART_COMPILE_C_FLAGS "-DART_ENABLE_CODEGEN_x86_64" "-DART_ENABLE_CODEGEN_x86")
elseif (UNWINDSTACK_ARCH STREQUAL "arm")
    list(APPEND ART_COMPILE_C_FLAGS "-DART_ENABLE_CODEGEN_arm")
elseif (UNWINDSTACK_ARCH STREQUAL "arm64")
    list(APPEND ART_COMPILE_C_FLAGS "-DART_ENABLE_CODEGEN_arm64" "-DART_ENABLE_CODEGEN_arm")
endif ()

add_library(base STATIC
        "${EXTERNAL_SRC}/libbase/chrono_utils.cpp"
        "${EXTERNAL_SRC}/libbase/file.cpp"
        "${EXTERNAL_SRC}/libbase/hex.cpp"
        "${EXTERNAL_SRC}/libbase/mapped_file.cpp"
        "${EXTERNAL_SRC}/libbase/parsebool.cpp"
        "${EXTERNAL_SRC}/libbase/parsenetaddress.cpp"
        "${EXTERNAL_SRC}/libbase/logging.cpp"
        "${EXTERNAL_SRC}/libbase/posix_strerror_r.cpp"
        "${EXTERNAL_SRC}/libbase/process.cpp"
        "${EXTERNAL_SRC}/libbase/stringprintf.cpp"
        "${EXTERNAL_SRC}/libbase/strings.cpp"
        "${EXTERNAL_SRC}/libbase/threads.cpp"
)
target_include_directories(base PUBLIC "${EXTERNAL_SRC}/libbase/include")
target_compile_options(base PRIVATE -Wno-c99-designator)

add_library(procinfo STATIC "${EXTERNAL_SRC}/libprocinfo/process.cpp")
target_include_directories(procinfo PUBLIC "${EXTERNAL_SRC}/libbase/include" "${EXTERNAL_SRC}/libprocinfo/include")

add_library(lzma STATIC
        "${EXTERNAL_SRC}/lzma/C/7zAlloc.c"
        "${EXTERNAL_SRC}/lzma/C/7zArcIn.c"
        "${EXTERNAL_SRC}/lzma/C/7zBuf2.c"
        "${EXTERNAL_SRC}/lzma/C/7zBuf.c"
        "${EXTERNAL_SRC}/lzma/C/7zCrc.c"
        "${EXTERNAL_SRC}/lzma/C/7zCrcOpt.c"
        "${EXTERNAL_SRC}/lzma/C/7zDec.c"
        "${EXTERNAL_SRC}/lzma/C/7zFile.c"
        "${EXTERNAL_SRC}/lzma/C/7zStream.c"
        "${EXTERNAL_SRC}/lzma/C/Aes.c"
        "${EXTERNAL_SRC}/lzma/C/AesOpt.c"
        "${EXTERNAL_SRC}/lzma/C/Alloc.c"
        "${EXTERNAL_SRC}/lzma/C/Bcj2.c"
        "${EXTERNAL_SRC}/lzma/C/Bra86.c"
        "${EXTERNAL_SRC}/lzma/C/Bra.c"
        "${EXTERNAL_SRC}/lzma/C/BraIA64.c"
        "${EXTERNAL_SRC}/lzma/C/CpuArch.c"
        "${EXTERNAL_SRC}/lzma/C/Delta.c"
        "${EXTERNAL_SRC}/lzma/C/LzFind.c"
        "${EXTERNAL_SRC}/lzma/C/Lzma2Dec.c"
        "${EXTERNAL_SRC}/lzma/C/Lzma2Enc.c"
        "${EXTERNAL_SRC}/lzma/C/Lzma86Dec.c"
        "${EXTERNAL_SRC}/lzma/C/Lzma86Enc.c"
        "${EXTERNAL_SRC}/lzma/C/LzmaDec.c"
        "${EXTERNAL_SRC}/lzma/C/LzmaEnc.c"
        "${EXTERNAL_SRC}/lzma/C/LzmaLib.c"
        "${EXTERNAL_SRC}/lzma/C/Ppmd7.c"
        "${EXTERNAL_SRC}/lzma/C/Ppmd7Dec.c"
        "${EXTERNAL_SRC}/lzma/C/Ppmd7Enc.c"
        "${EXTERNAL_SRC}/lzma/C/Sha256.c"
        "${EXTERNAL_SRC}/lzma/C/Sort.c"
        "${EXTERNAL_SRC}/lzma/C/Xz.c"
        "${EXTERNAL_SRC}/lzma/C/XzCrc64.c"
        "${EXTERNAL_SRC}/lzma/C/XzCrc64Opt.c"
        "${EXTERNAL_SRC}/lzma/C/XzDec.c"
        "${EXTERNAL_SRC}/lzma/C/XzEnc.c"
        "${EXTERNAL_SRC}/lzma/C/XzIn.c"
)
target_include_directories(lzma PUBLIC "${EXTERNAL_SRC}/lzma/C")
target_compile_options(lzma PRIVATE -fPIC "-D_7ZIP_ST")

add_library(unwindstack STATIC
        "${UNWINDING_SRC}/libunwindstack/AndroidUnwinder.cpp"
        "${UNWINDING_SRC}/libunwindstack/ArmExidx.cpp"
        # "${UNWINDING_SRC}/libunwindstack/Demangle.cpp"
        "shim_files/Demangle.cpp"
        "${UNWINDING_SRC}/libunwindstack/DexFiles.cpp"
        "${UNWINDING_SRC}/libunwindstack/DwarfCfa.cpp"
        "${UNWINDING_SRC}/libunwindstack/DwarfEhFrameWithHdr.cpp"
        "${UNWINDING_SRC}/libunwindstack/DwarfMemory.cpp"
        "${UNWINDING_SRC}/libunwindstack/DwarfOp.cpp"
        "${UNWINDING_SRC}/libunwindstack/DwarfSection.cpp"
        "${UNWINDING_SRC}/libunwindstack/Elf.cpp"
        "${UNWINDING_SRC}/libunwindstack/ElfInterface.cpp"
        "${UNWINDING_SRC}/libunwindstack/ElfInterfaceArm.cpp"
        "${UNWINDING_SRC}/libunwindstack/Global.cpp"
        "${UNWINDING_SRC}/libunwindstack/JitDebug.cpp"
        "${UNWINDING_SRC}/libunwindstack/MapInfo.cpp"
        "${UNWINDING_SRC}/libunwindstack/Maps.cpp"
        "${UNWINDING_SRC}/libunwindstack/Memory.cpp"
        "${UNWINDING_SRC}/libunwindstack/MemoryMte.cpp"
        "${UNWINDING_SRC}/libunwindstack/MemoryXz.cpp"
        "${UNWINDING_SRC}/libunwindstack/Regs.cpp"
        "${UNWINDING_SRC}/libunwindstack/RegsArm.cpp"
        "${UNWINDING_SRC}/libunwindstack/RegsArm64.cpp"
        "${UNWINDING_SRC}/libunwindstack/RegsX86.cpp"
        "${UNWINDING_SRC}/libunwindstack/RegsX86_64.cpp"
        "${UNWINDING_SRC}/libunwindstack/RegsRiscv64.cpp"
        "${UNWINDING_SRC}/libunwindstack/RegsMips.cpp"
        "${UNWINDING_SRC}/libunwindstack/RegsMips64.cpp"
        "${UNWINDING_SRC}/libunwindstack/Symbols.cpp"
        "${UNWINDING_SRC}/libunwindstack/ThreadEntry.cpp"
        # "${UNWINDING_SRC}/libunwindstack/ThreadUnwinder.cpp"
        "shim_files/ThreadUnwinder.cpp"
        "${UNWINDING_SRC}/libunwindstack/Unwinder.cpp"

        "${UNWINDING_SRC}/libunwindstack/DexFile.cpp"
        "${UNWINDING_SRC}/libunwindstack/LogAndroid.cpp"

        "${UNWINDSTACK_ARCH_SRC}"
)

target_include_directories(unwindstack
        PUBLIC "${UNWINDING_SRC}/libunwindstack"
        PUBLIC "${UNWINDING_SRC}/libunwindstack/include"
        PUBLIC "${EXTERNAL_SRC}/libbase/include"
        PUBLIC "${EXTERNAL_SRC}/bionic/libc/platform"
        PUBLIC "${EXTERNAL_SRC}/bionic/libc/async_safe/include"
        PUBLIC "${EXTERNAL_SRC}/libprocinfo/include"
        PUBLIC "${EXTERNAL_SRC}/lzma/C"
        PUBLIC "${EXTERNAL_SRC}/art/libdexfile/external/include"
        PUBLIC "${LOGGING_SRC}/liblog/include"
)
target_compile_options(unwindstack PRIVATE -Wno-c99-designator)

# check are we top-level project
if (CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)

    add_library(${PROJECT_NAME} SHARED lib.cpp)

    SET_TARGET_PROPERTIES(${PROJECT_NAME} PROPERTIES LINK_FLAGS "-Wl,-s")

    target_include_directories(${PROJECT_NAME} PUBLIC ${EXTERNAL_SRC}/libbase/include)
    target_include_directories(${PROJECT_NAME} PUBLIC ${EXTERNAL_SRC}/bionic/libc/kernel/uapi)
    target_include_directories(${PROJECT_NAME} PUBLIC ${EXTERNAL_SRC}/unwinding/libunwindstack/include)

    target_link_libraries(${PROJECT_NAME} base procinfo lzma unwindstack log)

endif ()