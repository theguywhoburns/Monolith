# Toolchain: x86-64 Linux, freestanding.
#
# Chosen automatically by the top-level CMakeLists.txt, so nothing has to pass
# -DCMAKE_TOOLCHAIN_FILE. It is picked up for try_compile() as well, which is
# why the flags live here rather than on a target: a target cannot affect the
# compiler checks that run before project() completes.

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Nothing to link a test executable against, so every try_compile() stops at the
# object file.
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

set(CMAKE_C_STANDARD 23)

# Without this, C_STANDARD 23 resolves to -std=gnu23. Nothing here needs GNU
# extensions and the project is non-GNU by premise.
set(CMAKE_C_EXTENSIONS OFF)

# Where the kernel's UAPI headers live. The devenv sets LINUX_HEADERS; a manual
# build passes -DMONOLITH_LINUX_INCLUDE=... instead.
if(NOT MONOLITH_LINUX_INCLUDE AND NOT "$ENV{LINUX_HEADERS}" STREQUAL "")
    set(MONOLITH_LINUX_INCLUDE "$ENV{LINUX_HEADERS}" CACHE PATH "" FORCE)
endif()
if(NOT MONOLITH_LINUX_INCLUDE)
    message(FATAL_ERROR
        "No Linux UAPI headers.\n"
        "  cmake -S . -B build -DMONOLITH_LINUX_INCLUDE=/path/to/linux-headers/include\n"
        "or export LINUX_HEADERS before configuring (the devenv does this for you).")
endif()
foreach(hdr asm/unistd.h linux/types.h)
    if(NOT EXISTS "${MONOLITH_LINUX_INCLUDE}/${hdr}")
        message(FATAL_ERROR
            "MONOLITH_LINUX_INCLUDE='${MONOLITH_LINUX_INCLUDE}' is not a Linux UAPI "
            "header tree: ${hdr} is missing.")
    endif()
endforeach()
message(STATUS "Linux UAPI headers: ${MONOLITH_LINUX_INCLUDE}")

# -nostdlibinc keeps the libc headers unreachable while leaving clang's own
# freestanding ones (stddef.h, stdarg.h, stdint.h) in place. gcc has no
# equivalent, which is why this project requires clang.
#
# -fno-pie here with -static at link is what makes the image ET_EXEC.
#
# Joined into one string on purpose: a bare CMake list reaches the shell
# newline-separated, so each flag ends up executed as its own command.
set(_c_flags
    -ffreestanding        # __STDC_HOSTED__ == 0
    -fno-builtin          # never emit calls to memset/memcpy/strlen
    -nostdlibinc
    -m64
    -mno-red-zone         # a signal handler may clobber it
    -mno-mmx
    -mno-sse
    -mno-sse2
    -fno-pic
    -fno-pie
    -fno-stack-protector
    -fno-asynchronous-unwind-tables
    -fno-unwind-tables
    -Wall
    -Wextra
    -isystem ${MONOLITH_LINUX_INCLUDE})
string(JOIN " " CMAKE_C_FLAGS_INIT ${_c_flags})

# -nostdlib covers libc, libgcc and the crt objects in one flag.
set(_link_flags
    -nostdlib
    -static               # no PT_INTERP
    -fuse-ld=lld
    -Wl,--build-id=none
    -Wl,--gc-sections
    -Wl,-z,noexecstack
    -Wl,-z,max-page-size=0x1000
    -Wl,--fatal-warnings)
string(JOIN " " CMAKE_EXE_LINKER_FLAGS_INIT ${_link_flags})
