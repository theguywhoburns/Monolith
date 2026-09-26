# monolith_linux_syscalls - the kernel ABI as inline asm.
#
# Header-only, so an INTERFACE library: there is nothing to compile, and the
# inline functions get emitted into each translation unit that uses them.
#
# It owns no flags. The platform flags and the kernel UAPI include path are in
# the toolchain file, which is the only place that can also affect the compiler
# checks that run before project().

add_library(monolith_linux_syscalls INTERFACE)

target_include_directories(monolith_linux_syscalls INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/include)
