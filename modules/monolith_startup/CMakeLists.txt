# monolith_startup - process entry point. This module is crt1.o.
#
# It owns _start, the contract it calls into, and the one compiler flag only
# _start needs. Everything else comes from the toolchain file.

add_library(monolith_startup STATIC
    src/startup.c)

target_include_directories(monolith_startup PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

# PUBLIC: the syscall wrappers are part of what consumers of this module see.
target_link_libraries(monolith_startup PUBLIC
    monolith_linux_syscalls)

# _start recovers the initial stack via __builtin_frame_address(0), which is
# %rbp, which is the entry %rsp only if the frame pointer is kept. Load-bearing
# for startup.c and for nothing else in the tree.
target_compile_options(monolith_startup PRIVATE
    -fno-omit-frame-pointer)

set_target_properties(monolith_startup PROPERTIES
    POSITION_INDEPENDENT_CODE OFF)
