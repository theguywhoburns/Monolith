# monolith_base_io - file I/O.
#
# The first module with real state in it, so unlike monolith_linux_syscalls
# this is a STATIC library rather than an INTERFACE one.
#
# It allocates nothing. The handle is returned by value and the write staging and
# directory buffers are caller-owned memory this module only points at. A module
# that allocated would either be impossible to build or would need an allocator
# first, and a file you cannot open because you are out of memory is a bad
# failure mode to inherit from fopen.

add_library(monolith_base_io STATIC
    src/io_file.c
    src/io_map.c
    src/io_meta.c
    src/io_dir.c)

target_include_directories(monolith_base_io PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(monolith_base_io PUBLIC
    monolith_linux_syscalls)
