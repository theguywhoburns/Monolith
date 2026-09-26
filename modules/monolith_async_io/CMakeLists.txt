# monolith_async_io - asynchronous file I/O.
#
# Separate from monolith_base_io on purpose. The synchronous layer is portable
# and stateless; this one is built on an io_uring ring, and io_uring is
# Linux-only and forced on us: O_NONBLOCK is a no-op on a regular file and
# epoll_ctl rejects one outright with EPERM, so there is no cheaper mechanism
# for "submit now, collect later" on a file.

add_library(monolith_async_io STATIC
    src/io.c)

target_include_directories(monolith_async_io PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(monolith_async_io PUBLIC
    monolith_base_io
    monolith_linux_io_uring)
