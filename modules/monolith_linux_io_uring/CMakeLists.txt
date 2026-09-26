# monolith_linux_io_uring - a usable wrapper around io_uring.
#
# The parts of io_uring that are easy to get wrong live here: the ring offsets
# (struct io_uring was deleted from the uapi headers in 6.18), the sq_array the
# kernel actually reads, and the three mappings.
#
# It knows nothing about files. monolith_async_io does, and is built on this.
#
# The only module in the tree that owns memory rather than borrowing it, because
# the kernel has to map the rings. Keeping that here is what lets
# monolith_base_io keep its "never allocates" property intact.

add_library(monolith_linux_io_uring STATIC
    src/uring.c)

target_include_directories(monolith_linux_io_uring PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(monolith_linux_io_uring PUBLIC
    monolith_linux_syscalls
    monolith_base_io)
