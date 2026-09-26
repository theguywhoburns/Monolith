cmake_minimum_required(VERSION 3.24)

set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_LIST_DIR}/cmake/toolchain-x86_64-freestanding.cmake"
    CACHE FILEPATH "" FORCE)

project(monolith
    VERSION 0.1.0
    DESCRIPTION "Freestanding x86-64 Linux: no libc, no CRT, no C library headers"
    LANGUAGES C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(WARNING "This project requires clang; -nostdlibinc has no gcc equivalent.")
endif()

# Every module directory is picked up automatically, so adding one needs no edit
# here. CONFIGURE_DEPENDS makes CMake re-run when that set changes.
#
# The glob yields them alphabetically and the order does not matter: CMake
# resolves target names in target_link_libraries at generate time rather than
# configure time, so a module may be added before the ones it links.
file(GLOB _modules CONFIGURE_DEPENDS "${CMAKE_CURRENT_LIST_DIR}/modules/*/CMakeLists.txt")
foreach(_module IN LISTS _modules)
    get_filename_component(_dir "${_module}" DIRECTORY)
    add_subdirectory("${_dir}")
endforeach()

enable_testing()

# Every executable is freestanding and needs _start, so that link is an
# invariant rather than a choice. Extra modules come from ARGN.
function(monolith_executable name source)
    add_executable(${name} ${source})
    target_link_libraries(${name} PRIVATE monolith_startup ${ARGN})
endfunction()

# The application is the consumer of the I/O modules. The two checkers exist on
# top of that, so the modules stay honest on paths the demo does not reach.
monolith_executable(monolith src/main.c
    monolith_base_io
    monolith_async_io)
monolith_executable(monolith_io_check    tools/io_check.c   monolith_base_io)
monolith_executable(monolith_async_check tools/async_check.c monolith_base_io monolith_async_io)

# The checkers exit with the number of failed checks, so any non-zero status
# fails the test.
add_test(NAME startup_hello COMMAND monolith)
add_test(NAME base_io       COMMAND monolith_io_check)
add_test(NAME async_io      COMMAND monolith_async_check)
