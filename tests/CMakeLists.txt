cmake_minimum_required(VERSION 3.22)
project(
    monolith_tests
    LANGUAGES C
)

add_compile_options(-nostartfiles -nodefaultlibs -nostdlib -nostdinc -Wl,--no-as-needed)
add_link_options(-Wl,--no-as-needed -nostartfiles -nodefaultlibs -nostdlib -nostdinc)
add_executable(monolith_tests test.c)
target_link_libraries(monolith_tests PRIVATE monolith)
