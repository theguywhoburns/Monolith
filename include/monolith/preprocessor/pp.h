#pragma once
#ifdef __cplusplus
extern "C" {
#endif

// Both platform and architecture detection are handled by CMake.

#if defined(MONOLITH_COMPILE_FROM_SOURCE) && defined(MONOLITH_EXPORTS)
#error "MONOLITH_COMPILE_FROM_SOURCE and MONOLITH_EXPORTS are mutually exclusive"
#endif

#define PRAGMA(x) _Pragma(#x)
#if defined(MONOLITH_COMPILER_MSVC)
    #if defined(MONOLITH_COMPILE_FROM_SOURCE)
        #define MONOLITH_API extern
    #elif defined(MONOLITH_EXPORTS)
        #define MONOLITH_API __declspec(dllexport)
    #else
        #define MONOLITH_API __declspec(dllimport)
    #endif 
    #define TYPEOF(x) decltype(x)
    #define ALIGNED(x) __declspec(align(x))
    #define PACKED(__packed_declaration__) __pragma(pack(push, 1)) __packed_declaration__ __pragma(pack(pop))
#elif defined(MONOLITH_COMPILER_GCC) || defined(MONOLITH_COMPILER_CLANG)
    #if defined(MONOLITH_COMPILE_FROM_SOURCE)
        #define MONOLITH_API extern
    #elif defined(MONOLITH_EXPORTS)
        #define MONOLITH_API __attribute__((visibility("default")))
    #else
        #define MONOLITH_API extern
    #endif
    #if defined(MONOLITH_COMPILER_CLANG)
        #define TYPEOF(x) __typeof__(x)
    #else
        #define TYPEOF(x) typeof(x)
    #endif
    #define ALIGNED(x) __attribute__((aligned(x)))
    #define PACKED(x) x __attribute__((packed))
#else
#error "Current compiler is not supported"
#endif
#ifdef __cplusplus
}
#endif