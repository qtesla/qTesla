/*************************************************************************************
* qTESLA: an efficient post-quantum signature scheme based on the R-LWE problem
*
* Abstract: configuration file
**************************************************************************************/  

#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>


// Definition of operating system

#define OS_LINUX     1

#if defined(__LINUX__)          // Linux OS
    #define OS_TARGET OS_LINUX 
#else
    #error -- "Unsupported OS"
#endif


// Definition of compiler

#define COMPILER_GCC     1
#define COMPILER_CLANG   2

#if defined(__GNUC__)           // GNU GCC compiler
    #define COMPILER COMPILER_GCC   
#elif defined(__clang__)        // Clang compiler
    #define COMPILER COMPILER_CLANG
#else
    #error -- "Unsupported COMPILER"
#endif


// Definition of the targeted architecture and basic data types
    
#define TARGET_AMD64        1
#define TARGET_x86          2
#define TARGET_ARM          3
#define TARGET_ARM64        4

#if defined(_AMD64_)
    #define TARGET TARGET_AMD64
    #define RADIX32         32
    typedef uint32_t        digit32_t;      // Unsigned 32-bit digit
    typedef int32_t         sdigit32_t;     // Signed 32-bit digit
    typedef int64_t         sdigit_t;       // Signed 64-bit digit
#elif defined(_X86_)
    #define TARGET TARGET_x86
    #define RADIX32         32
    typedef uint32_t        digit32_t;      // Unsigned 32-bit digit
    typedef int32_t         sdigit32_t;     // Signed 32-bit digit
    typedef int32_t         sdigit_t;       // Signed 32-bit digit
#elif defined(_ARM_)
    #define TARGET TARGET_ARM
    #define RADIX32         32
    typedef uint32_t        digit32_t;      // Unsigned 32-bit digit
    typedef int32_t         sdigit32_t;     // Signed 32-bit digit
    typedef int32_t         sdigit_t;       // Signed 32-bit digit
#elif defined(_ARM64_)
    #define TARGET TARGET_ARM64
    #define RADIX32         32
    typedef uint32_t        digit32_t;      // Unsigned 32-bit digit
    typedef int32_t         sdigit32_t;     // Signed 32-bit digit
    typedef int64_t         sdigit_t;       // Signed 64-bit digit
#else
    #error -- "Unsupported ARCHITECTURE"
#endif


#endif
