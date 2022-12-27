#include <nuttx/config.h>

/* Library */
#define WOLFCRYPT_ONLY
#define SINGLE_THREADED
#define WOLFSSL_SMALL_STACK

/* Environment */
#define NO_FILESYSTEM
#define HAVE_STRINGS_H
#define WOLF_C99

/* Math */
#ifdef CONFIG_ARCH_CHIP_STM32L552ZE
    /* Math - Optimized for NUCLEO-L552ZE-Q */
    #define WOLFSSL_SP
    #define WOLFSSL_SP_SMALL
    #define WOLFSSL_HAVE_SP_RSA
    #define WOLFSSL_HAVE_SP_DH
    #define WOLFSSL_HAVE_SP_ECC
    #define WOLFSSL_SP_MATH
    #define SP_WORD_SIZE 32
    #define WOLFSSL_SP_ASM
    #define WOLFSSL_SP_ARM_CORTEX_M_ASM
#else
    #define WOLFSSL_SP_MATH_ALL
#endif

/* Crypto */
#define HAVE_ECC
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING
#undef  RSA_LOW_MEM
#define NO_MD4
#define NO_DSA

/* RNG */
#define WOLFSSL_GENSEED_FORTEST

/* Applications */
#define NO_MAIN_FUNCTION
#define BENCH_EMBEDDED
#define WOLFSSL_BENCHMARK_FIXED_UNITS_MB

/* Development */
//#define DEBUG_WOLFSSL
