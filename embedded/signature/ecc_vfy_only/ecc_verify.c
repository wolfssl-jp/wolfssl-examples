/* ecc_verify.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdio.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include<wolfssl/test.h>
#include "signature.h"


#define HEAP_HINT NULL
#define ECC_KEY_SIZE_112 112
#define ECC_KEY_SIZE_128 128
#define ECC_KEY_SIZE_160 160
#define ECC_KEY_SIZE_192 192
#define ECC_KEY_SIZE_224 224
#define ECC_KEY_SIZE_239 239
#define ECC_KEY_SIZE_256 256
#define ECC_KEY_SIZE_320 320
#define ECC_KEY_SIZE_384 384
#define ECC_KEY_SIZE_512 512
#define ECC_KEY_SIZE_521 521
#define BYTE_SZ 8


int idx_key(int keysize);


#define CHECK_RET(a, b, eLabel, msg) { \
                                        if (a != b) {                    \
                                            printf("failed %s\n", msg);  \
                                            printf("ret = %d\n", a);   \
                                            goto eLabel;                 \
                                        }                                \
                                     }

int do_sig_ver_test(int eccKeySz);


int ecc_verify(void)
{
    int ret = 0;
#ifdef DEBUG_MEMORY
    wolfCrypt_Init();
    InitMemoryTracker();
#endif
    ret = do_sig_ver_test(ECC_KEY_SIZE_112);
    CHECK_RET(ret, 0, finished, "112 test");
    ret = do_sig_ver_test(ECC_KEY_SIZE_128);
    CHECK_RET(ret, 0, finished, "128 test");
    ret = do_sig_ver_test(ECC_KEY_SIZE_160);
    CHECK_RET(ret, 0, finished, "160 test");
    ret = do_sig_ver_test(ECC_KEY_SIZE_192);
    CHECK_RET(ret, 0, finished, "192 test");
    ret = do_sig_ver_test(ECC_KEY_SIZE_224);
    CHECK_RET(ret, 0, finished, "224 test");
    ret = do_sig_ver_test(ECC_KEY_SIZE_239);
    CHECK_RET(ret, 0, finished, "239 test");
    ret = do_sig_ver_test(ECC_KEY_SIZE_256);
    CHECK_RET(ret, 0, finished, "256 test");
    ret = do_sig_ver_test(ECC_KEY_SIZE_320);
    CHECK_RET(ret, 0, finished, "320 test");
    ret = do_sig_ver_test(ECC_KEY_SIZE_384);
    CHECK_RET(ret, 0, finished, "384 test");
    ret = do_sig_ver_test(ECC_KEY_SIZE_512);
    CHECK_RET(ret, 0, finished, "512 test");
    ret = do_sig_ver_test(ECC_KEY_SIZE_521);
    CHECK_RET(ret, 0, finished, "521 test");


finished:
#ifdef DEBUG_MEMORY
    printf("\n");
    ShowMemoryTracker();
    CleanupMemoryTracker();
    wolfCrypt_Cleanup();
#endif
    return ret;
}

int do_sig_ver_test(int eccKeySz)
{
    /* sha256 hash of the string "A 32-bit string to test signing" */
    unsigned char hash[32] = {
                                0x3b, 0x07, 0x54, 0x5c, 0xfd, 0x4f, 0xb7, 0xb5,
                                0xaf, 0xa7, 0x7a, 0x25, 0x33, 0xa5, 0x50, 0x70,
                                0x4a, 0x65, 0x3e, 0x72, 0x7e, 0xcd, 0xd4, 0x5b,
                                0x1b, 0x36, 0x96, 0x96, 0xca, 0x4f, 0x9b, 0x6f
                              };
    int ret;
    ecc_key key;
    byte* sig = NULL; // get rid of this magic number
    WC_RNG rng;
    int verified = 0;
    word32 sig_size;
    int key_size;
    unsigned char *pKeybuff;


/* Variables for Benchmark */
double start_time, total_time;
#ifndef BENCH_TIME_SEC
    #define BENCH_TIME_SEC 1
#endif
    int count;


    /*
     * for odd curve sizes account for mod EG:
     * Case 1) curve field of 256:
     *                 (256/8) + (256%8 != 0 ? 1:0) == 32 + 0 = 32
     *
     * Case 2) curve field of 521:
     *                 (521/8 = 65.125 (rounds to 65) + (521%8 != 0 ? 1:0) ==
                                                                    65 + 1 = 66
     *
     * Algorithm: (C / B) + (C % B != 0 ? 1:0)
     *
     * This remainder is a natural result of the calculation:
     * Algorithm: (C / (B-1)) / (B)
     */
    int byteField = (eccKeySz + (BYTE_SZ - 1)) / BYTE_SZ;
    word32 maxSigSz = ECC_MAX_SIG_SIZE;
#ifndef BENCHMARK
    printf("Key size is %d, byteField = %d\n", eccKeySz, byteField);
#endif


    ret = wc_InitRng(&rng);
    CHECK_RET(ret, 0, key_done, "wc_InitRng()");

#ifdef BENCHMARK
    count = 0;
    start_time = current_time(1);

    while( (double)BENCH_TIME_SEC > (total_time = current_time(0) - start_time ) ){
#endif
        ret = wc_ecc_init(&key);
        CHECK_RET(ret, 0, sig_done, "wc_ecc_init()");


    /* Import signature and ecc_key */

        sig = sig_keys[idx_key(eccKeySz)].sig;
        sig_size = sig_keys[idx_key(eccKeySz)].sig_size;
        pKeybuff = sig_keys[idx_key(eccKeySz)].pubkey;
        key_size = sig_keys[idx_key(eccKeySz)].key_size;

        ret = wc_ecc_import_x963(pKeybuff, key_size, &key);
        CHECK_RET(ret, 0, rng_done, "wc_ecc_import_x963()");


        ret = wc_ecc_verify_hash(sig, sig_size, hash, sizeof(hash),
                                                            &verified, &key);

        CHECK_RET(ret, 0, rng_done, "wc_ecc_verify_hash()");
        CHECK_RET(verified, 1, rng_done, "verification check");
        verified = 0;
        maxSigSz = ECC_MAX_SIG_SIZE;
#ifdef BENCHMARK
        count++;
    }

    printf("ECC Key Size %d     %9.2f Cycles/sec\n", eccKeySz, count/total_time);

#else

printf("Successfully verified signature w/ ecc key size %d!\n", eccKeySz);

#endif /* BENCHMARK */

rng_done:
    wc_FreeRng(&rng);
key_done:
    wc_ecc_free(&key);
sig_done:
    return ret;
}


int main(){
#ifdef BENCHMARK
    printf("---------------------------------------------------------------\n");
#if defined(SP_C64_FLAG)
    printf("Enabled 64-bit SP \n");
#elif defined(SP_C32_FLAG)
    printf("Enabled 32-bit SP \n");
#elif defined(SP_X86_64_FLAG)
    printf("Enabled SP for x86_64\n");
#elif defined(SP_ARM64_FLAG)
    printf("Enabled SP for Arm64\n");
#elif defined(TFM_FLAG)
    printf("Enabled TFM \n");
#endif
    printf("---------------------------------------------------------------\n");
    printf("Running ECC Sign Verify Benchmarks...\n");
#endif /* BENCHMARK */

#ifdef DEBUG_MEMORY
    return StackSizeCheck(NULL, (thread_func)ecc_verify);
#else
    return ecc_verify();
#endif
}

int idx_key(int keysize){
    switch(keysize){
        case ECC_KEY_SIZE_112:
            return 0;
        case ECC_KEY_SIZE_128:
            return 1;
        case ECC_KEY_SIZE_160:
            return 2;
        case ECC_KEY_SIZE_192:
            return 3;
        case ECC_KEY_SIZE_224:
            return 4;
        case ECC_KEY_SIZE_239:
            return 5;
        case ECC_KEY_SIZE_256:
            return 6;
        case ECC_KEY_SIZE_320:
            return 7;
        case ECC_KEY_SIZE_384:
            return 8;
        case ECC_KEY_SIZE_512:
            return 9;
        case ECC_KEY_SIZE_521:
            return 10;
        default:
            return -1;
    }

}

