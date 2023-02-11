/* ecdh.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include <stdio.h>
#include <string.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include "channel.h"

#define KEY_SIZE 32

static void hex_dump(byte *buf, int len, char *t1, char *t2)
{
    int i;
    printf("\n%s: %s", t1, t2);
    for (i = 0; i < len; i++) {
        if (i % 16 == 0)
            putchar('\n');
        printf("%02x ", buf[i]);
    }
    putchar('\n');
}

void genPublic(ecc_key *key, char *myName)
{
    int ret;
    WC_RNG rng;
    byte buf[CH_MAXLEN];
    word32 len;

    ret = wc_InitRng(&rng); // initialize rng
    if (ret != 0) {
        printf("ERROR: wc_InitRng(%d)\n", ret);
        return;
    }

    ret = wc_ecc_init(key); // initialize key
    if (ret != 0) {
        printf("ERROR: wc_ecc_init(%d)\n", ret);
        return;
    }

    ret = wc_ecc_make_key(&rng, KEY_SIZE, key); // make public/private key pair
    if (ret != 0) {
        printf("ERROR: wc_ecc_make_key(%d)\n", ret);
        return;
    }

    printf("wc_ecc_make_pub\n");
    ret = wc_ecc_make_pub(key, (ecc_point *)buf);
    if (ret != 0) {
        printf("ERROR: wc_ecc_make_pub(%d)\n", ret);
        return;
    }
    len = sizeof(ecc_point);

    hex_dump(buf, len, "Send Public", myName);
    sendMessage(buf, len);

}

void genSharedSec(ecc_key *key, char *myName)
{
    int ret;
    WC_RNG rng;
    byte *buf;
    word32 len;

    ecc_key pub;

    byte secret[KEY_SIZE]; // can hold 1024 byte shared secret key
    word32 secretSz = sizeof(secret);
    byte *p;

    // receive public key 
    len = recvMessage(&buf);
    hex_dump(buf, len, "Receive Public", myName);

   // generate secret key
    ret = wc_ecc_shared_secret_ex(key, (ecc_point *)buf, secret, &secretSz);
    if (ret != 0) {
        printf("ERROR: wc_ecc_shared_secret_ex(%d)\n", ret);
        return;
    }
    hex_dump(secret, secretSz, "Shared Secret", myName);
}
