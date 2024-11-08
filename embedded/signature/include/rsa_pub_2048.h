/* rsa_pub_2048.h
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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

/* This file contains an RSA 2048-bit public key.
 * It is the public counterpart to "rsa_priv_2048.h"
 */

/* RSA public key to verify with.
 * Key is PKCS#1 formatted and DER encoded.
 */
static const unsigned char public_key_2048[] = {
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09,
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
    0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0F, 0x00,
    0x30, 0x82, 0x01, 0x0A, 0x02, 0x82, 0x01, 0x01,
    0x00, 0xC3, 0x03, 0xD1, 0x2B, 0xFE, 0x39, 0xA4,
    0x32, 0x45, 0x3B, 0x53, 0xC8, 0x84, 0x2B, 0x2A,
    0x7C, 0x74, 0x9A, 0xBD, 0xAA, 0x2A, 0x52, 0x07,
    0x47, 0xD6, 0xA6, 0x36, 0xB2, 0x07, 0x32, 0x8E,
    0xD0, 0xBA, 0x69, 0x7B, 0xC6, 0xC3, 0x44, 0x9E,
    0xD4, 0x81, 0x48, 0xFD, 0x2D, 0x68, 0xA2, 0x8B,
    0x67, 0xBB, 0xA1, 0x75, 0xC8, 0x36, 0x2C, 0x4A,
    0xD2, 0x1B, 0xF7, 0x8B, 0xBA, 0xCF, 0x0D, 0xF9,
    0xEF, 0xEC, 0xF1, 0x81, 0x1E, 0x7B, 0x9B, 0x03,
    0x47, 0x9A, 0xBF, 0x65, 0xCC, 0x7F, 0x65, 0x24,
    0x69, 0xA6, 0xE8, 0x14, 0x89, 0x5B, 0xE4, 0x34,
    0xF7, 0xC5, 0xB0, 0x14, 0x93, 0xF5, 0x67, 0x7B,
    0x3A, 0x7A, 0x78, 0xE1, 0x01, 0x56, 0x56, 0x91,
    0xA6, 0x13, 0x42, 0x8D, 0xD2, 0x3C, 0x40, 0x9C,
    0x4C, 0xEF, 0xD1, 0x86, 0xDF, 0x37, 0x51, 0x1B,
    0x0C, 0xA1, 0x3B, 0xF5, 0xF1, 0xA3, 0x4A, 0x35,
    0xE4, 0xE1, 0xCE, 0x96, 0xDF, 0x1B, 0x7E, 0xBF,
    0x4E, 0x97, 0xD0, 0x10, 0xE8, 0xA8, 0x08, 0x30,
    0x81, 0xAF, 0x20, 0x0B, 0x43, 0x14, 0xC5, 0x74,
    0x67, 0xB4, 0x32, 0x82, 0x6F, 0x8D, 0x86, 0xC2,
    0x88, 0x40, 0x99, 0x36, 0x83, 0xBA, 0x1E, 0x40,
    0x72, 0x22, 0x17, 0xD7, 0x52, 0x65, 0x24, 0x73,
    0xB0, 0xCE, 0xEF, 0x19, 0xCD, 0xAE, 0xFF, 0x78,
    0x6C, 0x7B, 0xC0, 0x12, 0x03, 0xD4, 0x4E, 0x72,
    0x0D, 0x50, 0x6D, 0x3B, 0xA3, 0x3B, 0xA3, 0x99,
    0x5E, 0x9D, 0xC8, 0xD9, 0x0C, 0x85, 0xB3, 0xD9,
    0x8A, 0xD9, 0x54, 0x26, 0xDB, 0x6D, 0xFA, 0xAC,
    0xBB, 0xFF, 0x25, 0x4C, 0xC4, 0xD1, 0x79, 0xF4,
    0x71, 0xD3, 0x86, 0x40, 0x18, 0x13, 0xB0, 0x63,
    0xB5, 0x72, 0x4E, 0x30, 0xC4, 0x97, 0x84, 0x86,
    0x2D, 0x56, 0x2F, 0xD7, 0x15, 0xF7, 0x7F, 0xC0,
    0xAE, 0xF5, 0xFC, 0x5B, 0xE5, 0xFB, 0xA1, 0xBA,
    0xD3, 0x02, 0x03, 0x01, 0x00, 0x01
};

