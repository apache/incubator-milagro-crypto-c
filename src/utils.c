/**
 * @file utils.c
 * @author Mike Scott
 * @author Kealan McCusker
 * @date 28th July 2016
 * @brief AMCL Support functions for M-Pin servers
 *
 * LICENSE
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/* AMCL Support functions for M-Pin servers */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "amcl.h"
#include "utils.h"

#ifdef __cplusplus
extern "C"{
#endif

/* Decode a byte to a 2 chars string */

/** Decode hex value */
void amcl_hex2bin(const char *src, char *dst, size_t src_len)
{
    char v,c;
    for (size_t i = 0; i < src_len/2; i++)
    {
        c = src[2*i];
        if (c >= '0' && c <= '9')
        {
            v = c - '0';
        }
        else if (c >= 'A' && c <= 'F')
        {
            v = c - 'A' + 10;
        }
        else if (c >= 'a' && c <= 'f')
        {
            v = c - 'a' + 10;
        }
        else
        {
            v = 0;
        }
        v <<= 4;
        c = src[2*i + 1];
        if (c >= '0' && c <= '9')
        {
            v += c - '0';
        }
        else if (c >= 'A' && c <= 'F')
        {
            v += c - 'A' + 10;
        }
        else if (c >= 'a' && c <= 'f')
        {
            v += c - 'a' + 10;
        }
        else
        {
            v = 0;
        }
        dst[i] = v;
    }
}

/* Encode binary string */
void amcl_bin2hex(char *src, char *dst, size_t src_len, size_t dst_len)
{
    const char * hexadecimals = "0123456789abcdef";
    unsigned char ch;
    for (size_t i = 0; i < src_len && i< dst_len/2; i++)
    {
        ch=src[i];
        uint8_t res = ch / 16;
        uint8_t mod = ch % 16;
        dst[i*2] = hexadecimals[res];
        dst[(i*2)+1] = hexadecimals[mod];
    }
}

/* Print encoded binary string in hex */
void amcl_print_hex(char *src, size_t src_len)
{
    for (size_t i = 0; i < src_len; i++)
    {
        printf("%02x", (unsigned char) src[i]);
    }
    printf("\n");
}

/* Generates a random six digit one time password */
int generateOTP(csprng* RNG)
{
    int OTP=0;

    int i = 0;
    int val = 0;
    unsigned char byte[6] = {0};
    int mult=1;

    // Generate random 6 digit random value
    for (i=0; i<6; i++)
    {
        byte[i]=RAND_byte(RNG);
        val = byte[i];
        OTP = ((abs(val) % 10) * mult) + OTP;
        mult = mult * 10;
    }

    return OTP;
}

/* Generate a random Octet */
void generateRandom(csprng *RNG,octet *randomValue)
{
    int i;
    for (i=0; i<randomValue->len; i++)
    {
        randomValue->val[i] = RAND_byte(RNG);
    }
}

#ifdef __cplusplus
}
#endif
