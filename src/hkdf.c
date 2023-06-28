/*
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.
*/

/*
 * @file hkdf.c
 *
 * @author Alexandre Adomnicai <alexandre.adomnicai@qredo.com>
 *
 * @brief Implementation of the HMAC-based Extract-and-Expand Key Derivation
 * Function with SHA-256 according to RFC 5869.
 */
#include "arch.h"
#include "amcl.h"

#define SUCCESS                 0x00000000
#define ERR_NULLPOINTER_HKDF    0x00000201
#define ERR_BADARGLEN_HKDF      0x00000202

int HKDF_SHA256_extract(char prk[SHA256_HASH_SIZE],
    const char *salt, unsigned int saltlen,
    const char *ikm,  unsigned int ikmlen)
{
    if (prk == NULL || ikm == NULL)
        return ERR_NULLPOINTER_HKDF;
    if (ikmlen == 0)
        return ERR_BADARGLEN_HKDF;
    if (salt == NULL && saltlen != 0)
        return ERR_BADARGLEN_HKDF;
    if (saltlen != 0 && saltlen < SHA256_HASH_SIZE)
        return ERR_BADARGLEN_HKDF;

    char zeros[SHA256_HASH_SIZE] = {0x00};

    // If salt isn't provided, the key is set to 0
    if (salt == NULL || saltlen == 0)
        return HMAC_SHA256_oneshot(prk, SHA256_HASH_SIZE, zeros, SHA256_HASH_SIZE, ikm, ikmlen);
    else
        return HMAC_SHA256_oneshot(prk, SHA256_HASH_SIZE, salt, saltlen, ikm, ikmlen);
}

int HKDF_SHA256_expand(char *okm, unsigned int okmlen,
    const char *prk, unsigned int prklen,
    const char *info, unsigned int infolen)
{
    if (okm == NULL || prk == NULL)
        return ERR_NULLPOINTER_HKDF;
    if (prklen != SHA256_HASH_SIZE || okmlen > 255*SHA256_HASH_SIZE)
        return ERR_BADARGLEN_HKDF;

    unsigned int i;
    int ret = SUCCESS;
    char count = 0x01;
    char tmp[SHA256_HASH_SIZE];

    hmac_sha256 ctx;
    ret |= HMAC_SHA256_init(&ctx, prk, SHA256_HASH_SIZE);
    ret |= HMAC_SHA256_update(&(ctx.sha256_ctx), info, infolen);
    ret |= HMAC_SHA256_update(&(ctx.sha256_ctx), &count, 1);
    ret |= HMAC_SHA256_final(&ctx, tmp, SHA256_HASH_SIZE);

    while (okmlen > SHA256_HASH_SIZE) {
        count++;
        for(i = 0; i < SHA256_HASH_SIZE; i++)
            okm[i] = tmp[i];
        okm     += SHA256_HASH_SIZE;
        okmlen  -= SHA256_HASH_SIZE;
        ret |= HMAC_SHA256_init(&ctx, prk, SHA256_HASH_SIZE);
        ret |= HMAC_SHA256_update(&(ctx.sha256_ctx), tmp, SHA256_HASH_SIZE);
        ret |= HMAC_SHA256_update(&(ctx.sha256_ctx), info, infolen);
        ret |= HMAC_SHA256_update(&(ctx.sha256_ctx), &count, 1);
        ret |= HMAC_SHA256_final(&ctx, tmp, SHA256_HASH_SIZE);
    }

    for(i = 0; i < okmlen; i++)
        okm[i] = tmp[i];

    return ret;
}
