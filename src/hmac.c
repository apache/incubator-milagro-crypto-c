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
 * @file hmac.c
 *
 * @author Alexandre Adomnicai <alexandre.adomnicai@qredo.com>
 *
 * @brief Implementation of the Keyed-Hash Message Authentication Code (HMAC)
 * with SHA-256 according to FIPS 198-1 and RFC 2104.
 */
#include "arch.h"
#include "amcl.h"

int HMAC_SHA256_init(hmac_sha256 *ctx, const char* key, int keylen)
{
    if (ctx == NULL || key == NULL)
        return ERR_NULLPOINTER_HMAC;
    if (keylen < SHA256_HASH_SIZE)
        return ERR_KEYSIZE_HMAC;

    int i;
    char ipad = 0x36;

    // Initialize the underlying SHA256 instance
    HASH256_init(&(ctx->sha256_ctx));
    // Fill k0 with 0s for future padding
    for(i = 0; i < SHA256_BLOCK_SIZE; i++)
        ctx->k0[i] = 0x00;

    // If the key size is larger than the block size, then hash it
    if (keylen > SHA256_BLOCK_SIZE) {
        for(i = 0; i < keylen; i++)
            HASH256_process(&(ctx->sha256_ctx), key[i]);
        HASH256_hash(&(ctx->sha256_ctx), ctx->k0);
    }
    // Otherwise the key is simply padded with 0s into k0
    else {
        for(i = 0; i < keylen; i++)
            ctx->k0[i] = key[i];
    }

    // Update the HMAC instance to process k0 ^ ipad
    for(i = 0; i < SHA256_BLOCK_SIZE; i++)
        HASH256_process(&(ctx->sha256_ctx), (ctx->k0)[i] ^ ipad);

    return SUCCESS;
}

int HMAC_SHA256_update(hash256 *ctx, const char* in, int inlen)
{
    if (ctx == NULL)
        return ERR_NULLPOINTER_HMAC;
    if (inlen > 0 && in == NULL)
        return ERR_NULLPOINTER_HMAC;
    if (inlen < 0)
        return ERR_BADARGLEN_HMAC;

    // Update the HMAC instance to process in
    for(int i = 0; i < inlen; i++)
        HASH256_process(ctx, in[i]);

    return SUCCESS;
}

int HMAC_SHA256_final(hmac_sha256 *ctx, char* out, int outlen)
{
    if (ctx == NULL || out == NULL)
        return ERR_NULLPOINTER_HMAC;
    if (outlen <= 0 || outlen > SHA256_HASH_SIZE)
        return ERR_BADARGLEN_HMAC;

    int i;
    char opad = 0x5c;
    char digest[SHA256_HASH_SIZE];

    // Compute H((k0 ^ ipad) || in)
    HASH256_hash(&(ctx->sha256_ctx), digest);

    // Compute `H((K0 ^ opad ) || H((K0 ^ ipad) || in))`
    for(i = 0; i < SHA256_BLOCK_SIZE; i++)
        HASH256_process(&(ctx->sha256_ctx), (ctx->k0)[i] ^ opad);
    for(i = 0; i < SHA256_HASH_SIZE; i++)
        HASH256_process(&(ctx->sha256_ctx), digest[i]);
    HASH256_hash(&(ctx->sha256_ctx), digest);

    // Erase the secret key as it is not needed anymore
    for(i = 0; i < SHA256_BLOCK_SIZE; i++)
        ctx->k0[i] = 0x00;

    for(i = 0; i < outlen; i++)
        out[i] = digest[i];

    return SUCCESS;
}

int HMAC_SHA256_oneshot(char* out,  int outlen,
    const char* key,  int keylen,
    const char* in,  int inlen)
{
    if (out == NULL || key == NULL || in == NULL)
        return ERR_NULLPOINTER_HMAC;
    if (keylen < SHA256_HASH_SIZE)
        return ERR_KEYSIZE_HMAC;
    if (outlen <= 0 || outlen > SHA256_HASH_SIZE || inlen < 0)
        return ERR_BADARGLEN_HMAC;

    int i;
    hash256 sha256;
    char ipad = 0x36;
    char opad = 0x5c;
    char k0[SHA256_BLOCK_SIZE];
    char digest[SHA256_HASH_SIZE];

    HASH256_init(&sha256);
    // Fill k0 with 0s for future padding
    for(i = 0; i < SHA256_BLOCK_SIZE; i++)
        k0[i] = 0x00;

    // If the key size is larger than the block size, then hash it
    if (keylen > SHA256_BLOCK_SIZE) {
        for(i = 0; i < keylen; i++)
            HASH256_process(&sha256, key[i]);
        HASH256_hash(&sha256, k0);
    }
    // Otherwise the key is simply padded with 0s into k0
    else {
        for(i = 0; i < keylen; i++)
            k0[i] = key[i];
    }

    // Compute H((k0 ^ ipad) || in)
    for(i = 0; i < SHA256_BLOCK_SIZE; i++)
        HASH256_process(&sha256, k0[i] ^ ipad);
    for(i = 0; i < inlen; i++)
        HASH256_process(&sha256, in[i]);
    HASH256_hash(&sha256, digest);

    // Compute `H((k0 ^ opad ) || H((k0 ^ ipad) || in))`
    for(i = 0; i < SHA256_BLOCK_SIZE; i++)
        HASH256_process(&sha256, k0[i] ^ opad);
    for(i = 0; i < SHA256_HASH_SIZE; i++)
        HASH256_process(&sha256, digest[i]);
    HASH256_hash(&sha256, digest);

    // Erase the secret key as it is not needed anymore
    for(i = 0; i < SHA256_BLOCK_SIZE; i++)
        k0[i] = 0x00;

    for(i = 0; i < outlen; i++)
        out[i] = digest[i];

    return SUCCESS;
}
