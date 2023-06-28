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
 * Implementation of the AES-GCM Encryption/Authentication
 *
 * Some restrictions:
 * 1. Only for use with AES
 * 2. Returned tag is always 128-bits. Truncate at your own risk.
 * 3. The order of function calls must follow some rules
 *
 * Typical sequence of calls:
 * 1. call GCM_init
 * 2. call GCM_add_header any number of times, as long as length of header is multiple of 16 bytes (block size)
 * 3. call GCM_add_header one last time with any length of header
 * 4. call GCM_add_cipher any number of times, as long as length of cipher/plaintext is multiple of 16 bytes
 * 5. call GCM_add_cipher one last time with any length of cipher/plaintext
 * 6. call GCM_finish to extract the tag.
 *
 * See http://www.mindspring.com/~dmcgrew/gcm-nist-6.pdf
 */
/* SU=m, m is Stack Usage */

#include <string.h>
#include "arch.h"
#include "amcl.h"

#define NB 4
#define MR_TOBYTE(x) ((uchar)((x)))

static unsign32 pack(const uchar *b)
{
    /* pack bytes into a 32-bit Word */
    return ((unsign32)b[0]<<24)|((unsign32)b[1]<<16)|((unsign32)b[2]<<8)|(unsign32)b[3];
}

static void unpack(unsign32 a,uchar *b)
{
    /* unpack bytes from a word */
    b[3]=MR_TOBYTE(a);
    b[2]=MR_TOBYTE(a>>8);
    b[1]=MR_TOBYTE(a>>16);
    b[0]=MR_TOBYTE(a>>24);
}

static void precompute(gcm *g,const uchar *H)
{
    /* precompute small 2k bytes gf2m table of x^n.H */
    int i;
    int j;
    const unsign32 *last;
    unsign32 *next;
    unsign32 b;

    for (i=j=0; i<NB; i++,j+=4) g->table[0][i]=pack(&H[j]);

    for (i=1; i<128; i++)
    {
        next=g->table[i];
        last=g->table[i-1];
        b=0;
        for (j=0; j<NB; j++)
        {
            next[j]=b|(last[j])>>1;
            b=last[j]<<31;
        }
        if (b) next[0]^=0xE1000000; /* irreducible polynomial */
    }
}

/* SU= 32 */
static void gf2mul(gcm *g)
{
    /* gf2m mul - Z=H*X mod 2^128 */
    int i;
    int j;
    int m;
    unsign32 P[4];
    unsign32 b;

    P[0]=P[1]=P[2]=P[3]=0;
    j=8;
    m=0;
    for (i=0; i<128; i++)
    {
        b=(unsign32)(g->stateX[m]>>(--j))&1;
        b=~b+1;
        for (int k=0; k<NB; k++) P[k]^=(g->table[i][k]&b);
        if (j==0)
        {
            j=8;
            m++;
            if (m==16) break;
        }
    }
    for (i=j=0; i<NB; i++,j+=4) unpack(P[i],&g->stateX[j]);
}

/* SU= 32 */
static void GCM_wrap(gcm *g)
{
    /* Finish off GHASH */
    int i;
    int j;
    unsign32 F[4];
    uchar L[16];

    /* convert lengths from bytes to bits */
    F[0]=(g->lenA[0]<<3)|(g->lenA[1]&0xE0000000)>>29;
    F[1]=g->lenA[1]<<3;
    F[2]=(g->lenC[0]<<3)|(g->lenC[1]&0xE0000000)>>29;
    F[3]=g->lenC[1]<<3;
    for (i=j=0; i<NB; i++,j+=4) unpack(F[i],&L[j]);

    for (i=0; i<16; i++) g->stateX[i]^=L[i];
    gf2mul(g);
}

static int GCM_ghash(gcm *g,const char *plain,int len)
{
    int j=0;
    if (g->status==GCM_ACCEPTING_HEADER) g->status=GCM_ACCEPTING_CIPHER;
    if (g->status!=GCM_ACCEPTING_CIPHER) return 0;

    while (j<len)
    {
        for (int i=0; i<16 && j<len; i++,j++)
        {
            g->stateX[i]^=plain[j];
            g->lenC[1]++;
            if (g->lenC[1]==0) g->lenC[0]++;
        }
        gf2mul(g);
    }
    if (len%16!=0) g->status=GCM_NOT_ACCEPTING_MORE;
    return 1;
}

/* SU= 48 */
/* Initialize GCM mode */
void GCM_init(gcm* g,int nk,char *key,int niv,const char *iv)
{
    /* iv size niv is usually 12 bytes (96 bits). AES key size nk can be 16,24 or 32 bytes */
    uchar H[16];
    for (int i=0; i<16; i++)
    {
        H[i]=0;
        g->stateX[i]=0;
    }

    AES_init(&(g->a),ECB,nk,key,iv);
    AES_ecb_encrypt(&(g->a),H);     /* E(K,0) */
    precompute(g,H);

    g->lenA[0]=g->lenC[0]=g->lenA[1]=g->lenC[1]=0;
    if (niv==12)
    {
        for (int i=0; i<12; i++) g->a.f[i]=iv[i];
        unpack((unsign32)1,(uchar *)&(g->a.f[12]));  /* initialise IV */
        for (int i=0; i<16; i++) g->Y_0[i]=g->a.f[i];
    }
    else
    {
        g->status=GCM_ACCEPTING_CIPHER;
        GCM_ghash(g,iv,niv); /* GHASH(H,0,IV) */
        GCM_wrap(g);
        for (int i=0; i<16; i++)
        {
            g->a.f[i]=g->stateX[i];
            g->Y_0[i]=g->a.f[i];
            g->stateX[i]=0;
        }
        g->lenA[0]=g->lenC[0]=g->lenA[1]=g->lenC[1]=0;
    }
    g->status=GCM_ACCEPTING_HEADER;
}

/* SU= 24 */
/* Add Header data - included but not encrypted */
int GCM_add_header(gcm* g,const char *header,int len)
{
    /* Add some header. Won't be encrypted, but will be authenticated. len is length of header */
    int j=0;
    if (g->status!=GCM_ACCEPTING_HEADER) return 0;

    while (j<len)
    {
        for (int i=0; i<16 && j<len; i++,j++)
        {
            g->stateX[i]^=header[j];
            g->lenA[1]++;
            if (g->lenA[1]==0) g->lenA[0]++;
        }
        gf2mul(g);
    }
    if (len%16!=0) g->status=GCM_ACCEPTING_CIPHER;
    return 1;
}

/* SU= 48 */
/* Add Plaintext - included and encrypted */
int GCM_add_plain(gcm *g,char *cipher,const char *plain,int len)
{
    /* Add plaintext to extract ciphertext, len is length of plaintext.  */
    int j=0;
    unsign32 counter;
    uchar B[16];
    if (g->status==GCM_ACCEPTING_HEADER) g->status=GCM_ACCEPTING_CIPHER;
    if (g->status!=GCM_ACCEPTING_CIPHER) return 0;

    while (j<len)
    {
        counter=pack((uchar *)&(g->a.f[12]));
        counter++;
        unpack(counter,(uchar *)&(g->a.f[12]));  /* increment counter */
        for (int i=0; i<16; i++) B[i]=g->a.f[i];
        AES_ecb_encrypt(&(g->a),B);        /* encrypt it  */

        for (int i=0; i<16 && j<len; i++,j++)
        {
            cipher[j]=(char)(plain[j]^B[i]);
            g->stateX[i]^=cipher[j];
            g->lenC[1]++;
            if (g->lenC[1]==0) g->lenC[0]++;
        }
        gf2mul(g);
    }
    if (len%16!=0) g->status=GCM_NOT_ACCEPTING_MORE;
    return 1;
}

/* SU= 48 */
/* Add Ciphertext - decrypts to plaintext */
int GCM_add_cipher(gcm *g,char *plain,const char *cipher,int len)
{
    /* Add ciphertext to extract plaintext, len is length of ciphertext. */
    int j=0;
    unsign32 counter;
    char oc;
    uchar B[16];
    if (g->status==GCM_ACCEPTING_HEADER) g->status=GCM_ACCEPTING_CIPHER;
    if (g->status!=GCM_ACCEPTING_CIPHER) return 0;

    while (j<len)
    {
        counter=pack((uchar *)&(g->a.f[12]));
        counter++;
        unpack(counter,(uchar *)&(g->a.f[12]));  /* increment counter */
        for (int i=0; i<16; i++) B[i]=g->a.f[i];
        AES_ecb_encrypt(&(g->a),B);        /* encrypt it  */
        for (int i=0; i<16 && j<len; i++,j++)
        {
            oc=cipher[j];
            plain[j]=(char)(cipher[j]^B[i]);
            g->stateX[i]^=oc;
            g->lenC[1]++;
            if (g->lenC[1]==0) g->lenC[0]++;
        }
        gf2mul(g);
    }
    if (len%16!=0) g->status=GCM_NOT_ACCEPTING_MORE;
    return 1;
}

/* SU= 16 */
/* Finish and extract Tag */
void GCM_finish(gcm *g,char *tag)
{
    /* Finish off GHASH and extract tag (MAC) */
    int i;

    GCM_wrap(g);

    /* extract tag */
    if (tag!=NULL)
    {
        AES_ecb_encrypt(&(g->a),g->Y_0);        /* E(K,Y0) */
        for (i=0; i<16; i++) g->Y_0[i]^=g->stateX[i];
        for (i=0; i<16; i++)
        {
            tag[i]=g->Y_0[i];
            g->Y_0[i]=g->stateX[i]=0;
        }
    }
    g->status=GCM_FINISHED;
    AES_end(&(g->a));
}
