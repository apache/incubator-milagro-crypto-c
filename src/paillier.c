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

/* test driver and function exerciser for Paillier functions */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "ff_4096.h"
#include "ff_2048.h"
#include "paillier.h"

void FF_4096_divide(BIG_512_60 x[], BIG_512_60 y[], BIG_512_60 z[])
{
    BIG_512_60 d[FFLEN_4096];
    BIG_512_60 q[FFLEN_4096];

    FF_4096_zero(z,FFLEN_4096);

    while(FF_4096_comp(x,y,FFLEN_4096) <= 0)
    {
        // (Re)set values for d and q
        FF_4096_one(q,FFLEN_4096);
        FF_4096_copy(d,x,FFLEN_4096);

        // Left shift the denominator until bigger that remainder
        while(FF_4096_comp(d,y,FFLEN_4096) == -1)
        {
            FF_4096_shl(d,FFLEN_4096);
            FF_4096_shl(q,FFLEN_4096);
        }

        // Right shift the denominator if bigger than the remainder
        if(FF_4096_comp(d,y,FFLEN_4096) == 1)
        {
            FF_4096_shr(q,FFLEN_4096);
            FF_4096_shr(d,FFLEN_4096);
        }

        // y = y - d i.e. remainder
        FF_4096_sub(y,y,d,FFLEN_4096);
        FF_4096_norm(y,FFLEN_4096);

        // z = z + q i.e. update quotient
        FF_4096_add(z,z,q,FFLEN_4096);
    }
}

/* generate a Paillier key pair */
void PAILLIER_KEY_PAIR(csprng *RNG, octet *P, octet* Q, PAILLIER_public_key *PUB, PAILLIER_private_key *PRIV)
{
    BIG_1024_58 p[HFLEN_2048];
    BIG_1024_58 q[HFLEN_2048];

    // Public key
    BIG_1024_58 n[FFLEN_2048];
    BIG_1024_58 g[FFLEN_2048];

    // Secret key
    BIG_1024_58 l[FFLEN_2048];
    BIG_1024_58 m[FFLEN_2048];

    if (RNG!=NULL)
    {
        // p
        FF_2048_random(p,RNG,HFLEN_2048);
        while (FF_2048_lastbits(p,2)!=3)
        {
            FF_2048_inc(p,1,HFLEN_2048);
        }
        while (!FF_2048_prime(p,RNG,HFLEN_2048))
        {
            FF_2048_inc(p,4,HFLEN_2048);
        }

        // q
        FF_2048_random(q,RNG,HFLEN_2048);
        while (FF_2048_lastbits(q,2)!=3)
        {
            FF_2048_inc(q,1,HFLEN_2048);
        }
        while (!FF_2048_prime(q,RNG,HFLEN_2048))
        {
            FF_2048_inc(q,4,HFLEN_2048);
        }
    }
    else
    {
        FF_2048_fromOctet(p,P,HFLEN_2048);
        FF_2048_fromOctet(q,Q,HFLEN_2048);
    }

    // n = p * q
    FF_2048_mul(n,p,q,HFLEN_2048);

    // g = n + 1
    FF_2048_copy(g,n,FFLEN_2048);
    FF_2048_inc(g,1,FFLEN_2048);

    // Decrement p and q in place. They need to
    // be restored before being returned
    FF_2048_dec(p,1,HFLEN_2048);
    FF_2048_dec(q,1,HFLEN_2048);

    // l = (p-1) * (q-1)
    FF_2048_mul(l,p,q,HFLEN_2048);

    // m = ((p-1) * (q-1))^{-1} mod n
    FF_2048_invmodp(m,l,n,FFLEN_2048);

    // Restore p and q for output
    FF_2048_inc(p,1,HFLEN_2048);
    FF_2048_inc(q,1,HFLEN_2048);


    // Output Private Key
    char oct[FS_2048];
    octet OCT = {0,FS_2048, oct};

    FF_2048_toOctet(&OCT, p, HFLEN_2048);
    OCT_pad(&OCT,HFS_4096);
    FF_4096_fromOctet(PRIV->p, &OCT, HFLEN_4096);
    OCT_empty(&OCT);

    FF_2048_toOctet(&OCT, q, HFLEN_2048);
    OCT_pad(&OCT,HFS_4096);
    FF_4096_fromOctet(PRIV->q, &OCT, HFLEN_4096);
    OCT_empty(&OCT);

    FF_2048_toOctet(&OCT, n, FFLEN_2048);
    FF_4096_zero(PRIV->n, FFLEN_4096);
    FF_4096_fromOctet(PRIV->n, &OCT, HFLEN_4096);
    OCT_empty(&OCT);

    FF_2048_toOctet(&OCT, g, FFLEN_2048);
    FF_4096_zero(PRIV->g, FFLEN_4096);
    FF_4096_fromOctet(PRIV->g, &OCT, HFLEN_4096);
    OCT_empty(&OCT);

    FF_2048_toOctet(&OCT, l, FFLEN_2048);
    FF_4096_zero(PRIV->l, FFLEN_4096);
    FF_4096_fromOctet(PRIV->l, &OCT, HFLEN_4096);
    OCT_empty(&OCT);

    FF_2048_toOctet(&OCT, m, FFLEN_2048);
    FF_4096_zero(PRIV->m, FFLEN_4096);
    FF_4096_fromOctet(PRIV->m, &OCT, HFLEN_4096);
    OCT_empty(&OCT);

    // Precompute n^2
    FF_4096_sqr(PRIV->n2, PRIV->n, HFLEN_4096);
    FF_4096_norm(PRIV->n2, FFLEN_4096);

    // Output Public Key
    FF_4096_copy(PUB->n , PRIV->n , FFLEN_4096);
    FF_4096_copy(PUB->g , PRIV->g , FFLEN_4096);
    FF_4096_copy(PUB->n2, PRIV->n2, FFLEN_4096);

#ifdef DEBUG
    printf("p ");
    FF_2048_output(p,HFLEN_2048);
    printf("\n");
    printf("q ");
    FF_2048_output(q,HFLEN_2048);
    printf("\n");

    printf("n ");
    FF_2048_output(n,FFLEN_2048);
    printf("\n");
    printf("g ");
    FF_2048_output(g,FFLEN_2048);
    printf("\n");

    printf("l ");
    FF_2048_output(l,FFLEN_2048);
    printf("\n");
    printf("m ");
    FF_2048_output(m,FFLEN_2048);
    printf("\n");
#endif

    // Clean secret keys from memory
    FF_2048_zero(p,HFLEN_2048);
    FF_2048_zero(q,HFLEN_2048);
    FF_2048_zero(l,FFLEN_2048);
    FF_2048_zero(m,FFLEN_2048);
}

/* Clean secrets from private key */
void PAILLIER_PRIVATE_KEY_KILL(PAILLIER_private_key *PRIV)
{
    FF_4096_zero(PRIV->l, FFLEN_4096);
    FF_4096_zero(PRIV->m, FFLEN_4096);
    FF_4096_zero(PRIV->p, HFLEN_4096/2);
    FF_4096_zero(PRIV->q, HFLEN_4096/2);
}

/* Paillier encrypt
 R is for testing
*/
void PAILLIER_ENCRYPT(csprng *RNG, PAILLIER_public_key *PUB, octet* PT, octet* CT, octet* R)
{
    // Random r < n
    BIG_512_60 r[FFLEN_4096];

    // plaintext
    BIG_512_60 pt[FFLEN_4096];

    // ciphertext
    BIG_512_60 ct[FFLEN_4096];

    FF_4096_zero(pt, FFLEN_4096);
    FF_4096_fromOctet(pt,PT,HFLEN_4096);

    // In production generate R from RNG
    if (RNG!=NULL)
    {
        FF_4096_randomnum(r,PUB->n2,RNG,FFLEN_4096);
    }
    else
    {
        FF_4096_fromOctet(r,R,FFLEN_4096);
    }

    // ct = g^pt * r^n mod n2
    FF_4096_skpow2(ct, PUB->g, pt, r, PUB->n, PUB->n2, FFLEN_4096);

    // Output
    FF_4096_toOctet(CT, ct, FFLEN_4096);

    // Output R for Debug
    if (R!=NULL)
    {
        FF_4096_toOctet(R, r, HFLEN_4096);
    }

#ifdef DEBUG
    printf("n ");
    FF_4096_output(PUB->n,FFLEN_4096);
    printf("\n\n");
    printf("g ");
    FF_4096_output(PUB->g,FFLEN_4096);
    printf("\n\n");
    printf("n2 ");
    FF_4096_output(PUB->n2,FFLEN_4096);
    printf("\n\n");
    printf("r ");
    FF_4096_output(r,FFLEN_4096);
    printf("\n\n");
    printf("pt ");
    FF_4096_output(pt,FFLEN_4096);
    printf("\n\n");
    printf("ct ");
    FF_4096_output(ct,FFLEN_4096);
    printf("\n\n");
    printf("CT: ");
    OCT_output(CT);
    printf("\n");
#endif

    // Clean memory
    FF_4096_zero(pt, HFLEN_4096);
}

/* Paillier decrypt */
void PAILLIER_DECRYPT(PAILLIER_private_key *PRIV, octet* CT, octet* PT)
{
       // Ciphertext
    BIG_512_60 ct[FFLEN_4096];

    // Plaintext
    BIG_512_60 pt[FFLEN_4096];

    // ctl = ct^l mod n^2
    BIG_512_60 ctl[FFLEN_4096];

    // ctln = ctl / n
    BIG_512_60 ctln[FFLEN_4096];

    FF_4096_fromOctet(ct,CT,FFLEN_4096);

    // ct^l mod n^2 - 1
    FF_4096_skpow(ctl,ct,PRIV->l,PRIV->n2,FFLEN_4096);
    FF_4096_dec(ctl,1,FFLEN_4096);

#ifdef DEBUG
    printf("PAILLIER_DECRYPT ctl ");
    FF_4096_output(ctl,FFLEN_4096);
    printf("\n\n");
#endif

    // ctln = ctl / n
    // note that ctln fits into a FF_2048 element,
    // since ctln = ctl/n < n^2 / n = n
    FF_4096_divide(PRIV->n, ctl, ctln);

    // pt = ctln * m mod n
    // the result fits into a FF_4096 element,
    // since both m and ctln fit into a FF_2048 element
    FF_4096_mul(pt, ctln, PRIV->m, HFLEN_4096);
#ifdef DEBUG
    printf("pt1 ");
    FF_4096_output(pt,FFLEN_4096);
    printf("\n\n");
#endif
    FF_4096_mod(pt,PRIV->n,FFLEN_4096);

    // Output
    FF_4096_toOctet(PT, pt, HFLEN_4096);

#ifdef DEBUG
    printf("PAILLIER_DECRYPT n ");
    FF_4096_output(PRIV->n,FFLEN_4096);
    printf("\n\n");
    printf("PAILLIER_DECRYPT l ");
    FF_4096_output(PRIV->l,FFLEN_4096);
    printf("\n\n");
    printf("PAILLIER_DECRYPT m ");
    FF_4096_output(PRIV->m,FFLEN_4096);
    printf("\n\n");
    printf("PAILLIER_DECRYPT ct ");
    FF_4096_output(ct,FFLEN_4096);
    printf("\n\n");
    printf("PAILLIER_DECRYPT ctln ");
    FF_4096_output(ctln,FFLEN_4096);
    printf("\n\n");
    printf("PAILLIER_DECRYPT pt ");
    FF_4096_output(pt,FFLEN_4096);
    printf("\n\n");
#endif

    // Clean memory
    FF_4096_zero(ctl, FFLEN_4096);
    FF_4096_zero(ctln, FFLEN_4096);
    FF_4096_zero(pt, HFLEN_4096);
}

/* Homomorphic addition of plaintexts */
/*  n2 = n * n
    ct = ct1 * ct2
    ct = ct % n2
*/
void PAILLIER_ADD(PAILLIER_public_key *PUB, octet* CT1, octet* CT2, octet* CT)
{
    // ciphertext
    BIG_512_60 ct1[FFLEN_4096];
    BIG_512_60 ct2[FFLEN_4096];
    BIG_512_60 ct[2 * FFLEN_4096];

    FF_4096_fromOctet(ct1,CT1,FFLEN_4096);
    FF_4096_fromOctet(ct2,CT2,FFLEN_4096);

#ifdef DEBUG
    printf("PAILLIER_ADD ct1 ");
    FF_4096_output(ct1,FFLEN_4096);
    printf("\n\n");
    printf("PAILLIER_ADD ct2 ");
    FF_4096_output(ct2,FFLEN_4096);
    printf("\n\n");
#endif

    // ct = ct1 * ct2 mod n^2
    FF_4096_mul(ct,ct1,ct2,FFLEN_4096);

#ifdef DEBUG
    printf("PAILLIER_ADD ct1 * ct2 ");
    FF_4096_output(ct,2 * FFLEN_4096);
    printf("\n\n");
#endif

    FF_4096_dmod(ct,ct,PUB->n2,FFLEN_4096);

    // Output
    FF_4096_toOctet(CT, ct, FFLEN_4096);

#ifdef DEBUG
    printf("PAILLIER_ADD n ");
    FF_4096_output(PUB->n,HFLEN_4096);
    printf("\n\n");
    printf("PAILLIER_ADD ct1 ");
    FF_4096_output(ct1,FFLEN_4096);
    printf("\n\n");
    printf("PAILLIER_ADD ct2 ");
    FF_4096_output(ct2,FFLEN_4096);
    printf("\n\n");
#endif
}

/* Homomorphic multiplation of plaintext

    ct = ct1 ^ pt mod n^2

*/
void PAILLIER_MULT(PAILLIER_public_key *PUB, octet* CT1, octet* PT, octet* CT)
{
    // Ciphertext
    BIG_512_60 ct1[FFLEN_4096];

    // Plaintext
    BIG_512_60 pt[FFLEN_4096];

    // Ciphertext output. ct = ct1 ^ pt mod n^2
    BIG_512_60 ct[FFLEN_4096];

    FF_4096_zero(pt, FFLEN_4096);
    FF_4096_fromOctet(pt,PT,HFLEN_4096);

    FF_4096_fromOctet(ct1,CT1,FFLEN_4096);

    // ct1^pt mod n^2
    FF_4096_skpow(ct,ct1,pt,PUB->n2,FFLEN_4096);

    // output
    FF_4096_toOctet(CT, ct, FFLEN_4096);

#ifdef DEBUG
    printf("PAILLIER_MULT n: ");
    FF_4096_output(PUB->n,HFLEN_4096);
    printf("\n\n");
    printf("PAILLIER_MULT n2: ");
    FF_4096_output(PUB->n2,FFLEN_4096);
    printf("\n\n");
    printf("PAILLIER_MULT ct1: ");
    FF_4096_output(ct1,FFLEN_4096);
    printf("\n\n");
    printf("PAILLIER_MULT pt: ");
    FF_4096_output(pt,FFLEN_4096);
    printf("\n\n");
    printf("PAILLIER_MULT ct: ");
    FF_4096_output(ct,FFLEN_4096);
    printf("\n\n");
#endif

    // Clean memory
    FF_4096_zero(pt, HFLEN_4096);
}
