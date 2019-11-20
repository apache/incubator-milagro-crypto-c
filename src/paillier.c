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
#include "ff_8192.h"
#include "ff_4096.h"
#include "ff_2048.h"
#include "paillier.h"

/* Truncates an octet string */
void OCT_truncate(octet *y,octet *x)
{
    /* y < x */
    int i=0;
    int j=0;
    if (x==NULL) return;
    if (y==NULL) return;

    for (i=0; i<y->len; i++)
    {
        j=x->len+i;
        if (i>=y->max)
        {
            y->len=y->max;
            return;
        }
        y->val[i]=x->val[j];
    }
}

int FF_4096_divide(BIG_512_60 x[], BIG_512_60 y[], BIG_512_60 z[])
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

    return 0;
}

/* generate a Paillier key pair */
int PAILLIER_KEY_PAIR(csprng *RNG, octet *P, octet* Q, octet* N, octet* G, octet* L, octet* M)
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

    // Output
    if (P != NULL)
        FF_2048_toOctet(P, p, HFLEN_2048);

    if (Q != NULL)
        FF_2048_toOctet(Q, q, HFLEN_2048);

    FF_2048_toOctet(N, n, FFLEN_2048);
    FF_2048_toOctet(G, g, FFLEN_2048);

    FF_2048_toOctet(L, l, FFLEN_2048);
    FF_2048_toOctet(M, m, FFLEN_2048);

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

    return 0;
}

/* Paillier encrypt
 R is for testing
*/
int PAILLIER_ENCRYPT(csprng *RNG, octet* N, octet* G, octet* PT, octet* CT, octet* R)
{
    // Public key
    BIG_512_60 n[FFLEN_4096];
    BIG_512_60 g[FFLEN_4096];

    // n2 = n^2
    BIG_512_60 n2[FFLEN_4096];
    BIG_512_60 n28[FFLEN_8192];

    // Random r < n
    BIG_1024_58 n1[FFLEN_2048];
    BIG_1024_58 r1[FFLEN_2048];
    BIG_512_60 r[FFLEN_4096];

    // plaintext
    BIG_512_60 pt[FFLEN_4096];

    // g^pt mod n^2
    BIG_512_60 gpt[FFLEN_4096];
    BIG_512_60 gpt8[FFLEN_8192];

    // r^n mod n^2
    BIG_512_60 rn[FFLEN_4096];
    BIG_512_60 rn8[FFLEN_8192];

    // ciphertext
    BIG_512_60 ct[FFLEN_8192];

    // Convert n from FF_2048 to FF_4096
    char noct[FS_4096] = {0};
    octet NOCT = {FS_2048,FS_4096,noct};
    OCT_joctet(&NOCT, N);
    FF_4096_fromOctet(n,&NOCT,FFLEN_4096);

    // Convert g from FF_2048 to FF_4096
    char goct[FS_4096] = {0};
    octet GOCT = {FS_2048,FS_4096,goct};
    OCT_joctet(&GOCT, G);
    FF_4096_fromOctet(g,&GOCT,FFLEN_4096);


    // In production generate R from RNG
    if (RNG!=NULL)
    {
        // r < n
        FF_2048_fromOctet(n1,N,FFLEN_2048);
        FF_2048_randomnum(r1,n1,RNG,FFLEN_2048);

        // Convert r from FF_2048 to FF_4096
        char r1oct[FS_2048] = {0};
        octet R1OCT = {0,FS_2048,r1oct};
        FF_2048_toOctet(&R1OCT, r1, FFLEN_2048);

        char roct[FS_4096] = {0};
        octet ROCT = {FS_2048,FS_4096,roct};
        OCT_joctet(&ROCT, &R1OCT);
        FF_4096_fromOctet(r,&ROCT,FFLEN_4096);
    }
    else
    {
        // Convert r from FF_2048 to FF_4096
        char roct[FS_4096] = {0};
        octet ROCT = {FS_2048,FS_4096,roct};
        OCT_joctet(&ROCT, R);
        FF_4096_fromOctet(r,&ROCT,FFLEN_4096);
    }

    FF_4096_zero(pt, FFLEN_4096);
    FF_4096_fromOctet(pt,PT,HFLEN_4096);


    // n2 = n^2
    FF_4096_sqr(n2, n, HFLEN_4096);
    FF_4096_norm(n2, FFLEN_4096);

    // ct = g^pt * r^n mod n2
    FF_4096_bpow2(ct, g, pt, r, n, n2, FFLEN_4096);

    // Output
    FF_4096_toOctet(CT, ct, FFLEN_4096);

    // Output R for Debug
    if (R!=NULL)
    {
        char r2[FS_4096] = {0};
        octet R2 = {0,FS_4096,r2};
        FF_4096_toOctet(&R2, r, FFLEN_4096);
        R->len = FS_2048;
        R2.len = FS_2048;
        OCT_truncate(R,&R2);
    }

#ifdef DEBUG
    printf("n ");
    FF_4096_output(n,FFLEN_4096);
    printf("\n\n");
    printf("g ");
    FF_4096_output(g,FFLEN_4096);
    printf("\n\n");
    printf("n2 ");
    FF_4096_output(n2,FFLEN_4096);
    printf("\n\n");
    printf("r ");
    FF_4096_output(r,FFLEN_4096);
    printf("\n\n");
    printf("pt ");
    FF_4096_output(pt,FFLEN_4096);
    printf("\n\n");
    printf("gpt ");
    FF_4096_output(gpt,FFLEN_4096);
    printf("\n\n");
    printf("rn ");
    FF_4096_output(rn,FFLEN_4096);
    printf("\n\n");
    printf("gpt8 ");
    FF_8192_output(gpt8,FFLEN_8192);
    printf("\n\n");
    printf("rn8 ");
    FF_8192_output(rn8,FFLEN_8192);
    printf("\n\n");
    printf("ct ");
    FF_8192_output(ct,FFLEN_8192);
    printf("\n\n");
    printf("CT2: ");
    OCT_output(&CT2);
    printf("\n");
    printf("CT: ");
    OCT_output(CT);
    printf("\n");
#endif

    return 0;
}

/* Paillier decrypt */
int PAILLIER_DECRYPT(octet* N, octet* L, octet* M, octet* CT, octet* PT)
{
    // Public key
    BIG_512_60 n[FFLEN_4096];

    // secret key
    BIG_512_60 l[FFLEN_4096];
    BIG_512_60 m[FFLEN_4096];

    // Ciphertext
    BIG_512_60 ct[FFLEN_4096];

    // Plaintext
    BIG_512_60 pt[FFLEN_4096];

    // n2 = n^2
    BIG_512_60 n2[FFLEN_4096];

    // ctl = ct^l mod n^2
    BIG_512_60 ctl[FFLEN_4096];

    // ctln = ctl / n
    BIG_512_60 ctln[FFLEN_4096];

    // Convert n from FF_2048 to FF_4096
    char noct[FS_4096] = {0};
    octet NOCT = {FS_2048,FS_4096,noct};
    OCT_joctet(&NOCT, N);
    FF_4096_fromOctet(n,&NOCT,FFLEN_4096);

    // Convert l from FF_2048 to FF_4096
    char loct[FS_4096] = {0};
    octet LOCT = {FS_2048,FS_4096,loct};
    OCT_joctet(&LOCT, L);
    FF_4096_fromOctet(l,&LOCT,FFLEN_4096);

    // Convert m from FF_2048 to FF_4096
    char moct[FS_4096] = {0};
    octet MOCT = {FS_2048,FS_4096,moct};
    OCT_joctet(&MOCT, M);
    FF_4096_fromOctet(m,&MOCT,FFLEN_4096);

    FF_4096_fromOctet(ct,CT,FFLEN_4096);

    // n2 = n^2
    FF_4096_sqr(n2, n, FFLEN_4096);

    // ct^l mod n^2 - 1
    FF_4096_pow(ctl,ct,l,n2,FFLEN_4096);
    FF_4096_dec(ctl,1,FFLEN_4096);

#ifdef DEBUG
    printf("PAILLIER_DECRYPT ctl ");
    FF_4096_output(ctl,FFLEN_4096);
    printf("\n\n");
#endif

    // ctln = ctl / n
    // note that ctln fits into a FF_2048 element,
    // since ctln = ctl/n < n^2 / n = n
    FF_4096_divide(n, ctl, ctln);

    // pt = ctln * m mod n
    // the result fits into a FF_4096 element,
    // since both m and ctln fit into a FF_2048 element
    FF_4096_mul(pt, ctln, m, FFLEN_4096);
#ifdef DEBUG
    printf("pt1 ");
    FF_4096_output(pt,FFLEN_4096);
    printf("\n\n");
#endif
    FF_4096_mod(pt,n,FFLEN_4096);

    // Output. Convert pt from FF_4096 to FF_2046
    char pt2[FS_4096] = {0};
    octet PT2 = {0,FS_4096,pt2};
    FF_4096_toOctet(&PT2, pt, FFLEN_4096);
    PT->len = FS_2048;
    PT2.len = FS_2048;
    OCT_truncate(PT,&PT2);

#ifdef DEBUG
    printf("PAILLIER_DECRYPT n ");
    FF_4096_output(n,FFLEN_4096);
    printf("\n\n");
    printf("PAILLIER_DECRYPT l ");
    FF_4096_output(l,FFLEN_4096);
    printf("\n\n");
    printf("PAILLIER_DECRYPT m ");
    FF_4096_output(m,FFLEN_4096);
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

    return 0;

}

/* Homomorphic addition of plaintexts */
/*  n2 = n * n
    ct = ct1 * ct2
    ct = ct % n2
*/
int PAILLIER_ADD(octet* N, octet* CT1, octet* CT2, octet* CT)
{
    // Public key
    BIG_512_60 n[FFLEN_8192];

    // n2 = n^2
    BIG_512_60 n2[FFLEN_8192];

    // ciphertext
    BIG_512_60 ct1[FFLEN_8192];
    BIG_512_60 ct2[FFLEN_8192];
    BIG_512_60 ct[FFLEN_8192];

    // Convert n from FF_2048 to FF_8192
    char noct[FS_8192] = {0};
    octet NOCT = {FS_2048*3,FS_8192,noct};
    OCT_joctet(&NOCT, N);
    FF_8192_fromOctet(n,&NOCT,FFLEN_8192);

    // Convert ct1 from FF_4096 to FF_8192
    char ct1oct[FS_8192] = {0};
    octet CT1OCT = {FS_4096,FS_8192,ct1oct};
    OCT_joctet(&CT1OCT, CT1);

    FF_8192_fromOctet(ct1,&CT1OCT,FFLEN_8192);

    // Convert ct2 from FF_4096 to FF_8192
    char ct2oct[FS_8192] = {0};
    octet CT2OCT = {FS_4096,FS_8192,ct2oct};
    OCT_joctet(&CT2OCT, CT2);
    FF_8192_fromOctet(ct2,&CT2OCT,FFLEN_8192);

    // n2 = n^2
    FF_8192_sqr(n2, n, HFLEN_8192);

#ifdef DEBUG
    printf("PAILLIER_ADD ct1 ");
    FF_8192_output(ct1,FFLEN_8192);
    printf("\n\n");
    printf("PAILLIER_ADD ct2 ");
    FF_8192_output(ct2,FFLEN_8192);
    printf("\n\n");
#endif

    // ct = ct1 * ct2 mod n^2
    FF_8192_mul(ct,ct1,ct2,FFLEN_8192);

#ifdef DEBUG
    printf("PAILLIER_ADD ct1 * ct2 ");
    FF_8192_output(ct,FFLEN_8192);
    printf("\n\n");
#endif

    FF_8192_mod(ct,n2,FFLEN_8192);

    // Output. Convert ct from FF_8192 to FF_4096
    char cto2[FS_8192] = {0};
    octet CTO2 = {0,FS_8192,cto2};
    FF_8192_toOctet(&CTO2, ct, FFLEN_8192);
    CT->len = FS_4096;
    CTO2.len = FS_4096;
    OCT_truncate(CT,&CTO2);


#ifdef DEBUG
    printf("PAILLIER_ADD n ");
    FF_8192_output(n,FFLEN_8192);
    printf("\n\n");
    printf("PAILLIER_ADD ct1 ");
    FF_8192_output(ct1,FFLEN_8192);
    printf("\n\n");
    printf("PAILLIER_ADD ct2 ");
    FF_8192_output(ct2,FFLEN_8192);
    printf("\n\n");
#endif

    return 0;
}

/* Homomorphic multiplation of plaintext

    ct = ct1 ^ pt mod n^2

*/
int PAILLIER_MULT(octet* N, octet* CT1, octet* PT, octet* CT)
{
    // Public key
    BIG_512_60 n[FFLEN_4096];

    // n^2
    BIG_512_60 n2[FFLEN_4096];

    // Ciphertext
    BIG_512_60 ct1[FFLEN_4096];

    // Plaintext
    BIG_512_60 pt[FFLEN_4096];

    // Ciphertext output. ct = ct1 ^ pt mod n^2
    BIG_512_60 ct[FFLEN_4096];

    // Convert n from FF_2048 to FF_4096
    char noct[FS_4096] = {0};
    octet NOCT = {FS_2048,FS_4096,noct};
    OCT_joctet(&NOCT, N);
    FF_4096_fromOctet(n,&NOCT,FFLEN_4096);

    // Convert pt from FF_2048 to FF_4096
    char ptoct[FS_4096] = {0};
    octet PTOCT = {FS_2048,FS_4096,ptoct};
    OCT_joctet(&PTOCT, PT);
    FF_4096_fromOctet(pt,&PTOCT,FFLEN_4096);

    // n2 = n^2
    FF_4096_sqr(n2, n, FFLEN_4096);
    FF_4096_fromOctet(ct1,CT1,FFLEN_4096);


    // ct1^pt mod n^2
    FF_4096_pow(ct,ct1,pt,n2,FFLEN_4096);

    // output
    FF_4096_toOctet(CT, ct, FFLEN_4096);

#ifdef DEBUG
    printf("PAILLIER_MULT n: ");
    FF_4096_output(n,FFLEN_4096);
    printf("\n\n");
    printf("PAILLIER_MULT n2: ");
    FF_4096_output(n2,FFLEN_4096);
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

    return 0;
}

