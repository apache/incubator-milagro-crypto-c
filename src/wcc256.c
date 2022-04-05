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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "wcc256_ZZZ.h"


/* Perform sha256 of EC Points and Id. Map to an integer modulo the curve order.  */
void WCC_ZZZ_Hq(int sha, octet *A,octet *B,octet *C,octet *D,octet *h)
{
    BIG_XXX q,hs;
    // hv has to store two points in G1, One in G2 and the Id length
    char hv[4000];
    octet HV= {0,sizeof(hv),hv};
    char ht[WCC_PFS_ZZZ];
    octet HT= {0,sizeof(ht),ht};

    BIG_XXX_rcopy(q,CURVE_Order_ZZZ);

#ifdef DEBUG
    printf("WCC_ZZZ_Hq: A: ");
    OCT_output(A);
    printf("\n");
    printf("WCC_ZZZ_Hq: B: ");
    OCT_output(B);
    printf("\n");
    printf("WCC_ZZZ_Hq: C: ");
    OCT_output(C);
    printf("\n");
    printf("WCC_ZZZ_Hq: D: ");
    OCT_output(D);
    printf("\n");
#endif

    OCT_joctet(&HV,A);
    OCT_joctet(&HV,B);
    OCT_joctet(&HV,C);
    OCT_joctet(&HV,D);
    mhashit(sha,0,&HV,&HT);

    BIG_XXX_fromBytes(hs,HT.val);
    BIG_XXX_mod(hs,q);
    OCT_clear(&HT);
    BIG_XXX_toBytes(h->val,hs);
    h->len=WCC_PGS_ZZZ;
}

/*  Calculate a value in G1. VG1 = s*H1(ID) where ID is the identity */
int WCC_ZZZ_GET_G1_MULTIPLE(octet *S,octet *HID,octet *VG1)
{
    BIG_XXX s;
    ECP_ZZZ P;

    ECP_ZZZ_mapit(&P,HID);

    BIG_XXX_fromBytes(s,S->val);
    PAIR_ZZZ_G1mul(&P,s);

    ECP_ZZZ_toOctet(VG1,&P,false);
    return 0;
}

/* Calculate a value in G2. VG2 = s*H2(ID) where ID is the identity */
int WCC_ZZZ_GET_G2_MULTIPLE(octet *S,octet *HID,octet *VG2)
{
    BIG_XXX s;
    ECP8_ZZZ P;

    ECP8_ZZZ_mapit(&P,HID);

    BIG_XXX_fromBytes(s,S->val);
    PAIR_ZZZ_G2mul(&P,s);

    ECP8_ZZZ_toOctet(VG2,&P);
    return 0;
}

/* Calculate the sender AES Key */
int WCC_ZZZ_SENDER_KEY(int sha, octet *xOct, octet *piaOct, octet *pibOct, octet *PbG2Oct, octet *PgG1Oct, octet *AKeyG1Oct, octet *IdBOct, octet *AESKeyOct)
{
    ECP_ZZZ sAG1,PgG1;
    ECP8_ZZZ BG2,PbG2;
    char hv1[WCC_PFS_ZZZ];
    octet HV1= {0,sizeof(hv1),hv1};

    // Pairing outputs
    FP48_YYY g;

    FP16_YYY  c;
    BIG_XXX t,x,z,pia,pib;

    char xpgg1[2*WCC_PFS_ZZZ+1];
    octet xPgG1Oct= {0,sizeof(xpgg1), xpgg1};

    char hv[18*WCC_PFS_ZZZ+1];
    octet HV= {0,sizeof(hv),hv};
    char ht[AESKEY_ZZZ];
    octet HT= {0,sizeof(ht),ht};

    BIG_XXX_fromBytes(x,xOct->val);
    BIG_XXX_fromBytes(pia,piaOct->val);
    BIG_XXX_fromBytes(pib,pibOct->val);

    if (!ECP8_ZZZ_fromOctet(&PbG2,PbG2Oct))
    {
#ifdef DEBUG
        printf("PbG2Oct Invalid Point: ");
        OCT_output(PbG2Oct);
        printf("\n");
#endif
        return WCC_INVALID_POINT;
    }

    if (!ECP_ZZZ_fromOctet(&PgG1,PgG1Oct))
    {
#ifdef DEBUG
        printf("PgG1Oct Invalid Point: ");
        OCT_output(PgG1Oct);
        printf("\n");
#endif
        return WCC_INVALID_POINT;
    }

    mhashit(sha,0,IdBOct,&HV1);
    ECP8_ZZZ_mapit(&BG2,&HV1);

    if (!ECP_ZZZ_fromOctet(&sAG1,AKeyG1Oct))
    {
#ifdef DEBUG
        printf("AKeyG1Oct Invalid Point: ");
        OCT_output(AKeyG1Oct);
        printf("\n");
#endif
        return WCC_INVALID_POINT;
    }

    // z =  x + pia
    BIG_XXX_add(z,x,pia);
    BIG_XXX_norm(z);

    // (x+pia).AKeyG1
    PAIR_ZZZ_G1mul(&sAG1,z);

    // pib.BG2
    PAIR_ZZZ_G2mul(&BG2,pib);

    // pib.BG2+PbG2
    ECP8_ZZZ_add(&BG2, &PbG2);

    ECP8_ZZZ_affine(&BG2);
    ECP_ZZZ_affine(&sAG1);

    PAIR_ZZZ_ate(&g,&BG2,&sAG1);
    PAIR_ZZZ_fexp(&g);

    // x.PgG1
    PAIR_ZZZ_G1mul(&PgG1,x);
    ECP_ZZZ_toOctet(&xPgG1Oct,&PgG1,false);

    // Generate AES Key : K=H(k,x.PgG1)
    FP48_YYY_trace(&c,&g);

    HV.len = 16*WCC_PFS_ZZZ;
    FP_YYY_redc(t,&(c.a.a.a.a));
    BIG_XXX_toBytes(&(HV.val[0]),t);

    FP_YYY_redc(t,&(c.a.a.a.b));
    BIG_XXX_toBytes(&(HV.val[WCC_PFS_ZZZ]),t);

    FP_YYY_redc(t,&(c.a.a.b.a));
    BIG_XXX_toBytes(&(HV.val[WCC_PFS_ZZZ*2]),t);

    FP_YYY_redc(t,&(c.a.a.b.b));
    BIG_XXX_toBytes(&(HV.val[WCC_PFS_ZZZ*3]),t);

    FP_YYY_redc(t,&(c.a.b.a.a));
    BIG_XXX_toBytes(&(HV.val[WCC_PFS_ZZZ*4]),t);

    FP_YYY_redc(t,&(c.a.b.a.b));
    BIG_XXX_toBytes(&(HV.val[WCC_PFS_ZZZ*5]),t);

    FP_YYY_redc(t,&(c.a.b.b.a));
    BIG_XXX_toBytes(&(HV.val[WCC_PFS_ZZZ*6]),t);

    FP_YYY_redc(t,&(c.a.b.b.b));
    BIG_XXX_toBytes(&(HV.val[WCC_PFS_ZZZ*7]),t);

    FP_YYY_redc(t,&(c.b.a.a.a));
    BIG_XXX_toBytes(&(HV.val[WCC_PFS_ZZZ*8]),t);

    FP_YYY_redc(t,&(c.b.a.a.b));
    BIG_XXX_toBytes(&(HV.val[WCC_PFS_ZZZ*9]),t);

    FP_YYY_redc(t,&(c.b.a.b.a));
    BIG_XXX_toBytes(&(HV.val[WCC_PFS_ZZZ*10]),t);

    FP_YYY_redc(t,&(c.b.a.b.b));
    BIG_XXX_toBytes(&(HV.val[WCC_PFS_ZZZ*11]),t);

    FP_YYY_redc(t,&(c.b.b.a.a));
    BIG_XXX_toBytes(&(HV.val[WCC_PFS_ZZZ*12]),t);

    FP_YYY_redc(t,&(c.b.b.a.b));
    BIG_XXX_toBytes(&(HV.val[WCC_PFS_ZZZ*13]),t);

    FP_YYY_redc(t,&(c.b.b.b.a));
    BIG_XXX_toBytes(&(HV.val[WCC_PFS_ZZZ*14]),t);

    FP_YYY_redc(t,&(c.b.b.b.b));
    BIG_XXX_toBytes(&(HV.val[WCC_PFS_ZZZ*15]),t);

    // Set HV.len to correct value
    OCT_joctet(&HV,&xPgG1Oct);

    mhashit(sha,0,&HV,&HT);

    OCT_empty(AESKeyOct);
    OCT_jbytes(AESKeyOct,HT.val,AESKEY_ZZZ);

    return 0;
}

/* Calculate the receiver AES key */
int WCC_ZZZ_RECEIVER_KEY(int sha, octet *yOct, octet *wOct,  octet *piaOct, octet *pibOct,  octet *PaG1Oct, octet *PgG1Oct, octet *BKeyG2Oct, octet *IdAOct, octet *AESKeyOct)
{
    ECP_ZZZ AG1,PgG1,PaG1;
    ECP8_ZZZ sBG2;
    char hv1[WCC_PFS_ZZZ];
    octet HV1= {0,sizeof(hv1),hv1};

    // Pairing outputs
    FP48_YYY g;

    FP16_YYY  c;
    BIG_XXX t,w,y,pia,pib;;

    char wpag1[2*WCC_PFS_ZZZ+1];
    octet wPaG1Oct= {0,sizeof(wpag1), wpag1};

    char hv[18*WCC_PFS_ZZZ+1];
    octet HV= {0,sizeof(hv),hv};
    char ht[AESKEY_ZZZ];
    octet HT= {0,sizeof(ht),ht};

    BIG_XXX_fromBytes(y,yOct->val);
    BIG_XXX_fromBytes(w,wOct->val);
    BIG_XXX_fromBytes(pia,piaOct->val);
    BIG_XXX_fromBytes(pib,pibOct->val);

    if (!ECP_ZZZ_fromOctet(&PaG1,PaG1Oct))
        return WCC_INVALID_POINT;

    if (!ECP_ZZZ_fromOctet(&PgG1,PgG1Oct))
        return WCC_INVALID_POINT;

    mhashit(sha,0,IdAOct,&HV1);
    ECP_ZZZ_mapit(&AG1,&HV1);

    if (!ECP8_ZZZ_fromOctet(&sBG2,BKeyG2Oct))
        return WCC_INVALID_POINT;

    // y =  y + pib
    BIG_XXX_add(y,y,pib);
    BIG_XXX_norm(y);

    // (y+pib).BKeyG2
    PAIR_ZZZ_G2mul(&sBG2,y);

    // pia.AG1
    PAIR_ZZZ_G1mul(&AG1,pia);

    // pia.AG1+PaG1
    ECP_ZZZ_add(&AG1, &PaG1);

    ECP8_ZZZ_affine(&sBG2);
    ECP_ZZZ_affine(&AG1);

    PAIR_ZZZ_ate(&g,&sBG2,&AG1);
    PAIR_ZZZ_fexp(&g);

    // w.PaG1
    PAIR_ZZZ_G1mul(&PaG1,w);
    ECP_ZZZ_toOctet(&wPaG1Oct,&PaG1,false);

    // Generate AES Key: K=H(k,w.PaG1)
    FP48_YYY_trace(&c,&g);

    HV.len = 16*WCC_PFS_ZZZ;
    FP_YYY_redc(t,&(c.a.a.a.a));
    BIG_XXX_toBytes(&(HV.val[0]),t);

    FP_YYY_redc(t,&(c.a.a.a.b));
    BIG_XXX_toBytes(&(HV.val[WCC_PFS_ZZZ]),t);

    FP_YYY_redc(t,&(c.a.a.b.a));
    BIG_XXX_toBytes(&(HV.val[WCC_PFS_ZZZ*2]),t);

    FP_YYY_redc(t,&(c.a.a.b.b));
    BIG_XXX_toBytes(&(HV.val[WCC_PFS_ZZZ*3]),t);

    FP_YYY_redc(t,&(c.a.b.a.a));
    BIG_XXX_toBytes(&(HV.val[WCC_PFS_ZZZ*4]),t);

    FP_YYY_redc(t,&(c.a.b.a.b));
    BIG_XXX_toBytes(&(HV.val[WCC_PFS_ZZZ*5]),t);

    FP_YYY_redc(t,&(c.a.b.b.a));
    BIG_XXX_toBytes(&(HV.val[WCC_PFS_ZZZ*6]),t);

    FP_YYY_redc(t,&(c.a.b.b.b));
    BIG_XXX_toBytes(&(HV.val[WCC_PFS_ZZZ*7]),t);

    FP_YYY_redc(t,&(c.b.a.a.a));
    BIG_XXX_toBytes(&(HV.val[WCC_PFS_ZZZ*8]),t);

    FP_YYY_redc(t,&(c.b.a.a.b));
    BIG_XXX_toBytes(&(HV.val[WCC_PFS_ZZZ*9]),t);

    FP_YYY_redc(t,&(c.b.a.b.a));
    BIG_XXX_toBytes(&(HV.val[WCC_PFS_ZZZ*10]),t);

    FP_YYY_redc(t,&(c.b.a.b.b));
    BIG_XXX_toBytes(&(HV.val[WCC_PFS_ZZZ*11]),t);

    FP_YYY_redc(t,&(c.b.b.a.a));
    BIG_XXX_toBytes(&(HV.val[WCC_PFS_ZZZ*12]),t);

    FP_YYY_redc(t,&(c.b.b.a.b));
    BIG_XXX_toBytes(&(HV.val[WCC_PFS_ZZZ*13]),t);

    FP_YYY_redc(t,&(c.b.b.b.a));
    BIG_XXX_toBytes(&(HV.val[WCC_PFS_ZZZ*14]),t);

    FP_YYY_redc(t,&(c.b.b.b.b));
    BIG_XXX_toBytes(&(HV.val[WCC_PFS_ZZZ*15]),t);

    // Set HV.len to correct value
    OCT_joctet(&HV,&wPaG1Oct);

    mhashit(sha,0,&HV,&HT);

    OCT_empty(AESKeyOct);
    OCT_jbytes(AESKeyOct,HT.val,AESKEY_ZZZ);

    return 0;

}

/* Generate a random number modulus the group order */
int WCC_ZZZ_RANDOM_GENERATE(csprng *RNG,octet* S)
{
    BIG_XXX r,s;
    BIG_XXX_rcopy(r,CURVE_Order_ZZZ);
    BIG_XXX_randomnum(s,r,RNG);
    BIG_XXX_toBytes(S->val,s);
    S->len=WCC_PGS_ZZZ;
    return 0;
}

/* Add two members from the group G1 */
int WCC_ZZZ_RECOMBINE_G1(octet *R1,octet *R2,octet *R)
{
    ECP_ZZZ P,T;
    int res=0;
    if (!ECP_ZZZ_fromOctet(&P,R1)) res=WCC_INVALID_POINT;
    if (!ECP_ZZZ_fromOctet(&T,R2)) res=WCC_INVALID_POINT;
    if (res==0)
    {
        ECP_ZZZ_add(&P,&T);
        ECP_ZZZ_toOctet(R,&P,false);
    }
    return res;
}

/* Add two members from the group G2 */
int WCC_ZZZ_RECOMBINE_G2(octet *W1,octet *W2,octet *W)
{
    ECP8_ZZZ Q,T;
    int res=0;
    if (!ECP8_ZZZ_fromOctet(&Q,W1)) res=WCC_INVALID_POINT;
    if (!ECP8_ZZZ_fromOctet(&T,W2)) res=WCC_INVALID_POINT;
    if (res==0)
    {
        ECP8_ZZZ_add(&Q,&T);
        ECP8_ZZZ_toOctet(W,&Q);
    }
    return res;
}
