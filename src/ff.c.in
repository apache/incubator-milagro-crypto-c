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

/* AMCL basic functions for Large Finite Field support */

#include "ff_WWW.h"

// Constant time comparison of two 32 bit signed integers.
#define ct_equals(a,b) (int)((((a)^(b))-1)>>31&1)

/* x=y */
void FF_WWW_copy(BIG_XXX x[],BIG_XXX y[],int n)
{
    int i;
    for (i=0; i<n; i++)
        BIG_XXX_copy(x[i],y[i]);
}

/* x=y<<n */
static void FF_WWW_dsucopy(BIG_XXX x[],BIG_XXX y[],int n)
{
    int i;
    for (i=0; i<n; i++)
    {
        BIG_XXX_copy(x[n+i],y[i]);
        BIG_XXX_zero(x[i]);
    }
}

/* x=y */
static void FF_WWW_dscopy(BIG_XXX x[],BIG_XXX y[],int n)
{
    int i;
    for (i=0; i<n; i++)
    {
        BIG_XXX_copy(x[i],y[i]);
        BIG_XXX_zero(x[n+i]);
    }
}

/* x=y>>n */
static void FF_WWW_sducopy(BIG_XXX x[],BIG_XXX y[],int n)
{
    int i;
    for (i=0; i<n; i++)
        BIG_XXX_copy(x[i],y[n+i]);
}

/* set to zero */
void FF_WWW_zero(BIG_XXX x[],int n)
{
    int i;
    for (i=0; i<n; i++)
        BIG_XXX_zero(x[i]);
}

/* test equals 0 */
int FF_WWW_iszilch(BIG_XXX x[],int n)
{
    int i;
    int rc = 1;

    for (i=0; i<n; i++)
        rc &= BIG_XXX_iszilch(x[i]);

    return rc;
}

/* test equals 1 */
int FF_WWW_isunity(BIG_XXX x[], int n)
{
    int i;
    int rc;

    rc = BIG_XXX_isunity(x[0]);

    for (i=1; i<n; i++)
        rc &= BIG_XXX_iszilch(x[i]);

    return rc;
}

/* shift right by BIGBITS-bit words */
static void FF_WWW_shrw(BIG_XXX a[],int n)
{
    int i;
    for (i=0; i<n; i++)
    {
        BIG_XXX_copy(a[i],a[i+n]);
        BIG_XXX_zero(a[i+n]);
    }
}

/* shift left by BIGBITS-bit words */
static void FF_WWW_shlw(BIG_XXX a[],int n)
{
    int i;
    for (i=0; i<n; i++)
    {
        BIG_XXX_copy(a[i+n],a[i]);
        BIG_XXX_zero(a[i]);
    }
}

/* extract last bit */
int FF_WWW_parity(BIG_XXX x[])
{
    return BIG_XXX_parity(x[0]);
}

/* extract last m bits */
int FF_WWW_lastbits(BIG_XXX x[],int m)
{
    return BIG_XXX_lastbits(x[0],m);
}

/* x=1 */
void FF_WWW_one(BIG_XXX x[],int n)
{
    int i;
    BIG_XXX_one(x[0]);
    for (i=1; i<n; i++)
        BIG_XXX_zero(x[i]);
}

/* x=m, where m is 32-bit int */
void FF_WWW_init(BIG_XXX x[],sign32 m,int n)
{
    int i;
    BIG_XXX_zero(x[0]);
#if CHUNK<64
    x[0][0]=(chunk)(m&BMASK_XXX);
    x[0][1]=(chunk)(m>>BASEBITS_XXX);
#else
    x[0][0]=(chunk)m;
#endif
    for (i=1; i<n; i++)
        BIG_XXX_zero(x[i]);
}

/* compare x and y - must be normalised */
int FF_WWW_comp(BIG_XXX x[],BIG_XXX y[],int n)
{
    int i;
    int c;
    int eq = 1;
    int gt = 0;

    for (i=n-1; i>=0; i--)
    {
        c = BIG_XXX_comp(x[i],y[i]);
        gt += eq * (c * c + c);
        eq *= 1 - c * c;
    }

    return gt + eq - 1;
}

/* recursive add */
static void FF_WWW_radd(BIG_XXX z[],int zp,BIG_XXX x[],int xp,BIG_XXX y[],int yp,int n)
{
    int i;
    for (i=0; i<n; i++)
        BIG_XXX_add(z[zp+i],x[xp+i],y[yp+i]);
}

/* recursive inc */
static void FF_WWW_rinc(BIG_XXX z[],int zp,BIG_XXX y[],int yp,int n)
{
    int i;
    for (i=0; i<n; i++)
        BIG_XXX_add(z[zp+i],z[zp+i],y[yp+i]);
}

/* recursive dec */
static void FF_WWW_rdec(BIG_XXX z[],int zp,BIG_XXX y[],int yp,int n)
{
    int i;
    for (i=0; i<n; i++)
        BIG_XXX_sub(z[zp+i],z[zp+i],y[yp+i]);
}

/* simple add */
void FF_WWW_add(BIG_XXX z[],BIG_XXX x[],BIG_XXX y[],int n)
{
    int i;
    for (i=0; i<n; i++)
        BIG_XXX_add(z[i],x[i],y[i]);
}

/* simple sub */
void FF_WWW_sub(BIG_XXX z[],BIG_XXX x[],BIG_XXX y[],int n)
{
    int i;
    for (i=0; i<n; i++)
        BIG_XXX_sub(z[i],x[i],y[i]);
}

/* increment/decrement by a small integer */
void FF_WWW_inc(BIG_XXX x[],int m,int n)
{
    BIG_XXX_inc(x[0],m);
    FF_WWW_norm(x,n);
}

void FF_WWW_dec(BIG_XXX x[],int m,int n)
{
    BIG_XXX_dec(x[0],m);
    FF_WWW_norm(x,n);
}

/* normalise - but hold any overflow in top part unless n<0 */
static void FF_WWW_rnorm(BIG_XXX z[],int zp,int n)
{
    int i,trunc=0;
    chunk carry;
    if (n<0)
    {
        /* -v n signals to do truncation */
        n=-n;
        trunc=1;
    }
    for (i=0; i<n-1; i++)
    {
        carry=BIG_XXX_norm(z[zp+i]);

        z[zp+i][NLEN_XXX-1]^=carry<<P_TBITS_WWW; /* remove it */
        z[zp+i+1][0]+=carry;
    }
    carry=BIG_XXX_norm(z[zp+n-1]);
    if (trunc) z[zp+n-1][NLEN_XXX-1]^=carry<<P_TBITS_WWW;
}

void FF_WWW_norm(BIG_XXX z[],int n)
{
    FF_WWW_rnorm(z,0,n);
}

/* shift left by one bit */
void FF_WWW_shl(BIG_XXX x[],int n)
{
    int i;
    int carry,delay_carry=0;
    for (i=0; i<n-1; i++)
    {
        carry=BIG_XXX_fshl(x[i],1);
        x[i][0]|=delay_carry;
        x[i][NLEN_XXX-1]^=(chunk)carry<<P_TBITS_WWW;
        delay_carry=carry;
    }
    BIG_XXX_fshl(x[n-1],1);
    x[n-1][0]|=delay_carry;
}

/* shift right by one bit */
void FF_WWW_shr(BIG_XXX x[],int n)
{
    int i;
    int carry;
    for (i=n-1; i>0; i--)
    {
        carry=BIG_XXX_fshr(x[i],1);
        x[i-1][NLEN_XXX-1]|=(chunk)carry<<P_TBITS_WWW;
    }
    BIG_XXX_fshr(x[0],1);
}

void FF_WWW_output(BIG_XXX x[],int n)
{
    int i;
    FF_WWW_norm(x,n);
    for (i=n-1; i>=0; i--)
    {
        BIG_XXX_output(x[i]);
        printf(" ");
    }
}

void FF_WWW_rawoutput(BIG_XXX x[],int n)
{
    int i;
    for (i=n-1; i>=0; i--)
    {
        BIG_XXX_rawoutput(x[i]);
        printf(" ");
    }
}

/* Convert FFs to/from octet strings */
void FF_WWW_toOctet(octet *w,BIG_XXX x[],int n)
{
    int i;
    w->len=n*MODBYTES_XXX;
    for (i=0; i<n; i++)
    {
        BIG_XXX_toBytes(&(w->val[(n-i-1)*MODBYTES_XXX]),x[i]);
    }
}

void FF_WWW_fromOctet(BIG_XXX x[],octet *w,int n)
{
    int i;
    for (i=0; i<n; i++)
    {
        BIG_XXX_fromBytes(x[i],&(w->val[(n-i-1)*MODBYTES_XXX]));
    }
}

/* in-place swapping using xor - side channel resistant */
static void FF_WWW_cswap(BIG_XXX a[],BIG_XXX b[],int d,int n)
{
    int i;
    for (i=0; i<n; i++)
        BIG_XXX_cswap(a[i],b[i],d);
    return;
}

/* copy b to a - side channel resistant */
static void FF_WWW_cmove(BIG_XXX a[],BIG_XXX b[],int d,int n)
{
    int i;
    for (i=0; i<n; i++)
        BIG_XXX_cmove(a[i],b[i],d);
    return;
}

/* z=x*y, t is workspace */
static void FF_WWW_karmul(BIG_XXX z[],int zp,BIG_XXX x[],int xp,BIG_XXX y[],int yp,BIG_XXX t[],int tp,int n)
{
    int nd2;
    if (n==1)
    {
        BIG_XXX_norm(x[xp]);
        BIG_XXX_norm(y[yp]);
        BIG_XXX_mul(t[tp],x[xp],y[yp]);
        BIG_XXX_split(z[zp+1],z[zp],t[tp],BIGBITS_XXX);
        return;
    }

    nd2=n/2;
    FF_WWW_radd(z,zp,x,xp,x,xp+nd2,nd2);
    FF_WWW_rnorm(z,zp,nd2);  /* needs this if recursion level too deep */

    FF_WWW_radd(z,zp+nd2,y,yp,y,yp+nd2,nd2);
    FF_WWW_rnorm(z,zp+nd2,nd2);
    FF_WWW_karmul(t,tp,z,zp,z,zp+nd2,t,tp+n,nd2);
    FF_WWW_karmul(z,zp,x,xp,y,yp,t,tp+n,nd2);
    FF_WWW_karmul(z,zp+n,x,xp+nd2,y,yp+nd2,t,tp+n,nd2);
    FF_WWW_rdec(t,tp,z,zp,n);
    FF_WWW_rdec(t,tp,z,zp+n,n);
    FF_WWW_rinc(z,zp+nd2,t,tp,n);
    FF_WWW_rnorm(z,zp,2*n);
}

static void FF_WWW_karsqr(BIG_XXX z[],int zp,BIG_XXX x[],int xp,BIG_XXX t[],int tp,int n)
{
    int nd2;
    if (n==1)
    {
        BIG_XXX_norm(x[xp]);
        BIG_XXX_sqr(t[tp],x[xp]);
        BIG_XXX_split(z[zp+1],z[zp],t[tp],BIGBITS_XXX);
        return;
    }
    nd2=n/2;
    FF_WWW_karsqr(z,zp,x,xp,t,tp+n,nd2);
    FF_WWW_karsqr(z,zp+n,x,xp+nd2,t,tp+n,nd2);
    FF_WWW_karmul(t,tp,x,xp,x,xp+nd2,t,tp+n,nd2);
    FF_WWW_rinc(z,zp+nd2,t,tp,n);
    FF_WWW_rinc(z,zp+nd2,t,tp,n);

    FF_WWW_rnorm(z,zp+nd2,n);  /* was FF_rnorm(z,zp,2*n)  */
}

static void FF_WWW_karmul_lower(BIG_XXX z[],int zp,BIG_XXX x[],int xp,BIG_XXX y[],int yp,BIG_XXX t[],int tp,int n)
{
    /* Calculates Least Significant bottom half of x*y */
    int nd2;
    if (n==1)
    {
        /* only calculate bottom half of product */
        BIG_XXX_norm(x[xp]);
        BIG_XXX_norm(y[yp]);
        BIG_XXX_smul(z[zp],x[xp],y[yp]);
        return;
    }
    nd2=n/2;
    FF_WWW_karmul(z,zp,x,xp,y,yp,t,tp+n,nd2);
    FF_WWW_karmul_lower(t,tp,x,xp+nd2,y,yp,t,tp+n,nd2);
    FF_WWW_rinc(z,zp+nd2,t,tp,nd2);
    FF_WWW_karmul_lower(t,tp,x,xp,y,yp+nd2,t,tp+n,nd2);
    FF_WWW_rinc(z,zp+nd2,t,tp,nd2);
    FF_WWW_rnorm(z,zp+nd2,-nd2);  /* truncate it */
}

static void FF_WWW_karmul_upper(BIG_XXX z[],BIG_XXX x[],BIG_XXX y[],BIG_XXX t[],int n)
{
    /* Calculates Most Significant upper half of x*y, given lower part */
    int nd2;

    nd2=n/2;
    FF_WWW_radd(z,n,x,0,x,nd2,nd2);
    FF_WWW_radd(z,n+nd2,y,0,y,nd2,nd2);
    FF_WWW_rnorm(z,n,nd2);
    FF_WWW_rnorm(z,n+nd2,nd2);

    FF_WWW_karmul(t,0,z,n+nd2,z,n,t,n,nd2);  /* t = (a0+a1)(b0+b1) */
    FF_WWW_karmul(z,n,x,nd2,y,nd2,t,n,nd2); /* z[n]= a1*b1 */
    /* z[0-nd2]=l(a0b0) z[nd2-n]= h(a0b0)+l(t)-l(a0b0)-l(a1b1) */
    FF_WWW_rdec(t,0,z,n,n);              /* t=t-a1b1  */
    FF_WWW_rinc(z,nd2,z,0,nd2);   /* z[nd2-n]+=l(a0b0) = h(a0b0)+l(t)-l(a1b1)  */
    FF_WWW_rdec(z,nd2,t,0,nd2);   /* z[nd2-n]=h(a0b0)+l(t)-l(a1b1)-l(t-a1b1)=h(a0b0) */
    FF_WWW_rnorm(z,0,-n);					/* a0b0 now in z - truncate it */
    FF_WWW_rdec(t,0,z,0,n);         /* (a0+a1)(b0+b1) - a0b0 */
    FF_WWW_rinc(z,nd2,t,0,n);

    FF_WWW_rnorm(z,nd2,n);
}

/* z=x*y */
void FF_WWW_mul(BIG_XXX z[],BIG_XXX x[],BIG_XXX y[],int n)
{
#ifndef C99
    BIG_XXX t[2*FFLEN_WWW];
#else
    BIG_XXX t[2*n];
#endif
    FF_WWW_karmul(z,0,x,0,y,0,t,0,n);
}

/* return low part of product */
static void FF_WWW_lmul(BIG_XXX z[],BIG_XXX x[],BIG_XXX y[],int n)
{
#ifndef C99
    BIG_XXX t[2*FFLEN_WWW];
#else
    BIG_XXX t[2*n];
#endif
    FF_WWW_karmul_lower(z,0,x,0,y,0,t,0,n);
}

/* Set b=b mod c */
void FF_WWW_mod(BIG_XXX b[],BIG_XXX c[],int n)
{
    int k=0;

#ifndef C99
    BIG_XXX r[FFLEN_WWW];
#else
    BIG_XXX r[n];
#endif

    FF_WWW_norm(b,n);
    if (FF_WWW_comp(b,c,n)<0)
        return;
    do
    {
        FF_WWW_shl(c,n);
        k++;
    }
    while (FF_WWW_comp(b,c,n)>=0);

    while (k>0)
    {
        FF_WWW_shr(c,n);
        FF_WWW_sub(r,b,c,n);
        FF_WWW_norm(r,n);
        FF_WWW_cmove(b,r,FF_WWW_comp(b,c,n)>=0,n);
        k--;
    }
}

/* z=x^2 */
void FF_WWW_sqr(BIG_XXX z[],BIG_XXX x[],int n)
{
#ifndef C99
    BIG_XXX t[2*FFLEN_WWW];
#else
    BIG_XXX t[2*n];
#endif
    FF_WWW_karsqr(z,0,x,0,t,0,n);
}

/* r=t mod modulus, N is modulus, ND is Montgomery Constant */
static void FF_WWW_reduce(BIG_XXX r[],BIG_XXX T[],BIG_XXX N[],BIG_XXX ND[],int n)
{
    /* fast karatsuba Montgomery reduction */
#ifndef C99
    BIG_XXX t[2*FFLEN_WWW];
    BIG_XXX m[FFLEN_WWW];
#else
    BIG_XXX t[2*n];
    BIG_XXX m[n];
#endif
    FF_WWW_sducopy(r,T,n);  /* keep top half of T */
    FF_WWW_karmul_lower(m,0,T,0,ND,0,t,0,n);  /* m=T.(1/N) mod R */

    FF_WWW_karmul_upper(T,N,m,t,n);  /* T=mN */
    FF_WWW_sducopy(m,T,n);

    FF_WWW_add(r,r,N,n);
    FF_WWW_sub(r,r,m,n);
    FF_WWW_norm(r,n);
}


/* Set r=a mod b */
/* a is of length - 2*n */
/* r,b is of length - n */
void FF_WWW_dmod(BIG_XXX r[],BIG_XXX a[],BIG_XXX b[],int n)
{
    int k;
#ifndef C99
    BIG_XXX s[2*FFLEN_WWW];
    BIG_XXX m[2*FFLEN_WWW];
    BIG_XXX x[2*FFLEN_WWW];
#else
    BIG_XXX s[2*n];
    BIG_XXX m[2*n];
    BIG_XXX x[2*n];
#endif
    FF_WWW_copy(x,a,2*n);
    FF_WWW_norm(x,2*n);
    FF_WWW_dsucopy(m,b,n);
    k=BIGBITS_XXX*n;

    while (FF_WWW_comp(x,m,2*n)>=0)
    {
        FF_WWW_sub(x,x,m,2*n);
        FF_WWW_norm(x,2*n);
    }

    while (k>0)
    {
        FF_WWW_shr(m,2*n);
        FF_WWW_sub(s,x,m,2*n);
        FF_WWW_norm(s,2*n);
        FF_WWW_cmove(x,s,FF_WWW_comp(x,m,2*n)>=0,2*n);
        k--;
    }
    FF_WWW_copy(r,x,n);
    FF_WWW_mod(r,b,n);
}

/* Set r=1/a mod p. Kaliski method - a<p on entry */
void FF_WWW_invmodp(BIG_XXX r[],BIG_XXX a[],BIG_XXX p[],int n)
{
#ifndef C99
    BIG_XXX u[FFLEN_WWW],v[FFLEN_WWW],s[FFLEN_WWW],w[FFLEN_WWW];
#else
    BIG_XXX u[n],v[n],s[n],w[n];
#endif

    int k, p1, pu, pv, psw, pmv;

    FF_WWW_copy(u, p, n);
    FF_WWW_copy(v, a, n);
    FF_WWW_mod(v, p, n);
    FF_WWW_zero(r, n);
    FF_WWW_one(s, n);

    // v = a2^(n*BIGBITS_XXX) mod p
    for(k = 0; k < n*BIGBITS_XXX; k++)
    {
        FF_WWW_sub(w, v, p, n);
        FF_WWW_norm(w, n);
        FF_WWW_cmove(v, w, (FF_WWW_comp(v, p, n) > 0), n);
        FF_WWW_shl(v, n);
    }

    // CT Kaliski almost inverse
    // The correction step is included
    for (k = 0; k < 2*n*BIGBITS_XXX; k++)
    {
        p1 = !FF_WWW_iszilch(v, n);

        pu = FF_WWW_parity(u);
        pv = FF_WWW_parity(v);
        // Cases 2-4 of Kaliski
        psw = p1 & ((!pu) | (pv & (FF_WWW_comp(u, v, n)>0)));
        // Cases 3-4 of Kaliski
        pmv = p1 & pu & pv;

        // Swap for cases 2-4 of Kaliski
        FF_WWW_cswap(u, v, psw, n);
        FF_WWW_cswap(r, s, psw, n);

        // Addition and subtraction for cases 3-4 of Kaliski
        FF_WWW_sub(w, v, u, n);
        FF_WWW_norm(w, n);
        FF_WWW_cmove(v, w, pmv, n);

        FF_WWW_add(w, r, s, n);
        FF_WWW_norm(w, n);
        FF_WWW_cmove(s, w, pmv, n);

        // Subtraction for correction step
        FF_WWW_sub(w, r, p, n);
        FF_WWW_norm(w, n);
        FF_WWW_cmove(r, w, (!p1) & (FF_WWW_comp(r, p, n)>0), n);

        // Shifts for all Kaliski cases and correction step
        FF_WWW_shl(r, n);
        FF_WWW_shr(v, n);

        // Restore u,v,r,s to the original position
        FF_WWW_cswap(u, v, psw, n);
        FF_WWW_cswap(r, s, psw, n);
    }

    // Last step of Kaliski
    // Moved after the correction step
    FF_WWW_sub(w, r, p, n);
    FF_WWW_norm(w, n);
    FF_WWW_cmove(r, w, (FF_WWW_comp(r, p, n)>0), n);

    FF_WWW_sub(r, p, r, n);
    FF_WWW_norm(r, n);

    // Restore inverse from Montgomery form
    for (k = 0; k < n*BIGBITS_XXX; k++)
    {
        FF_WWW_add(w, r, p, n);
        FF_WWW_norm(w, n);
        FF_WWW_cmove(r, w, FF_WWW_parity(r), n);
        FF_WWW_shr(r, n);
    }
}

/* nesidue mod m */
static void FF_WWW_nres(BIG_XXX a[],BIG_XXX m[],int n)
{
#ifndef C99
    BIG_XXX d[2*FFLEN_WWW];
#else
    BIG_XXX d[2*n];
#endif
    if (n==1)
    {
        BIG_XXX_dscopy(d[0],a[0]);
        BIG_XXX_dshl(d[0],NLEN_XXX*BASEBITS_XXX);
        BIG_XXX_dmod(a[0],d[0],m[0]);
    }
    else
    {
        FF_WWW_dsucopy(d,a,n);
        FF_WWW_dmod(a,d,m,n);
    }
}

static void FF_WWW_redc(BIG_XXX a[],BIG_XXX m[],BIG_XXX ND[],int n)
{
#ifndef C99
    BIG_XXX d[2*FFLEN_WWW];
#else
    BIG_XXX d[2*n];
#endif
    if (n==1)
    {
        BIG_XXX_dzero(d[0]);
        BIG_XXX_dscopy(d[0],a[0]);
        BIG_XXX_monty(a[0],m[0],((chunk)1<<BASEBITS_XXX)-ND[0][0],d[0]);
    }
    else
    {
        FF_WWW_mod(a,m,n);
        FF_WWW_dscopy(d,a,n);
        FF_WWW_reduce(a,d,m,ND,n);
        FF_WWW_mod(a,m,n);
    }
}

/* U=1/a mod 2^m - Arazi & Qi */
void FF_WWW_invmod2m(BIG_XXX U[],BIG_XXX a[],int n)
{
    int i;
#ifndef C99
    BIG_XXX t1[FFLEN_WWW],b[FFLEN_WWW],c[FFLEN_WWW];
#else
    BIG_XXX t1[2*n],b[n],c[n];
#endif

    FF_WWW_zero(U,n);
    FF_WWW_zero(b,n);
    FF_WWW_zero(c,n);
    FF_WWW_zero(t1,2*n);

    BIG_XXX_copy(U[0],a[0]);
    BIG_XXX_invmod2m(U[0]);
    for (i=1; i<n; i<<=1)
    {
        FF_WWW_copy(b,a,i);
        FF_WWW_mul(t1,U,b,i);
        FF_WWW_shrw(t1,i); // top half to bottom half, top half=0

        FF_WWW_copy(c,a,2*i);
        FF_WWW_shrw(c,i); // top half of c
        FF_WWW_lmul(b,U,c,i); // should set top half of b=0
        FF_WWW_add(t1,t1,b,i);
        FF_WWW_norm(t1,2*i);
        FF_WWW_lmul(b,t1,U,i);
        FF_WWW_copy(t1,b,i);
        FF_WWW_one(b,i);
        FF_WWW_shlw(b,i);
        FF_WWW_sub(t1,b,t1,2*i);
        FF_WWW_norm(t1,2*i);
        FF_WWW_shlw(t1,i);
        FF_WWW_add(U,U,t1,2*i);
    }

    FF_WWW_norm(U,n);
}

void FF_WWW_random(BIG_XXX x[],csprng *rng,int n)
{
    int i;
    for (i=0; i<n; i++)
    {
        BIG_XXX_random(x[i],rng);
    }
    /* make sure top bit is 1 */
    while (BIG_XXX_nbits(x[n-1])<MODBYTES_XXX*8) BIG_XXX_random(x[n-1],rng);
}

/* generate random x mod p */
void FF_WWW_randomnum(BIG_XXX x[],BIG_XXX p[],csprng *rng,int n)
{
    int i;
#ifndef C99
    BIG_XXX d[2*FFLEN_WWW];
#else
    BIG_XXX d[2*n];
#endif
    for (i=0; i<2*n; i++)
    {
        BIG_XXX_random(d[i],rng);
    }
    FF_WWW_dmod(x,d,p,n);
}

static void FF_WWW_modmul(BIG_XXX z[],BIG_XXX x[],BIG_XXX y[],BIG_XXX p[],BIG_XXX ND[],int n)
{
#ifndef C99
    BIG_XXX d[2*FFLEN_WWW];
#else
    BIG_XXX d[2*n];
#endif
    chunk ex=P_EXCESS_WWW(x[n-1]);
    chunk ey=P_EXCESS_WWW(y[n-1]);
#ifdef dchunk
    if ((dchunk)(ex+1)*(ey+1)>(dchunk)P_FEXCESS_WWW)
#else
    if ((ex+1)>P_FEXCESS_WWW/(ey+1))
#endif
    {
#ifdef DEBUG_REDUCE
        printf("Product too large - reducing it %d %d\n",ex,ey);
#endif
        FF_WWW_mod(x,p,n);
    }

    if (n==1)
    {
        BIG_XXX_mul(d[0],x[0],y[0]);
        BIG_XXX_monty(z[0],p[0],((chunk)1<<BASEBITS_XXX)-ND[0][0],d[0]);
    }
    else
    {
        FF_WWW_mul(d,x,y,n);
        FF_WWW_reduce(z,d,p,ND,n);
    }
}

static void FF_WWW_modsqr(BIG_XXX z[],BIG_XXX x[],BIG_XXX p[],BIG_XXX ND[],int n)
{
#ifndef C99
    BIG_XXX d[2*FFLEN_WWW];
#else
    BIG_XXX d[2*n];
#endif
    chunk ex=P_EXCESS_WWW(x[n-1]);
#ifdef dchunk
    if ((dchunk)(ex+1)*(ex+1)>(dchunk)P_FEXCESS_WWW)
#else
    if ((ex+1)>P_FEXCESS_WWW/(ex+1))
#endif
    {
#ifdef DEBUG_REDUCE
        printf("Product too large - reducing it %d\n",ex);
#endif
        FF_WWW_mod(x,p,n);
    }
    if (n==1)
    {
        BIG_XXX_sqr(d[0],x[0]);
        BIG_XXX_monty(z[0],p[0],((chunk)1<<BASEBITS_XXX)-ND[0][0],d[0]);
    }
    else
    {
        FF_WWW_sqr(d,x,n);
        FF_WWW_reduce(z,d,p,ND,n);
    }
}

void FF_WWW_2w_precompute(BIG_XXX *X[], BIG_XXX *T[], int k, int w, BIG_XXX p[], BIG_XXX ND[], int plen)
{
    int i, j, z, b;

    FF_WWW_one(T[0], plen);
    FF_WWW_nres(T[0], p, plen);

    for (i = 0; i < k; i++)
    {
        j = 1<<(i*w);

        FF_WWW_copy(T[j], X[i], plen);
        FF_WWW_nres(T[j], p, plen);

        for (j++; j < (1<<((i+1)*w)); j++)
        {
            // Perform parity checks on windows.
            // z==k <==> all exponents are even
            for (z = 0; (z < k) && !((j >> (w*z)) & 1); z++);

            if (z<k)
            {
                // Find the LSB of j. Set b as 2^LSB
                for (b = 1; !(j & b); b<<=1);

                FF_WWW_modmul(T[j], T[j-b], T[b], p, ND, plen);
            }
            else
            {
                FF_WWW_modsqr(T[j], T[j>>1], p, ND, plen);
            }
        }
    }
}

void FF_WWW_ct_2w_pow(BIG_XXX r[], BIG_XXX *T[], BIG_XXX *E[], int k, int w, BIG_XXX p[], BIG_XXX ND[], int plen, int elen)
{
    int i, j;
    sign32 index, e;

#ifndef C99
    BIG_XXX ws[FFLEN_WWW];
#else
    BIG_XXX ws[plen];
#endif

    FF_WWW_one(r, plen);
    FF_WWW_nres(r, p, plen);

    for (i=8*MODBYTES_XXX*elen-w; i>=0; i-=w)
    {
        // Square
        for (j=0; j<w; j++)
        {
            FF_WWW_modsqr(r,r,p,ND,plen);
        }

        // Choose element from precomputed table and multiply
        e = 0;
        for (j=k-1; j>=0; j--)
        {
            e <<= w;
            // This is assuming the window divides the BIGBITS
            e |= BIG_XXX_bits(E[j][i/BIGBITS_XXX],i%BIGBITS_XXX,w);
        }

        for (index = 0; index < 1<<(w*k); index++)
        {
            FF_WWW_cmove(ws, T[index], ct_equals(index,e), plen);
        }

        FF_WWW_modmul(r,r,ws,p,ND,plen);
    }

    FF_WWW_redc(r,p,ND,plen);
}

void FF_WWW_nt_2w_pow(BIG_XXX r[], BIG_XXX *T[], BIG_XXX *E[], int k, int w, BIG_XXX p[], BIG_XXX ND[], int plen, int elen)
{
    int i, j, e;

    FF_WWW_one(r, plen);
    FF_WWW_nres(r, p, plen);

    for (i=8*MODBYTES_XXX*elen-w; i>=0; i-=w)
    {
        // Square
        for (j=0; j<w; j++)
        {
            FF_WWW_modsqr(r,r,p,ND,plen);
        }

        // Choose element from precomputed table and multiply
        e = 0;
        for (j=k-1; j>=0; j--)
        {
            e <<= w;
            // This is assuming the window divides the BIGBITS
            e |= BIG_XXX_bits(E[j][i/BIGBITS_XXX],i%BIGBITS_XXX,w);
        }

        if (e != 0)
        {
            FF_WWW_modmul(r,r,T[e],p,ND,plen);
        }
    }

    FF_WWW_redc(r,p,ND,plen);
}


void FF_WWW_bi_precompute(BIG_XXX *X[], BIG_XXX *T[], int k, int w, BIG_XXX p[], BIG_XXX ND[], int plen)
{
    int i, j, window;

#ifndef C99
    BIG_XXX gsqr[FFLEN_WWW];
#else
    BIG_XXX gsqr[plen];
#endif

    window = 1<<(w-1);
    j = 0;

    for (i=0; i<k; i++)
    {
        FF_WWW_copy(T[j], X[i], plen);
        FF_WWW_nres(T[j], p, plen);

        FF_WWW_modsqr(gsqr, T[j], p, ND, plen);

        for(j++; j<((i+1) * window); j++)
        {
            FF_WWW_modmul(T[j], T[j - 1], gsqr, p, ND, plen);
        }
    }
}

void FF_WWW_bi_pow(BIG_XXX r[], BIG_XXX *T[], BIG_XXX *E[], int k, int w, BIG_XXX p[], BIG_XXX ND[], int plen, int elen)
{
    int i, j, l, pos;

#ifndef C99
    int w_handle[4];
    int e[4];
#else
    int w_handle[k];
    int e[k];
#endif

    FF_WWW_one(r, plen);
    FF_WWW_nres(r, p, plen);

    for (i=0; i<k; i++)
    {
        w_handle[i] = -1;
    }

    for (i=8*MODBYTES_XXX*elen-1; i>=0; i--)
    {
        FF_WWW_modsqr(r,r,p,ND,plen);

        for (j=0; j<k; j++)
        {
            // Prepare table entry and position for multiplication if none
            // is selected
            if (w_handle[j] < 0 && (BIG_XXX_bit(E[j][i/BIGBITS_XXX], i%BIGBITS_XXX) == 1))
            {
                // Skip position until the exponent is odd
                for(pos = i - w + 1; BIG_XXX_bit(E[j][pos/BIGBITS_XXX], pos%BIGBITS_XXX) == 0; pos++);

                // Save exponent for multiplication step
                e[j] = 0;
                for(l=i; l>pos; l--)
                {
                    e[j] <<= 1;
                    e[j] |= BIG_XXX_bit(E[j][l/BIGBITS_XXX], l%BIGBITS_XXX);
                }

                // Set position for multiplication step
                w_handle[j] = pos;
            }

            // Multiplication step
            if (w_handle[j] == i)
            {
                FF_WWW_modmul(r, r, T[j * (1<<(w-1)) + e[j]], p, ND, plen);

                // Multiplication done. Reset multiplication position
                // to unselected
                w_handle[j] = -1;
            }
        }
    }

    FF_WWW_redc(r, p, ND, plen);
}

/* r=x^e mod p using side-channel resistant Montgomery Ladder, for short e */
void FF_WWW_ct_pow_big(BIG_XXX r[],BIG_XXX x[],BIG_XXX e,BIG_XXX p[],int n)
{
    int i,b;
#ifndef C99
    BIG_XXX R0[FFLEN_WWW],R1[FFLEN_WWW],ND[FFLEN_WWW];
#else
    BIG_XXX R0[n],R1[n],ND[n];
#endif
    FF_WWW_invmod2m(ND,p,n);
    FF_WWW_one(R0,n);
    FF_WWW_copy(R1,x,n);
    FF_WWW_nres(R0,p,n);
    FF_WWW_nres(R1,p,n);
    for (i=8*MODBYTES_XXX-1; i>=0; i--)
    {
        b=BIG_XXX_bit(e,i);
        FF_WWW_modmul(r,R0,R1,p,ND,n);
        FF_WWW_cswap(R0,R1,b,n);
        FF_WWW_modsqr(R0,R0,p,ND,n);
        FF_WWW_copy(R1,r,n);
        FF_WWW_cswap(R0,R1,b,n);
    }
    FF_WWW_copy(r,R0,n);
    FF_WWW_redc(r,p,ND,n);
}

/* r=x^e mod p using side-channel resistant implementation */
void FF_WWW_ct_pow(BIG_XXX r[],BIG_XXX x[],BIG_XXX e[],BIG_XXX p[],int n, int en)
{
#ifndef C99
    BIG_XXX T_mem[16][FFLEN_WWW],ND[FFLEN_WWW];
#else
    BIG_XXX T_mem[16][n],ND[n];
#endif

    BIG_XXX *T[] =
    {
        T_mem[0],  T_mem[1],  T_mem[2],  T_mem[3],
        T_mem[4],  T_mem[5],  T_mem[6],  T_mem[7],
        T_mem[8],  T_mem[9],  T_mem[10], T_mem[11],
        T_mem[12], T_mem[13], T_mem[14], T_mem[15],
    };

    BIG_XXX *X[] = {x};
    BIG_XXX *E[] = {e};

    FF_WWW_invmod2m(ND,p,n);

    FF_WWW_2w_precompute(X, T, 1, 4, p, ND, n);
    FF_WWW_ct_2w_pow(r, T, E, 1, 4, p, ND, n, en);
}

/* r=x^e*y^f mod p - side channel resistant */
void FF_WWW_ct_pow_2(BIG_XXX r[],BIG_XXX x[], BIG_XXX e[], BIG_XXX y[], BIG_XXX f[], BIG_XXX p[], int n, int en)
{
#ifndef C99
    BIG_XXX T_mem[16][FFLEN_WWW],ND[FFLEN_WWW];
#else
    BIG_XXX T_mem[16][n],ND[n];
#endif

    BIG_XXX *T[] =
    {
        T_mem[0],  T_mem[1],  T_mem[2],  T_mem[3],
        T_mem[4],  T_mem[5],  T_mem[6],  T_mem[7],
        T_mem[8],  T_mem[9],  T_mem[10], T_mem[11],
        T_mem[12], T_mem[13], T_mem[14], T_mem[15],
    };

    BIG_XXX *X[] = {x, y};
    BIG_XXX *E[] = {e, f};

    FF_WWW_invmod2m(ND,p,n);

    FF_WWW_2w_precompute(X, T, 2, 2, p, ND, n);
    FF_WWW_ct_2w_pow(r, T, E, 2, 2, p, ND, n, en);
}

/* r=x^e*y^f*z^g mod p - side channel resistant */
void FF_WWW_ct_pow_3(BIG_XXX r[],BIG_XXX x[], BIG_XXX e[], BIG_XXX y[], BIG_XXX f[], BIG_XXX z[], BIG_XXX g[], BIG_XXX p[], int n, int en)
{
#ifndef C99
    BIG_XXX T_mem[8][FFLEN_WWW],ND[FFLEN_WWW];
#else
    BIG_XXX T_mem[8][n],ND[n];
#endif

    BIG_XXX *T[] =
    {
        T_mem[0], T_mem[1], T_mem[2], T_mem[3],
        T_mem[4], T_mem[5], T_mem[6], T_mem[7],
    };

    BIG_XXX *X[] = {x, y, z};
    BIG_XXX *E[] = {e, f, g};

    FF_WWW_invmod2m(ND,p,n);

    FF_WWW_2w_precompute(X, T, 3, 1, p, ND, n);
    FF_WWW_ct_2w_pow(r, T, E, 3, 1, p, ND, n, en);
}

/* raise to an integer power - right-to-left method */
void FF_WWW_nt_pow_int(BIG_XXX r[],BIG_XXX x[],int e,BIG_XXX p[],int n)
{
    int f=1;
#ifndef C99
    BIG_XXX w[FFLEN_WWW],ND[FFLEN_WWW];
#else
    BIG_XXX w[n],ND[n];
#endif
    FF_WWW_invmod2m(ND,p,n);

    FF_WWW_copy(w,x,n);
    FF_WWW_nres(w,p,n);

    if (e==2)
    {
        FF_WWW_modsqr(r,w,p,ND,n);
    }
    else for (;;)
        {
            if (e%2==1)
            {
                if (f) FF_WWW_copy(r,w,n);
                else FF_WWW_modmul(r,r,w,p,ND,n);
                f=0;
            }
            e>>=1;
            if (e==0) break;
            FF_WWW_modsqr(w,w,p,ND,n);
        }

    FF_WWW_redc(r,p,ND,n);
}

/* r=x^e mod p, faster but not side channel resistant */
void FF_WWW_nt_pow(BIG_XXX r[], BIG_XXX x[], BIG_XXX e[], BIG_XXX p[], int n, int en)
{
#ifndef C99
    BIG_XXX T_mem[16][FFLEN_WWW],ND[FFLEN_WWW];
#else
    BIG_XXX T_mem[16][n],ND[n];
#endif

    BIG_XXX *T[] =
    {
        T_mem[0],  T_mem[1],  T_mem[2],  T_mem[3],
        T_mem[4],  T_mem[5],  T_mem[6],  T_mem[7],
        T_mem[8],  T_mem[9],  T_mem[10], T_mem[11],
        T_mem[12], T_mem[13], T_mem[14], T_mem[15],
    };

    BIG_XXX *X[] = {x};
    BIG_XXX *E[] = {e};

    FF_WWW_invmod2m(ND,p,n);

    FF_WWW_bi_precompute(X, T, 1, 5, p, ND, n);
    FF_WWW_bi_pow(r, T, E, 1, 5, p, ND, n, en);
}

void FF_WWW_nt_pow_2(BIG_XXX *r,BIG_XXX *x,BIG_XXX *e, BIG_XXX *y, BIG_XXX *f, BIG_XXX *p,int n, int en)
{
#ifndef C99
    BIG_XXX T_mem[16][FFLEN_WWW],ND[FFLEN_WWW];
#else
    BIG_XXX T_mem[16][n],ND[n];
#endif

    BIG_XXX *T[] =
    {
        T_mem[0],  T_mem[1],  T_mem[2],  T_mem[3],
        T_mem[4],  T_mem[5],  T_mem[6],  T_mem[7],
        T_mem[8],  T_mem[9],  T_mem[10], T_mem[11],
        T_mem[12], T_mem[13], T_mem[14], T_mem[15],
    };

    BIG_XXX *X[] = {x,y};
    BIG_XXX *E[] = {e,f};

    FF_WWW_invmod2m(ND,p,n);

    FF_WWW_bi_precompute(X, T, 2, 4, p, ND, n);
    FF_WWW_bi_pow(r, T, E, 2, 4, p, ND, n, en);
}

void FF_WWW_nt_pow_3(BIG_XXX *r,BIG_XXX *x,BIG_XXX *e, BIG_XXX *y, BIG_XXX *f, BIG_XXX *z, BIG_XXX *g, BIG_XXX *p, int n, int en)
{
#ifndef C99
    BIG_XXX T_mem[8][FFLEN_WWW],ND[FFLEN_WWW];
#else
    BIG_XXX T_mem[8][n],ND[n];
#endif

    BIG_XXX *T[] =
    {
        T_mem[0],  T_mem[1],  T_mem[2],  T_mem[3],
        T_mem[4],  T_mem[5],  T_mem[6],  T_mem[7],
    };

    BIG_XXX *X[] = {x,y,z};
    BIG_XXX *E[] = {e,f,g};

    FF_WWW_invmod2m(ND,p,n);

    FF_WWW_2w_precompute(X, T, 3, 1, p, ND, n);
    FF_WWW_nt_2w_pow(r, T, E, 3, 1, p, ND, n, en);
}

void FF_WWW_nt_pow_4(BIG_XXX *r,BIG_XXX *x,BIG_XXX *e, BIG_XXX *y, BIG_XXX *f, BIG_XXX *z, BIG_XXX *g, BIG_XXX *w, BIG_XXX *h, BIG_XXX *p, int n, int en)
{
#ifndef C99
    BIG_XXX T_mem[16][FFLEN_WWW],ND[FFLEN_WWW];
#else
    BIG_XXX T_mem[16][n],ND[n];
#endif

    BIG_XXX *T[] =
    {
        T_mem[0],  T_mem[1],  T_mem[2],  T_mem[3],
        T_mem[4],  T_mem[5],  T_mem[6],  T_mem[7],
        T_mem[8],  T_mem[9],  T_mem[10], T_mem[11],
        T_mem[12], T_mem[13], T_mem[14], T_mem[15],
    };

    BIG_XXX *X[] = {x,y,z,w};
    BIG_XXX *E[] = {e,f,g,h};

    FF_WWW_invmod2m(ND,p,n);

    FF_WWW_2w_precompute(X, T, 4, 1, p, ND, n);
    FF_WWW_nt_2w_pow(r, T, E, 4, 1, p, ND, n, en);
}

static sign32 igcd(sign32 x,sign32 y)
{
    /* integer GCD, returns GCD of x and y */
    sign32 r;
    if (y==0) return x;
    while ((r=x%y)!=0)
        x=y,y=r;
    return y;
}

/* quick and dirty check for common factor with s */
int FF_WWW_cfactor(BIG_XXX w[],sign32 s,int n)
{
    int r;
    sign32 g;
#ifndef C99
    BIG_XXX x[FFLEN_WWW],y[FFLEN_WWW];
#else
    BIG_XXX x[n],y[n];
#endif
    FF_WWW_init(y,s,n);
    FF_WWW_copy(x,w,n);
    FF_WWW_norm(x,n);

    do
    {
        FF_WWW_sub(x,x,y,n);
        FF_WWW_norm(x,n);
        while (!FF_WWW_iszilch(x,n) && FF_WWW_parity(x)==0) FF_WWW_shr(x,n);
    }
    while (FF_WWW_comp(x,y,n)>0);
#if CHUNK<32
    g=x[0][0]+((sign32)(x[0][1])<<BASEBITS_XXX);
#else
    g=(sign32)x[0][0];
#endif
    r=igcd(s,g);
    if (r>1) return 1;
    return 0;
}

/* Miller-Rabin test for primality. Slow. */
int FF_WWW_prime(BIG_XXX p[],csprng *rng,int n)
{
    int i,j,loop,s=0;
#ifndef C99
    BIG_XXX d[FFLEN_WWW],x[FFLEN_WWW],nm1[FFLEN_WWW];
#else
    BIG_XXX d[n],x[n],nm1[n];
#endif
    sign32 sf=4849845;/* 3*5*.. *19 */

    FF_WWW_norm(p,n);

    if (FF_WWW_cfactor(p,sf,n)) return 0;

    FF_WWW_copy(nm1,p,n);
    FF_WWW_dec(nm1,1,n);
    FF_WWW_norm(nm1,n);
    FF_WWW_copy(d,nm1,n);
    while (FF_WWW_parity(d)==0)
    {
        FF_WWW_shr(d,n);
        s++;
    }
    if (s==0) return 0;

    for (i=0; i<10; i++)
    {
        FF_WWW_randomnum(x,p,rng,n);
        FF_WWW_nt_pow(x,x,d,p,n,n);
        if (FF_WWW_isunity(x,n) || FF_WWW_comp(x,nm1,n)==0) continue;
        loop=0;
        for (j=1; j<s; j++)
        {
            FF_WWW_nt_pow_int(x,x,2,p,n);
            if (FF_WWW_isunity(x,n)) return 0;
            if (FF_WWW_comp(x,nm1,n)==0 )
            {
                loop=1;
                break;
            }
        }
        if (loop) continue;
        return 0;
    }

    return 1;
}

/* Chinese Remainder Theorem to reconstruct results mod pq*/
void FF_WWW_crt(BIG_XXX *r, BIG_XXX *rp, BIG_XXX *rq, BIG_XXX *p, BIG_XXX *invp, BIG_XXX *pq, int n)
{
#ifndef C99
    BIG_XXX c[FFLEN_WWW], a[FFLEN_WWW], b[2*FFLEN_WWW];
#else
    BIG_XXX c[2*n], a[2*n], b[4*n];
#endif

    // c = p * (p^-1 mod q)
    FF_WWW_mul(c, p, invp, n);

    // a = (rq - rp) mod pq
    FF_WWW_copy(a, pq, 2*n);
    FF_WWW_sub(a, a, rp, n);
    FF_WWW_add(a, a, rq, n);

    // (ac + rp) mod pq
    FF_WWW_mul(b, a, c, 2*n);
    FF_WWW_dmod(a, b, pq, 2*n);

    FF_WWW_dscopy(r, rp, n);
    FF_WWW_add(r, r, a, 2*n);
    FF_WWW_mod(r, pq, 2*n);
}
