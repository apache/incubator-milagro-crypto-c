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

/*** Basic Octet string maintainance routines  ***/
/* SU=m, m is Stack Usage */

#include <string.h>
#include "amcl.h"

/* Output an octet string (Debug Only) */

/* SU= 16 */
/* output octet */
void OCT_output(const octet *w)
{
    unsigned char ch;
    for (int i=0; i<w->len; i++)
    {
        ch=w->val[i];
        printf("%02x",ch);
    }
    printf("\n");
}

/* SU= 16 */
void OCT_output_string(const octet *w)
{
    unsigned char ch;
    for (int i=0; i<w->len; i++)
    {
        ch=w->val[i];
        printf("%c",ch);
    }
}

/* Convert C string to octet format - truncates if no room  */
void OCT_jstring(octet *y,const char *s)
{
    int i;
    int j;
    i=y->len;
    j=0;
    while (s[j]!=0 && i<y->max)
    {
        y->val[i]=s[j];
        y->len++;
        i++;
        j++;
    }
}

/* compare 2 octet strings.
 * If x==y return TRUE, else return FALSE */
/* SU= 8 */
int OCT_comp(const octet *x,const octet *y)
{
    byte res = 0;

    if (x->len != y->len) return 0;
    for (int i=0; i<x->len; i++)
    {
        res |= (x->val[i] ^ y->val[i]);
    }

    // Condense result to one bit
    res = ~res;
    res &= res >> 4;
    res &= res >> 2;
    res &= res >> 1;

    return (int)res;
}

/* check are first n bytes the same (in constant time) */

int OCT_ncomp(const octet *x,const octet *y,int n)
{
    byte res = 0;
    if (n>y->len || n>x->len) return 0;
    for (int i=0; i<n; i++)
    {
        res |= (x->val[i] ^ y->val[i]);
    }

    // Condense result to one bit
    res = ~res;
    res &= res >> 4;
    res &= res >> 2;
    res &= res >> 1;

    return (int)res;
}

/* Shift octet to the left by n bytes. Leftmost bytes disappear  */
void OCT_shl(octet *x,int n)
{
    if (n>=x->len)
    {
        x->len=0;
        return;
    }
    x->len-=n;
    for (int i=0; i<x->len; i++)
        x->val[i]=x->val[i+n];
}

/* Append binary string to octet - truncates if no room */
/* SU= 12 */
void OCT_jbytes(octet *y,const char *b,int len)
{
    int i;
    i=y->len;
    for (int j=0; j<len && i<y->max; j++)
    {
        y->val[i]=b[j];
        y->len++;
        i++;
    }
}

/* Concatenates two octet strings */
/* SU= 8 */
void OCT_joctet(octet *y,const octet *x)
{
    /* y=y || x */
    int j;
    if (x==NULL) return;

    for (int i=0; i<x->len; i++)
    {
        j=y->len+i;
        if (j>=y->max)
        {
            y->len=y->max;
            return;
        }
        y->val[j]=x->val[i];
    }
    y->len+=x->len;
}

/* Append byte to octet rep times */
/* SU= 8 */
void OCT_jbyte(octet *y,int ch,int rep)
{
    int i;
    i=y->len;
    for (int j=0; j<rep && i<y->max; j++)
    {
        y->val[i]=(char)ch;
        y->len++;
        i++;
    }
}

/* XOR common bytes of x with y */
/* SU= 8 */
void OCT_xor(octet *y,const octet *x)
{
    /* xor first x->len bytes of y */

    for (int i=0; i<x->len && i<y->len; i++)
    {
        y->val[i]^=x->val[i];
    }
}

/* clear an octet */
void OCT_empty(octet *w)
{
    w->len=0;
}

/* Kill an octet string - Zeroise it for security */
void OCT_clear(octet *w)
{
    for (int i=0; i<w->max; i++) w->val[i]=0;
    w->len=0;
}

/* appends int x of length len bytes to OCTET string */
/* SU= 8 */
void OCT_jint(octet *y,int x,int len)
{
    int i;
    int n;
    n=y->len+len;
    if (n>y->max || len<=0) return;
    for (i=y->len; i<n; i++) y->val[i]=0;
    y->len=n;

    i=y->len;
    while (x>0 && i>0)
    {
        i--;
        y->val[i]=(char)(x%256);
        x/=256;
    }
}

/* Pad an octet to a given length */
/* SU= 8 */
int OCT_pad(octet *w,int n)
{
    int i;
    int d;
    if (w->len>n || n>w->max) return 0;
    if (n==w->len) return 1;
    d=n-w->len;
    for (i=n-1; i>=d; i--)
        w->val[i]=w->val[i-d];
    for (i=d-1; i>=0; i--)
        w->val[i]=0;
    w->len=n;
    return 1;
}


/* Convert an octet string to base64 string */
/* SU= 56 */
void OCT_tobase64(char *b,const octet *w)
{
    int i;
    int j;
    int k;
    int rem;
    int last;
    int c;
    int ch[4];
    unsigned char ptr[3];
    rem=w->len%3;
    j=k=0;
    last=4;
    while (j<w->len)
    {
        for (i=0; i<3; i++)
        {
            if (j<w->len) ptr[i]=w->val[j++];
            else
            {
                ptr[i]=0;
                last--;
            }
        }
        ch[0]=(ptr[0]>>2)&0x3f;
        ch[1]=((ptr[0]<<4)|(ptr[1]>>4))&0x3f;
        ch[2]=((ptr[1]<<2)|(ptr[2]>>6))&0x3f;
        ch[3]=ptr[2]&0x3f;
        for (i=0; i<last; i++)
        {
            c=ch[i];
            if (c<26) c+=65;
            if (c>=26 && c<52) c+=71;
            if (c>=52 && c<62) c-=4;
            if (c==62) c='+';
            if (c==63) c='/';
            b[k++]=(char)c;
        }
    }
    if (rem>0) for (i=rem; i<3; i++) b[k++]='=';
    b[k]='\0';  /* dangerous! */
}

/* SU= 56 */
void OCT_frombase64(octet *w,const char *b)
{
    int i;
    int j;
    int k;
    int pads;
    int len=(int)strlen(b);
    int c;
    int ch[4];
    int ptr[3];
    OCT_clear(w);

    j=k=0;
    while (j<len && k<w->max)
    {
        pads=0;
        for (i=0; i<4; i++)
        {
            c=80+b[j++];
            if (c<=112) continue; /* ignore white space */
            if (c>144 && c<171) c-=145;
            if (c>176 && c<203) c-=151;
            if (c>127 && c<138) c-=76;
            if (c==123) c=62;
            if (c==127) c=63;
            if (c==141)
            {
                pads++;    /* ignore pads '=' */
                continue;
            }
            ch[i]=c;
        }
        ptr[0]=(ch[0]<<2)|(ch[1]>>4);
        ptr[1]=(ch[1]<<4)|(ch[2]>>2);
        ptr[2]=(ch[2]<<6)|ch[3];
        for (i=0; i<3-pads && k<w->max; i++)
        {
            /* don't put in leading zeros */
            w->val[k++]=(char)ptr[i];
        }
    }
    w->len=k;
}

/* copy an octet string - truncates if no room */
/* SU= 16 */
void OCT_copy(octet *y,const octet *x)
{
    OCT_clear(y);
    y->len=x->len;
    if (y->len>y->max) y->len=y->max;

    for (int i=0; i<y->len; i++)
        y->val[i]=x->val[i];
}

/* XOR m with all of x */
void OCT_xorbyte(octet *x,int m)
{
    for (int i=0; i<x->len; i++) x->val[i]^=m;
}

/* truncates x to n bytes and places the rest in y (if y is not NULL) */
/* SU= 8 */
void OCT_chop(octet *x,octet *y,int n)
{
    if (n>=x->len)
    {
        if (y!=NULL) y->len=0;
        return;
    }
    if (y!=NULL) y->len=x->len-n;
    x->len=n;

    if (y!=NULL)
    {
        for (int i=0; i<y->len && i<y->max; i++) y->val[i]=x->val[i+n];
    }
}

/* set x to len random bytes */
void OCT_rand(octet *x,csprng *RNG,int len)
{
    if (len>x->max) len=x->max;
    x->len=len;

    for (int i=0; i<len; i++) x->val[i]=(char)RAND_byte(RNG);
}

/* Convert an octet to a hex string */
void OCT_toHex(const octet *src,char *dst)
{
    int i;
    const char * hexadecimals = "0123456789abcdef";
    unsigned char ch;
    for (i=0; i<src->len; i++)
    {
        ch=src->val[i];
        uint8_t res = ch / 16;
        uint8_t mod = ch % 16;
        dst[i*2] = hexadecimals[res];
        dst[(i*2)+1] = hexadecimals[mod];
    }
    dst[i*2] =0;
}

static int char2int(char input)
{
    if(input >= '0' && input <= '9')
        return input - '0';
    if(input >= 'A' && input <= 'F')
        return input - 'A' + 10;
    if(input >= 'a' && input <= 'f')
        return input - 'a' + 10;
    return 0;
}

/* Convert from a hex string */
void OCT_fromHex(octet *dst,const char *src)
{
    int i=0;
    int j=0;
    int len = (int)strlen(src);
    OCT_clear(dst);

    while(j < len && i < dst->max)
    {
        dst->val[i++] = (char)(char2int(src[j])*16 + char2int(src[j+1]));
        j += 2;
    }
    dst->len=i;
}

/* Convert an octet to a string */
void OCT_toStr(const octet *src,char *dst)
{
    unsigned char ch;
    for (int i=0; i<src->len; i++)
    {
        ch=src->val[i];
        snprintf(&dst[i], sizeof(unsigned char)+1, "%c", ch);
    }
}

