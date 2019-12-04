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
#include "amcl.h"
#include "randapi.h"
#include "paillier.h"

#define LINE_LEN 2000

void read_OCTET(octet* OCT, char* string)
{
    int len = strlen(string);
    char buff[len];
    memcpy(buff,string,len);
    char *end = strchr(buff,',');
    if (end == NULL)
    {
        printf("ERROR unexpected test vector %s\n",string);
        exit(EXIT_FAILURE);
    }
    end[0] = '\0';
    OCT_fromHex(OCT,buff);
}

void read_FF_4096(BIG_512_60 *x, char* string, int n)
{
    int len = strlen(string);
    char oct[len/2];
    octet OCT = {0, len/2, oct};

    read_OCTET(&OCT, string);
    FF_4096_fromOctet(x, &OCT, n);
}

void compare_FF(char *x_name, char* y_name, BIG_512_60 *x, BIG_512_60 *y, int n)
{
    if(FF_4096_comp(x, y, n))
    {
        fprintf(stderr, "FAILURE %s != %s\n", x_name, y_name);
        exit(EXIT_FAILURE);
    }
}

void clean_private(PAILLIER_private_key *PRIV)
{
    PAILLIER_PRIVATE_KEY_KILL(PRIV);
    FF_4096_zero(PRIV->n, FFLEN_4096);
    FF_4096_zero(PRIV->g, FFLEN_4096);
    FF_4096_zero(PRIV->n2, FFLEN_4096);
}

void clean_public(PAILLIER_public_key *PUB)
{
    FF_4096_zero(PUB->n, FFLEN_4096);
    FF_4096_zero(PUB->g, FFLEN_4096);
    FF_4096_zero(PUB->n2, FFLEN_4096);
}

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_paillier_decrypt [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int len=0;
    FILE *fp;

    char line[LINE_LEN]= {0};
    char * linePtr=NULL;

    int testSeed=0;

    PAILLIER_private_key PRIV;
    PAILLIER_public_key PUB;

    int testNo=0;
    const char* TESTline = "TEST = ";

    char seedgolden[32]= {0};
    octet SEEDGOLDEN = {0,sizeof(seedgolden),seedgolden};
    const char* SEEDline = "SEED = ";

    char p[FS_2048]={0};
    char pgolden[HFS_2048]= {0};
    octet P = {0, sizeof(p),p};
    octet PGOLDEN = {0,sizeof(pgolden),pgolden};
    const char* Pline = "P = ";

    char q[FS_2048]={0};
    char qgolden[HFS_2048]={0};
    octet Q = {0, sizeof(q),q};
    octet QGOLDEN = {0,sizeof(qgolden),qgolden};
    const char* Qline = "Q = ";

    PAILLIER_private_key PRIVGOLDEN;
    PAILLIER_public_key PUBGOLDEN;
    const char* Nline = "N = ";
    const char* Gline = "G = ";
    const char* Lline = "L = ";
    const char* Mline = "M = ";

    // Clean GOLDEN keys, the generated keys should be cleaned
    // during initialisation
    clean_private(&PRIVGOLDEN);
    clean_public(&PUBGOLDEN);

    fp = fopen(argv[1], "r");
    if (fp == NULL)
    {
        printf("ERROR opening test vector file\n");
        exit(EXIT_FAILURE);
    }

    while (fgets(line, LINE_LEN, fp) != NULL)
    {
        // Read TEST Number
        if (!strncmp(line,TESTline, strlen(TESTline)))
        {
            len = strlen(TESTline);
            linePtr = line + len;
            sscanf(linePtr,"%d\n",&testNo);
        }

        // Read SEED
        if (!strncmp(line,SEEDline, strlen(SEEDline)))
        {
            len = strlen(SEEDline);
            linePtr = line + len;
            read_OCTET(&SEEDGOLDEN,linePtr);
            testSeed = 1;
        }

        // Read P
        if (!strncmp(line,Pline, strlen(Pline)))
        {
            len = strlen(Pline);
            linePtr = line + len;
            read_OCTET(&PGOLDEN,linePtr);
            OCT_copy(&P, &PGOLDEN);
            OCT_pad(&P, HFS_4096);
            FF_4096_fromOctet(PRIVGOLDEN.p,&P,HFLEN_4096);
        }

        // Read Q
        if (!strncmp(line,Qline, strlen(Qline)))
        {
            len = strlen(Qline);
            linePtr = line + len;
            read_OCTET(&QGOLDEN,linePtr);
            OCT_copy(&Q, &QGOLDEN);
            OCT_pad(&Q, HFS_4096);
            FF_4096_fromOctet(PRIVGOLDEN.q,&Q,HFLEN_4096);
        }

        // Read N
        if (!strncmp(line,Nline, strlen(Nline)))
        {
            len = strlen(Nline);
            linePtr = line + len;
            read_FF_4096(PRIVGOLDEN.n, linePtr, HFLEN_4096);

            FF_4096_sqr(PRIVGOLDEN.n2,PRIVGOLDEN.n, HFLEN_4096);
            FF_4096_norm(PRIVGOLDEN.n2, FFLEN_4096);

            FF_4096_invmod2m(PRIVGOLDEN.invn, PRIVGOLDEN.n, FFLEN_4096);

            FF_4096_copy(PUBGOLDEN.n, PRIVGOLDEN.n, HFLEN_4096);
            FF_4096_copy(PUBGOLDEN.n2, PRIVGOLDEN.n2, FFLEN_4096);
        }

        // Read G
        if (!strncmp(line,Gline, strlen(Gline)))
        {
            len = strlen(Gline);
            linePtr = line + len;
            read_FF_4096(PRIVGOLDEN.g, linePtr, HFLEN_4096);
            FF_4096_copy(PUBGOLDEN.g, PRIVGOLDEN.g, HFLEN_4096);
        }

        // Read L
        if (!strncmp(line,Lline, strlen(Lline)))
        {
            len = strlen(Lline);
            linePtr = line + len;
            read_FF_4096(PRIVGOLDEN.l, linePtr, HFLEN_4096);
        }

        // Read M and process test vector
        if (!strncmp(line,Mline, strlen(Mline)))
        {
            len = strlen(Mline);
            linePtr = line + len;
            read_FF_4096(PRIVGOLDEN.m, linePtr, HFLEN_4096);

            if (testSeed)
            {
                testSeed=0;

                // CSPRNG
                csprng RNG;

                // initialise strong RNG
                CREATE_CSPRNG(&RNG,&SEEDGOLDEN);

                PAILLIER_KEY_PAIR(&RNG, NULL, NULL, &PUB, &PRIV);
            }
            else
            {
                PAILLIER_KEY_PAIR(NULL, &PGOLDEN, &QGOLDEN, &PUB, &PRIV);
            }

#ifdef DEBUG
            printf("SEED = ");
            OCT_output(&SEEDGOLDEN);
            printf("\nP = ");
            FF_4096_output(PRIV.p , HFLEN_4096);
            printf("\nQ = ");
            FF_4096_output(PRIV.q , HFLEN_4096);
            printf("\nL = ");
            FF_4096_output(PRIV.l , FFLEN_4096);
            printf("\nM = ");
            FF_4096_output(PRIV.m , FFLEN_4096);
            printf("\nN = ");
            FF_4096_output(PRIV.n , FFLEN_4096);
            printf("\nG = ");
            FF_4096_output(PRIV.g , FFLEN_4096);
            printf("\nN2 = ");
            FF_4096_output(PRIV.n2, FFLEN_4096);
            printf("\nPUB N = ");
            FF_4096_output(PUB.n , FFLEN_4096);
            printf("\nPUB G = ");
            FF_4096_output(PUB.g , FFLEN_4096);
            printf("\nPUB N2 = ");
            FF_4096_output(PUB.n2, FFLEN_4096);
            printf("\n\n");
#endif

            compare_FF("PRIV.p",    "PRIVGOLDEN.p",    PRIV.p,    PRIVGOLDEN.p,    HFLEN_4096);
            compare_FF("PRIV.q",    "PRIVGOLDEN.q",    PRIV.q,    PRIVGOLDEN.q,    HFLEN_4096);
            compare_FF("PRIV.l",    "PRIVGOLDEN.l",    PRIV.l,    PRIVGOLDEN.l,    FFLEN_4096);
            compare_FF("PRIV.m",    "PRIVGOLDEN.m",    PRIV.m,    PRIVGOLDEN.m,    FFLEN_4096);
            compare_FF("PRIV.n",    "PRIVGOLDEN.n",    PRIV.n,    PRIVGOLDEN.n,    FFLEN_4096);
            compare_FF("PRIV.g",    "PRIVGOLDEN.g",    PRIV.g,    PRIVGOLDEN.g,    FFLEN_4096);
            compare_FF("PRIV.invn", "PRIVGOLDEN.invn", PRIV.invn, PRIVGOLDEN.invn, FFLEN_4096);
            compare_FF("PRIV.n2",   "PRIVGOLDEN.n2",   PRIV.n2,   PRIVGOLDEN.n2,   FFLEN_4096);

            compare_FF("PUB.n",  "PUBGOLDEN.n",  PUB.n,  PUBGOLDEN.n,  FFLEN_4096);
            compare_FF("PUB.g",  "PUBGOLDEN.g",  PUB.g,  PUBGOLDEN.g,  FFLEN_4096);
            compare_FF("PUB.n2", "PUBGOLDEN.n2", PUB.n2, PUBGOLDEN.n2, FFLEN_4096);

            // Clean keys for next test vector
            clean_private(&PRIV);
            clean_private(&PRIVGOLDEN);

            clean_public(&PUB);
            clean_public(&PUBGOLDEN);
        }
    }

    fclose(fp);

    printf("SUCCESS TEST PAILLIER KEYGEN PASSED\n");
    exit(EXIT_SUCCESS);
}
