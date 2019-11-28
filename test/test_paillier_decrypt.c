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
    char *linePtr=NULL;

    char pt[FS_2048]= {0};
    octet PT = {0,sizeof(pt),pt};

    int testNo=0;
    const char* TESTline = "TEST = ";

    PAILLIER_private_key PRIV;
    const char* Nline = "N = ";
    const char* Lline = "L = ";
    const char* Mline = "M = ";

    char ptgolden[FS_2048]= {0};
    octet PTGOLDEN = {0,sizeof(ptgolden),ptgolden};
    const char* PTline = "PLAINTEXT = ";

    char ctgolden[FS_4096]= {0};
    octet CTGOLDEN = {0,sizeof(ctgolden),ctgolden};
    const char* CTline = "CIPHERTEXT = ";

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

        // Read N
        if (!strncmp(line,Nline, strlen(Nline)))
        {
            len = strlen(Nline);
            linePtr = line + len;
            FF_4096_zero(PRIV.n, FFLEN_4096);
            read_FF_4096(PRIV.n, linePtr, HFLEN_4096);

            FF_4096_sqr(PRIV.n2,PRIV.n, HFLEN_4096);
            FF_4096_norm(PRIV.n2, FFLEN_4096);
#ifdef DEBUG
            printf("N = ");
            FF_4096_output(PRIV.n , FFLEN_4096);
            printf("\n");
#endif
        }

        // Read L
        if (!strncmp(line,Lline, strlen(Lline)))
        {
            len = strlen(Lline);
            linePtr = line + len;
            read_FF_4096(PRIV.l, linePtr, HFLEN_4096);
#ifdef DEBUG
            printf("L = ");
            FF_4096_output(PRIV.l , HFLEN_4096);
            printf("\n");
#endif
        }

        // Read M
        if (!strncmp(line,Mline, strlen(Mline)))
        {
            len = strlen(Mline);
            linePtr = line + len;
            FF_4096_zero(PRIV.m, FFLEN_4096);
            read_FF_4096(PRIV.m, linePtr, HFLEN_4096);
#ifdef DEBUG
            printf("M = ");
            FF_4096_output(PRIV.m , FFLEN_4096);
            printf("\n");
#endif
        }

        // Read CIPHERTEXT
        if (!strncmp(line,CTline, strlen(CTline)))
        {
            len = strlen(CTline);
            linePtr = line + len;
            read_OCTET(&CTGOLDEN,linePtr);
#ifdef DEBUG
            printf("CIPHERTEXT = ");
            OCT_output(&CTGOLDEN);
#endif
        }

        // Read PLAINTEXT and process test vector
        if (!strncmp(line,PTline, strlen(PTline)))
        {
            len = strlen(PTline);
            linePtr = line + len;
            read_OCTET(&PTGOLDEN,linePtr);
#ifdef DEBUG
            printf("PLAINTEXT = ");
            OCT_output(&PTGOLDEN);
#endif

            PAILLIER_DECRYPT(&PRIV, &CTGOLDEN, &PT);

#ifdef DEBUG
            printf("PT: ");
            OCT_output(&PT);
            printf("\n");
#endif

            if(!OCT_comp(&PTGOLDEN,&PT))
            {
#ifdef DEBUG
                printf("PTGOLDEN: ");
                OCT_output(&PTGOLDEN);
                printf("\n");
#endif
                fprintf(stderr, "FAILURE Test %d\n", testNo);
                fclose(fp);
                exit(EXIT_FAILURE);
            }
        }
    }

    fclose(fp);

    printf("SUCCESS TEST PAILLIER DECRYPTION PASSED\n");
    exit(EXIT_SUCCESS);
}

