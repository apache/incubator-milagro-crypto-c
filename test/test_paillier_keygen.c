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
#include "ff_8192.h"
#include "ff_4096.h"
#include "ff_2048.h"
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

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_paillier_decrypt [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    int len=0;
    FILE *fp;
    int rc=0;

    char line[LINE_LEN]= {0};
    char * linePtr=NULL;

    int applyVector=0;
    int testSeed=0;

    const char* TESTline = "TEST = ";
    int testNo=0;

    // Test result
    int result=0;
    const char* RESULTline = "RESULT = ";

    char p1[FS_2048]= {0};
    octet P1 = {0,sizeof(p1),p1};
    char q1[FS_2048]= {0};
    octet Q1 = {0,sizeof(q1),q1};

    char n1[FS_2048]= {0};
    octet N1 = {0,sizeof(n1),n1};
    char g1[FS_2048]= {0};
    octet G1 = {0,sizeof(g1),g1};

    char l1[FS_2048]= {0};
    octet L1 = {0,sizeof(l1),l1};

    char m1[FS_2048]= {0};
    octet M1 = {0,sizeof(m1),m1};

    char n2[FS_2048]= {0};
    octet N2 = {0,sizeof(n2),n2};
    char g2[FS_2048]= {0};
    octet G2 = {0,sizeof(g2),g2};

    char l2[FS_2048]= {0};
    octet L2 = {0,sizeof(l2),l2};

    char m2[FS_2048]= {0};
    octet M2 = {0,sizeof(m2),m2};

    char seedgolden[32]= {0};
    octet SEEDGOLDEN = {0,sizeof(seedgolden),seedgolden};
    const char* SEEDline = "SEED = ";

    char pgolden[FS_2048]= {0};
    octet PGOLDEN = {0,sizeof(pgolden),pgolden};
    const char* Pline = "P = ";

    char qgolden[FS_2048]= {0};
    octet QGOLDEN = {0,sizeof(qgolden),qgolden};
    const char* Qline = "Q = ";

    char ngolden[FS_2048]= {0};
    octet NGOLDEN = {0,sizeof(ngolden),ngolden};
    const char* Nline = "N = ";

    char ggolden[FS_2048]= {0};
    octet GGOLDEN = {0,sizeof(ggolden),ggolden};
    const char* Gline = "G = ";

    char lgolden[FS_2048]= {0};
    octet LGOLDEN = {0,sizeof(lgolden),lgolden};
    const char* Lline = "L = ";

    char mgolden[FS_2048]= {0};
    octet MGOLDEN = {0,sizeof(mgolden),mgolden};
    const char* Mline = "M = ";

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
            printf("TEST = %d\n",testNo);
        }

        // Read SEED
        if (!strncmp(line,SEEDline, strlen(SEEDline)))
        {
            len = strlen(SEEDline);
            linePtr = line + len;
            read_OCTET(&SEEDGOLDEN,linePtr);
            testSeed = 1;
#ifdef DEBUG
            printf("SEED = ");
            OCT_output(&SEEDGOLDEN);
#endif
        }

        // Read P
        if (!strncmp(line,Pline, strlen(Pline)))
        {
            len = strlen(Pline);
            linePtr = line + len;
            read_OCTET(&PGOLDEN,linePtr);
#ifdef DEBUG
            printf("P = ");
            OCT_output(&PGOLDEN);
#endif
        }

        // Read Q
        if (!strncmp(line,Qline, strlen(Qline)))
        {
            len = strlen(Qline);
            linePtr = line + len;
            read_OCTET(&QGOLDEN,linePtr);
#ifdef DEBUG
            printf("Q = ");
            OCT_output(&QGOLDEN);
#endif
        }

        // Read N
        if (!strncmp(line,Nline, strlen(Nline)))
        {
            len = strlen(Nline);
            linePtr = line + len;
            read_OCTET(&NGOLDEN,linePtr);
#ifdef DEBUG
            printf("N = ");
            OCT_output(&NGOLDEN);
#endif
        }

        // Read G
        if (!strncmp(line,Gline, strlen(Gline)))
        {
            len = strlen(Gline);
            linePtr = line + len;
            read_OCTET(&GGOLDEN,linePtr);
#ifdef DEBUG
            printf("G = ");
            OCT_output(&GGOLDEN);
#endif
        }

        // Read L
        if (!strncmp(line,Lline, strlen(Lline)))
        {
            len = strlen(Lline);
            linePtr = line + len;
            read_OCTET(&LGOLDEN,linePtr);
#ifdef DEBUG
            printf("L = ");
            OCT_output(&LGOLDEN);
#endif
        }

        // Read M
        if (!strncmp(line,Mline, strlen(Mline)))
        {
            len = strlen(Mline);
            linePtr = line + len;
            read_OCTET(&MGOLDEN,linePtr);
#ifdef DEBUG
            printf("M = ");
            OCT_output(&MGOLDEN);
#endif
        }

        // Read expected result
        if (!strncmp(line,RESULTline, strlen(RESULTline)))
        {
            len = strlen(RESULTline);
            linePtr = line + len;
            sscanf(linePtr,"%d\n",&result);
            applyVector=1;
#ifdef DEBUG
            printf("RESULT = %d\n\n", result);
#endif
        }

        if (applyVector)
        {
            applyVector=0;


            if (testSeed)
            {
                testSeed=0;

                // CSPRNG
                csprng RNG;

                // initialise strong RNG
                CREATE_CSPRNG(&RNG,&SEEDGOLDEN);

                rc = PAILLIER_KEY_PAIR(&RNG, &P1, &Q1, &N1, &G1, &L1, &M1);
                if (rc)
                {
                    fprintf(stderr, "FAILURE PAILLIER_KEY_PAIR Test %d rc: %d\n", testNo, rc);
                    fclose(fp);
                    exit(EXIT_FAILURE);
                }

#ifdef DEBUG
                printf("P1: ");
                OCT_output(&P1);
                printf("\n");
                printf("Q1: ");
                OCT_output(&Q1);
                printf("\n");

                printf("Public Key \n");
                printf("N1: ");
                OCT_output(&N1);
                printf("\n");
                printf("G1: ");
                OCT_output(&G1);
                printf("\n");

                printf("Secret Key \n");
                printf("L1: ");
                OCT_output(&L1);
                printf("\n");
                printf("M1: ");
                OCT_output(&M1);
                printf("\n");
#endif

                // OCT_comp returns 1 for equal
                rc = !(OCT_comp(&PGOLDEN,&P1));
                if(rc != result)
                {
                    fprintf(stderr, "FAILURE Test %d PGOLDEN rc: %d\n", testNo, rc);
                    fclose(fp);
                    exit(EXIT_FAILURE);
                }

                rc = !(OCT_comp(&QGOLDEN,&Q1));
                if(rc != result)
                {
                    fprintf(stderr, "FAILURE Test %d QGOLDEN rc: %d\n", testNo, rc);
                    fclose(fp);
                    exit(EXIT_FAILURE);
                }

                rc = !(OCT_comp(&NGOLDEN,&N1));
                if(rc != result)
                {
                    fprintf(stderr, "FAILURE Test %d NGOLDEN rc: %d\n", testNo, rc);
                    fclose(fp);
                    exit(EXIT_FAILURE);
                }

                rc = !(OCT_comp(&GGOLDEN,&G1));
                if(rc != result)
                {
                    fprintf(stderr, "FAILURE Test %d GGOLDEN rc: %d\n", testNo, rc);
                    fclose(fp);
                    exit(EXIT_FAILURE);
                }

                rc = !(OCT_comp(&LGOLDEN,&L1));
                if(rc != result)
                {
                    fprintf(stderr, "FAILURE Test %d LGOLDEN rc: %d\n", testNo, rc);
                    fclose(fp);
                    exit(EXIT_FAILURE);
                }

                rc = !(OCT_comp(&MGOLDEN,&M1));
                if(rc != result)
                {
                    fprintf(stderr, "FAILURE Test %d MGOLDEN rc: %d\n", testNo, rc);
                    fclose(fp);
                    exit(EXIT_FAILURE);
                }

            }


            rc = PAILLIER_KEY_PAIR(NULL, &PGOLDEN, &QGOLDEN, &N2, &G2, &L2, &M2);
            if (rc)
            {
                fprintf(stderr, "FAILURE PAILLIER_KEY_PAIR Test %d rc: %d\n", testNo, rc);
                fclose(fp);
                exit(EXIT_FAILURE);
            }

#ifdef DEBUG
            printf("Public Key \n");
            printf("N2: ");
            OCT_output(&N2);
            printf("\n");
            printf("G2: ");
            OCT_output(&G2);
            printf("\n");

            printf("Secret Key \n");
            printf("L2: ");
            OCT_output(&L2);
            printf("\n");
            printf("M2: ");
            OCT_output(&M2);
            printf("\n");
#endif
            rc = !(OCT_comp(&NGOLDEN,&N2));
            if(rc != result)
            {
                fprintf(stderr, "FAILURE Test %d NGOLDEN rc: %d\n", testNo, rc);
                fclose(fp);
                exit(EXIT_FAILURE);
            }

            rc = !(OCT_comp(&GGOLDEN,&G2));
            if(rc != result)
            {
                fprintf(stderr, "FAILURE Test %d GGOLDEN rc: %d\n", testNo, rc);
                fclose(fp);
                exit(EXIT_FAILURE);
            }

            rc = !(OCT_comp(&LGOLDEN,&L2));
            if(rc != result)
            {
                fprintf(stderr, "FAILURE Test %d LGOLDEN rc: %d\n", testNo, rc);
                fclose(fp);
                exit(EXIT_FAILURE);
            }

            rc = !(OCT_comp(&MGOLDEN,&M2));
            if(rc != result)
            {
                fprintf(stderr, "FAILURE Test %d MGOLDEN rc: %d\n", testNo, rc);
                fclose(fp);
                exit(EXIT_FAILURE);
            }


        }
    }
    fclose(fp);
    printf("SUCCESS TEST PAILLIER KEYGEN PASSED\n");
    exit(EXIT_SUCCESS);
}

