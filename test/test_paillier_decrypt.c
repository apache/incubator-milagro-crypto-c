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

    int applyVector=0;

    const char* TESTline = "TEST = ";
    int testNo=0;

    // Test result
    int result=0;
    const char* RESULTline = "RESULT = ";

    char pt[FS_2048]= {0};
    octet PT = {0,sizeof(pt),pt};

    char ngolden[FS_2048]= {0};
    octet NGOLDEN = {0,sizeof(ngolden),ngolden};
    const char* Nline = "N = ";

    char lgolden[FS_2048] = {0};
    octet LGOLDEN = {0,sizeof(lgolden),lgolden};
    const char* Lline = "L = ";

    char mgolden[FS_2048]= {0};
    octet MGOLDEN = {0,sizeof(mgolden),mgolden};
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
            printf("TEST = %d\n",testNo);
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

        // Read PLAINTEXT
        if (!strncmp(line,PTline, strlen(PTline)))
        {
            len = strlen(PTline);
            linePtr = line + len;
            read_OCTET(&PTGOLDEN,linePtr);
#ifdef DEBUG
            printf("PLAINTEXT = ");
            OCT_output(&PTGOLDEN);
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

            int rc = PAILLIER_DECRYPT(&NGOLDEN, &LGOLDEN, &MGOLDEN, &CTGOLDEN, &PT);
            if (rc)
            {
                fprintf(stderr, "FAILURE PAILLIER_DECRYPT Test %d rc: %d\n", testNo, rc);
                fclose(fp);
                exit(EXIT_FAILURE);
            }

#ifdef DEBUG
            printf("PT: ");
            OCT_output(&PT);
            printf("\n");
#endif

            // OCT_comp return 1 for equal
            rc = !(OCT_comp(&PTGOLDEN,&PT));
            if(rc != result)
            {
#ifdef DEBUG
                printf("PTGOLDEN: ");
                OCT_output(&PTGOLDEN);
                printf("\n");
#endif
                fprintf(stderr, "FAILURE Test %d rc: %d\n", testNo, rc);
                fclose(fp);
                exit(EXIT_FAILURE);
            }
        }
    }
    fclose(fp);
    printf("SUCCESS TEST PAILLIER DECRYPTION PASSED\n");
    exit(EXIT_SUCCESS);
}

