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
/**
 * @file    test_hmac.c
 * 
 * @author  Alexandre Adomnicai <alexandre.adomnicai@qredo.com>
 * 
 * @brief   Tests for HMAC-SHA256 algorithm.
 *
 */

#include "arch.h"
#include "amcl.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define LINE_LEN 500
//#define DEBUG

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        printf("usage: ./test_hkdf [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    // Variables for file parsing
    FILE *fp = NULL;
    char line[LINE_LEN];
    const char *linePtr = NULL;
    int l1 = 0;
    bool readLine = false;
    int lineNo = 0;
    const char *IKMStr  = "IKM = ";
    const char *SaltStr = "salt = ";
    const char *InfoStr = "info = ";
    const char *PRKStr  = "PRK = ";
    const char *OKMStr  = "OKM = ";
    char *IKM   = NULL;
    char *Salt  = NULL;
    char *Info  = NULL;
    char *PRK   = NULL;
    char *OKM   = NULL;
    char *OutPRK = NULL;
    char *OutOKM = NULL;
    int IKMLen  = 0;
    int SaltLen = 0;
    int InfoLen = 0;
    int PRKLen  = 0;
    int OKMLen  = 0;
    int ret     = 0;
    int cmp     = 0;

    // Open file
    fp = fopen(argv[1], "r");
    if (fp == NULL) {
        printf("ERROR opening test vector file\n");
        exit(EXIT_FAILURE);
    }

    while (fgets(line, LINE_LEN, fp) != NULL) {
        readLine = true;
        // Read the authentication key
        if (!strncmp(line, IKMStr, strlen(IKMStr))) {
            // Find hex value in string
            linePtr = line + strlen(IKMStr);
            // Allocate memory
            l1      = (int)strlen(linePtr) - 1;
            IKMLen  = l1 / 2;
            IKM     = (char*) malloc(IKMLen);
            if (IKM == NULL)
                exit(EXIT_FAILURE);
            // Key binary value
            amcl_hex2bin(linePtr, IKM, l1);
#ifdef DEBUG
            printf("line %d %s\n", lineNo,line);
            printf("IKMLen = %d\n", IKMLen);
#endif
        }

        // Read the message to authenticate
        if (!strncmp(line, SaltStr, strlen(SaltStr))) {
            // Find hex value in string
            linePtr = line + strlen(SaltStr);
            // Allocate memory
            l1      = (int)strlen(linePtr) - 1;
            SaltLen = l1 / 2;
            Salt    = (char*) malloc(SaltLen);
            if (Salt == NULL)
                exit(EXIT_FAILURE);
            // Msg binary value
            amcl_hex2bin(linePtr, Salt, l1);
#ifdef DEBUG
            printf("line %d %s\n", lineNo,line);
            printf("SaltLen = %d\n", SaltLen);
#endif
        }

        // Read the message to authenticate
        if (!strncmp(line, InfoStr, strlen(InfoStr))) {
            // Find hex value in string
            linePtr = line + strlen(InfoStr);
            // Allocate memory
            l1      = (int)strlen(linePtr) - 1;
            InfoLen = l1 / 2;
            Info    = (char*) malloc(InfoLen);
            if (Info == NULL)
                exit(EXIT_FAILURE);
            // Msg binary value
            amcl_hex2bin(linePtr, Info, l1);
#ifdef DEBUG
            printf("line %d %s\n", lineNo,line);
            printf("InfoLen = %d\n", InfoLen);
#endif
        }

        // Read the message to authenticate
        if (!strncmp(line, PRKStr, strlen(PRKStr))) {
            // Find hex value in string
            linePtr = line + strlen(PRKStr);
            // Allocate memory
            l1      = (int)strlen(linePtr) - 1;
            PRKLen  = l1 / 2;
            PRK     = (char*) malloc(PRKLen);
            OutPRK  = (char*) malloc(PRKLen);
            if (PRK == NULL || OutPRK == NULL)
                exit(EXIT_FAILURE);
            // Msg binary value
            amcl_hex2bin(linePtr, PRK, l1);
#ifdef DEBUG
            printf("line %d %s\n", lineNo,line);
            printf("PRKLen = %d\n", PRKLen);
#endif
        }

        // Read the message authentication code
        if (!strncmp(line, OKMStr, strlen(OKMStr))) {
            // Find hex value in string
            linePtr = line + strlen(OKMStr);
            // Allocate memory
            l1      = (int)strlen(linePtr) - 1;
            OKMLen  = l1 / 2;
            OKM     = (char*) malloc(OKMLen);
            OutOKM  = (char*) malloc(OKMLen);
            if (OKM == NULL || OutOKM == NULL)
                exit(EXIT_FAILURE);
            octet PRKOct = {PRKLen, PRKLen, PRK};
            octet OKMOct = {OKMLen, OKMLen, OKM};
            // Mac binary value
            amcl_hex2bin(linePtr, OKM, l1);
#ifdef DEBUG
            printf("line %d %s\n", lineNo,line);
            printf("OKMLen = %d\n", OKMLen);
#endif

            // Recompute the HKDF-extract output
            ret = HKDF_SHA256_extract(OutPRK, Salt, SaltLen, IKM, IKMLen);
            // Check that it matches the expected value
            octet OutPRKOct = {PRKLen, PRKLen, OutPRK};
            cmp = OCT_comp(&PRKOct, &OutPRKOct);
            if (!cmp || ret) {
                printf("TEST HKDF_SHA256_extract FAILED COMPARE MAC LINE %d\n",lineNo);
                exit(EXIT_FAILURE);
            }
            // Recompute the HKDF-expand output
            ret = HKDF_SHA256_expand(OutOKM, OKMLen, OutPRK, PRKLen, Info, InfoLen);
            // Check that it matches the expected value
            octet OutOKMOct = {OKMLen, OKMLen, OutOKM};
            cmp = OCT_comp(&OKMOct, &OutOKMOct);
            if (!cmp || ret) {
                printf("TEST HKDF_SHA256_expand FAILED COMPARE MAC LINE %d\n",lineNo);
                exit(EXIT_FAILURE);
            }
            free(IKM);
            free(Salt);
            free(Info);
            free(PRK);
            free(OKM);
            free(OutPRK);
            free(OutOKM);
            IKM = NULL;
            Salt = NULL;
            Info = NULL;
            PRK = NULL;
            OKM = NULL;
            OutPRK = NULL;
            OutOKM = NULL;
        }
        lineNo++;
    }
    fclose(fp);
    if (!readLine) {
        printf("ERROR No test vectors\n");
        exit(EXIT_FAILURE);
    }
    printf("SUCCESS TEST HKDF-SHA256 PASSED\n");
    exit(EXIT_SUCCESS);
}
