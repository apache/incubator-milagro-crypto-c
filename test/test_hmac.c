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
        printf("usage: ./test_hmac [path to test vector file]\n");
        exit(EXIT_FAILURE);
    }

    // For tests related to the incremental API
    hmac_sha256 ctx;

    // Variables for file parsing
    FILE *fp = NULL;
    char line[LINE_LEN];
    const char *linePtr = NULL;
    int l1 = 0;
    bool readLine = false;
    int lineNo = 0;
    const char *KeyStr = "Key = ";
    const char *MsgStr = "Msg = ";
    const char *MacStr = "Mac = ";
    char *Key = NULL;
    char *Msg = NULL;
    char *Mac = NULL;
    char *Out = NULL;
    int KeyLen = 0;
    int MsgLen = 0;
    int MacLen = 0;
    int ret = 0;
    int cmp = 0;

    // Open file
    fp = fopen(argv[1], "r");
    if (fp == NULL) {
        printf("ERROR opening test vector file\n");
        exit(EXIT_FAILURE);
    }

    while (fgets(line, LINE_LEN, fp) != NULL) {
        readLine = true;
        // Read the authentication key
        if (!strncmp(line, KeyStr, strlen(KeyStr))) {
#ifdef DEBUG
            printf("line %d %s\n", lineNo,line);
#endif
            // Find hex value in string
            linePtr = line + strlen(KeyStr);
            // Allocate memory
            l1      = (int)strlen(linePtr) - 2;
            KeyLen  = l1 / 2;
            Key     = (char*) malloc(KeyLen);
            if (Key == NULL)
                exit(EXIT_FAILURE);
            // Key binary value
            amcl_hex2bin(linePtr, Key, l1);
            ret |= HMAC_SHA256_init(&ctx, Key, KeyLen);
        }

        // Read the message to authenticate
        if (!strncmp(line, MsgStr, strlen(MsgStr))) {
#ifdef DEBUG
            printf("line %d %s\n", lineNo,line);
#endif
            // Find hex value in string
            linePtr = line + strlen(MsgStr);
            // Allocate memory
            l1      = (int)strlen(linePtr) - 2;
            MsgLen  = l1 / 2;
            Msg     = (char*) malloc(MsgLen);
            if (Msg == NULL)
                exit(EXIT_FAILURE);
            // Msg binary value
            amcl_hex2bin(linePtr, Msg, l1);
            ret |= HMAC_SHA256_update(&(ctx.sha256_ctx), Msg, MsgLen);
        }

        // Read the message authentication code
        if (!strncmp(line, MacStr, strlen(MacStr))) {
#ifdef DEBUG
            printf("line %d %s\n", lineNo,line);
#endif
            // Find hex value in string
            linePtr = line + strlen(MacStr);
            // Allocate memory
            l1      = (int)strlen(linePtr) - 2;
            MacLen  = l1 / 2;
            Mac     = (char*) malloc(MacLen);
            Out     = (char*) malloc(MacLen);
            if (Mac == NULL || Out == NULL)
                exit(EXIT_FAILURE);
            octet MacOct = {MacLen, MacLen, Mac};
            // Mac binary value
            amcl_hex2bin(linePtr, Mac, l1);

            // Recompute the HMAC value (incremental API)
            ret |= HMAC_SHA256_final(&ctx, Out, MacLen);
            octet OutOct_incr = {MacLen, MacLen, Out};
            cmp = OCT_comp(&MacOct, &OutOct_incr);
            if (!cmp || ret) {
                printf("TEST HMAC_INCR FAILED COMPARE MAC LINE %d\n",lineNo);
                exit(EXIT_FAILURE);
            }

            // Recompute the HMAC value (one-shot API)
            ret = HMAC_SHA256_oneshot(Out, MacLen, Key, KeyLen, Msg, MsgLen);
            // Check that it matches the expected value
            octet OutOct_oneshot = {MacLen, MacLen, Out};
            cmp = OCT_comp(&MacOct, &OutOct_oneshot);
            if (!cmp || ret) {
                printf("TEST HMAC_ONESHOT FAILED COMPARE MAC LINE %d\n",lineNo);
                exit(EXIT_FAILURE);
            }
            free(Key);
            free(Msg);
            free(Mac);
            free(Out);
            Key = NULL;
            Msg = NULL;
            Mac = NULL;
            Out = NULL;
        }
        lineNo++;
    }
    fclose(fp);
    if (!readLine) {
        printf("ERROR No test vectors\n");
        exit(EXIT_FAILURE);
    }
    printf("SUCCESS TEST HMAC-SHA256 PASSED\n");
    exit(EXIT_SUCCESS);
}
