/*
* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef CRYPTO_CONTEXT
#define CRYPTO_CONTEXT 
#include <stdlib.h>
#define CRYPTO_VEC_PATH_MAX 256
typedef enum e_mode 
{
    ecb_mode,
    cbc_mode,
    cfb_mode,
    ctr_mode
} encryption_mode;
typedef struct crypto_context
{
   char* ciphertext;                    /*<!-- Ciphertext to be compared */
   size_t ciphertext_length;            /*<!-- Ciphertext lenght */
   char filename[CRYPTO_VEC_PATH_MAX];  /*<!-- Path of the vector test filename */
   char* key;                           /*<!-- Key to be used */
   size_t key_length;                   /*<!-- Key length */
   char* init_vector;                   /*<!-- IV */
   size_t init_vector_length;           /*<!-- Vector length */
   encryption_mode mode;                 /*<!-- Kind of encryption mode */
   void (*parse_vector_file)(struct crypto_context* self); /*<!-- function for loading 
                                                                  the file and init the structure */
} crypto_context_t;

/* @brief  Create a new encryption context assigning the loader
*  @param  encryption_mode  Mode of encryption (ECB, CBC, CFB, CTR)
*  @param  loader           Init function to be used for parsing the vector file.
*/
extern crypto_context_t* new_context(encryption_mode mode, void (*loader)(crypto_context_t*));
/*
* @brief Delete the memory for crypto context
* @param ctx Context to be used.
*/
extern void delete_context(crypto_context_t* ctx);
/*
* @brief Convert the encryption mode to an integer;
* @param mode encryption_mode Mode of encryption (ECB, CBC, CFB, CTR)
*/
extern int convert_mode(encryption_mode mode);
/*
 * @brief Compute the block_size foreach algorithm;
 * @param algo   Block Cipher Algorithm name
 * @param mode   Mode for encryption
 */
extern size_t get_block_size(char* algo, encryption_mode mode);
#endif
