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
#include <stdlib.h>
#include <crypto_context.h>

/* @brief  Create a new encryption context assigning the loader
*  @param  encryption_mode  Mode of encryption (ECB, CBC, CFB, CTR)
*  @param  loader           Init function to be used for parsing the vector file.
*/
crypto_context_t *new_context(encryption_mode mode,
			      void (*loader) (crypto_context_t *))
{
	crypto_context_t *ctx = calloc(1, sizeof(struct crypto_context));
	ctx->parse_vector_file = loader;
	ctx->mode = mode;
	return ctx;
}

/*
* @brief Delete the memory for crypto context
* @param ctx Context to be used.
*/
void delete_context(crypto_context_t * ctx)
{
	free(ctx->ciphertext);
	free(ctx->key);
	free(ctx->init_vector);
}

/*
* @brief Convert the encryption mode to an integer;
* @param mode encryption_mode Mode of encryption (ECB, CBC, CFB, CTR)
*/
int convert_mode(encryption_mode mode)
{
	return (int)mode;
}

/*
 * @brief Compute the block_size foreach algorithm;
 * @param algo   Block Cipher Algorithm name
 * @param mode   Mode for encryption
 */
size_t get_block_size(char *algo, encryption_mode mode)
{
	if (!strcmp("aes", algo)) {
		// we are aes
		switch (mode) {
		case cbc_mode:
		case ecb_mode:
		case ctr_mode:
			{
				return 16;
			}
		case cfb_mode:
			{
				return 1;
			}
		}
	}
	return 16;
}
