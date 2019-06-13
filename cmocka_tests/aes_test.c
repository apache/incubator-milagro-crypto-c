/**
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
#include <arch.h>
#include <amcl.h>
#include <setjmp.h> 
#include <cmocka.h>
#include <aes_test.h>
#include <crypto_context.h>

int aes_setup(void **state)
{
	crypto_context_t* context = calloc(1, sizeof(crypto_context_t));    
  	*state = context;
	return 0;
}

int aes_teardown(void **state)
{
	crypto_context_t* context = *state;
	free(context);
	return 0;
}

void should_encrypt_aes_ecb_128_correctly(void **state)
{
	crypto_context_t *ctx = *state;
	assert_non_null(ctx);
	ctx->mode = encrypt
}

void should_fail_aes_ecb_128_with_invalidkey(void **state)
{

}

void should_encrypt_aes_cbc_128_correctly(void **state)
{
}

void should_encrypt_aes_ctr_128_correctly(void **state)
{
}

void should_encrypt_aes_cfb_1_correctly(void **state)
{
}

static void
test_encryption_aes(struct crypto_context *context,
		    char *plain_text, size_t plain_text_size)
{
	// arrange test
	amcl_aes block_cipher;
	uint8_t valid_aes_init;
	int i = 0;
	size_t block_size = get_block_size("aes",context->mode);
	size_t n_blocks = plain_text_size / block_size;
	valid_aes_init = AES_init(&block_cipher,
				  convert_mode(context->mode),
				  context->key_length,
				  context->key, context->init_vector);
	// act & assert.
	for (i = 0; i < n_blocks; i++) {
		AES_encrypt(&block_cipher, &plain_text[i * block_size]);
	}
	octet ciphertext_octect =
	    { plain_text_size, plain_text_size, plain_text };
	octet expected_ciphertext = { context->ciphertext_length,
		context->ciphertext_length,
		context->ciphertext
	};
	int ret = OCT_comp(&expected_ciphertext, &ciphertext_octect);
	assert_int_equal(1, ret);

}
