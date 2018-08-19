/*
 * ch_keys.c
 * 
 * Copyright 2018 Che Hongwei <htc.chehw@gmail.com>
 * 
 * The MIT License (MIT)
 * 
 * Permission is hereby granted, free of charge, to any person 
 * obtaining a copy of this software and associated documentation 
 * files (the "Software"), to deal in the Software without restriction, 
 * including without limitation the rights to use, copy, modify, merge, 
 * publish, distribute, sublicense, and/or sell copies of the Software, 
 * and to permit persons to whom the Software is furnished to do so, 
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included
 *  in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES 
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, 
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR 
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR 
 * THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 * 
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>



#include "ch_keys.h"

#include <secp256k1.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <pthread.h>

static pthread_key_t tls;	/* thread local storage */
static pthread_once_t key_once = PTHREAD_ONCE_INIT;

typedef struct ch_keys_context
{
	secp256k1_context * secp;
	unsigned int err_code;
	pthread_t tid;
}ch_keys_context_t;

static ch_keys_context_t * ch_keys_context_new()
{
	ch_keys_context_t * ctx = calloc(1, sizeof(ch_keys_context_t));
	assert(NULL != ctx);
	
	secp256k1_context * secp = secp256k1_context_create(
		SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
	assert(NULL != secp);
	
	ctx->secp = secp;
	return ctx;
}

static void ch_keys_context_free(ch_keys_context_t * ctx)
{
	if(NULL == ctx) return;
	if(ctx->secp)
	{
		secp256k1_context_destroy(ctx->secp);
		ctx->secp = NULL;
	}
	free(ctx);
	pthread_setspecific(tls, NULL);
	return;
}


static void init_tls()
{
	pthread_key_create(&tls, (void (*)(void *))ch_keys_context_free);
}
__attribute__((constructor))
static void init()
{
	(void)pthread_once(&key_once, init_tls);
}

static void set_error(unsigned int err_code)
{
	ch_keys_context_t * ctx = pthread_getspecific(tls);
	if(NULL == ctx)
	{
		ctx = ch_keys_context_new();
		assert(NULL != ctx);
		pthread_setspecific(tls, ctx);
	}
	ctx->err_code = err_code;
}

static ch_keys_context_t * get_context()
{
	ch_keys_context_t * ctx = pthread_getspecific(tls);
	if(NULL == ctx)
	{
		ctx = ch_keys_context_new();
		assert(NULL != ctx);
		
		ctx->tid = pthread_self();
	}
	return ctx;
}

int ch_keys_context_get_tid()
{
	ch_keys_context_t * ctx = get_context();
	if(ctx)
	{
		return (int)ctx->tid;
	}
	return -1;
}

ch_keys_t * ch_keys_new(ch_keys_t * keys, unsigned char * sec_key)
{
	int rc = 0;
	ch_keys_context_t * ctx = get_context();
	assert(NULL != ctx);
	
	if(NULL == keys) keys = calloc(1, sizeof(ch_keys_t));
	assert(NULL != keys);
	
	unsigned char * priv_key = keys->priv_key;
	
	if(sec_key) memcpy(priv_key, sec_key, 32);
	else
	{
		rc = RAND_bytes(priv_key, 32);
		if(rc <= 0) /* the PRNG has not been seeded with enough randomness to ensure an unpredictable byte sequence. */
		{
			set_error(ERR_get_error());
			return NULL;
		}
	}
	
	secp256k1_context * secp = ctx->secp;
	secp256k1_pubkey pubkey;
	rc = secp256k1_ec_pubkey_create(secp, &pubkey, priv_key);
	
	if(rc <= 0)	/* calc pubkey failed */
	{
		memset(priv_key, 0, 32);	/* clear sensitive data */
		free(keys);
		return NULL;
	}
	
	keys->cb_pubkey = sizeof(keys->pub_key);
	rc = secp256k1_ec_pubkey_serialize(secp, keys->pub_key, &keys->cb_pubkey,
		&pubkey, keys->flags?SECP256K1_EC_UNCOMPRESSED:SECP256K1_EC_COMPRESSED);
	if(rc <= 0)
	{
		memset(priv_key, 0, 32);	/* clear sensitive data */
		free(keys);
		return NULL;
	}
	
	return keys;
}
void ch_keys_cleanup(ch_keys_t * keys)
{
	if(keys)
	{
		memset(keys->priv_key, 0, 32);	/* clear sensitive data */
		free(keys);
	}
}
