#ifndef _SHA512_H_
#define _SHA512_H_

#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef struct sha512_ctx
{
	uint64_t s[8];
	unsigned char buf[128];
	size_t bytes;
}sha512_ctx_t;

void sha512_init(sha512_ctx_t * sha);
void sha512_update(sha512_ctx_t * sha, const void * data, size_t len);
void sha512_final(sha512_ctx_t * sha, unsigned char hash[64]);


typedef struct hmac_sha512
{
	sha512_ctx_t outer;
	sha512_ctx_t inner;	
}hmac_sha512_t;

void hmac_sha512_init(hmac_sha512_t * hmac, const unsigned char * key, size_t keylen);
void hmac_sha512_update(hmac_sha512_t * hmac, const unsigned char * data, size_t len);
void hmac_sha512_final(hmac_sha512_t * hmac, unsigned char hash[64]);

#define hmac512(key, keylen, data, size, hash) do { \
		hmac_sha512_t hmac[1]; \
		hmac_sha512_init(hmac, (unsigned char *)key, keylen); \
		hmac_sha512_update(hmac, data, size); \
		hmac_sha512_final(hmac, hash); \
	} while(0)

#ifdef __cplusplus
}
#endif
#endif
