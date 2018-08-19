#ifndef _SHA256_H_
#define _SHA256_H_

#include <stdint.h>
#include <stdlib.h>


typedef struct sha256_ctx
{
	uint32_t s[8];
	unsigned char buf[64];
	size_t bytes;
}sha256_ctx_t;


#ifdef __cplusplus
extern "C" {
#endif
void sha256_init(sha256_ctx_t * sha);
void sha256_update(sha256_ctx_t * sha, const unsigned char * data, size_t len);
void sha256_final(sha256_ctx_t * sha, unsigned char hash[32]);

typedef struct hmac_sha256
{
	sha256_ctx_t outer;
	sha256_ctx_t inner;	
}hmac_sha256_t;

void hmac_sha256_init(hmac_sha256_t * hmac, const unsigned char * key, size_t keylen);
void hmac_sha256_update(hmac_sha256_t * hmac, const unsigned char * data, size_t len);
void hmac_sha256_final(hmac_sha256_t * hmac, unsigned char hash[32]);

#ifdef __cplusplus
}
#endif
#endif
