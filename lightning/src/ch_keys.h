#ifndef _CH_KEYS_H_
#define _CH_KEYS_H_

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct ch_key
{
	unsigned char priv_key[32];
	unsigned char pub_key[72]; /* (65 + 7): 8 bytes align */
	size_t cb_pubkey;
	size_t flags; /* 0=compressed; 1=uncompressed */
}ch_keys_t;


ch_keys_t * ch_keys_new(ch_keys_t * keys, unsigned char * sec_key);
void ch_keys_cleanup(ch_keys_t * keys);

int ch_keys_context_get_tid();

#ifdef __cplusplus
}
#endif
#endif
