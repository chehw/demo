#ifndef _TX_H_
#define _TX_H_

#include <stdio.h>
#include <stdint.h>

#include "satoshi-types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct raw_txin raw_txin_t;
struct raw_txin
{
	struct
	{
		uint8_t prev_hash[32];
		uint32_t index;
	}outpoint;
	
	unsigned char sig_script[4096];
	size_t cb_sig_script;
	
	unsigned char redeem_script[100];
	size_t cb_redeem_script;
	
	unsigned char sig[100];
	size_t cb_sig;
	
	uint32_t hash_type;
	
	unsigned char pubkey[65];
	size_t cb_pubkey;
	
	uint32_t sequence;
};

typedef struct satoshi_raw_tx
{
	int32_t version;
	size_t txin_count;
	raw_txin_t * txins;
//	size_t txout_count;
	unsigned char * txouts_data;
	size_t cb_txouts;
	
	size_t txout_count;
	satoshi_txout_t * txouts;
	uint32_t lock_time;
}satoshi_raw_tx_t;



#ifdef __cplusplus
}
#endif
#endif
