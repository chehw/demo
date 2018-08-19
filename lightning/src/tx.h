#ifndef _TX_H_
#define _TX_H_

#include <stdio.h>
#include <stdint.h>

#include "satoshi-types.h"
#include "satoshi-script.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct raw_txin raw_txin_t;
enum raw_txin_type
{
	raw_txin_type_p2pkh = 0,
	raw_txin_type_p2sh = 1,
};
struct raw_txin
{
	struct
	{
		uint8_t prev_hash[32];
		uint32_t index;
	}outpoint;
	union
	{
		unsigned char sig_script[4096];
		varstr_t vsig_script;
	};
	size_t cb_sig_script;
	
	enum raw_txin_type type;
	union
	{
		unsigned char redeem_script[100];
		varstr_t vredeem_script;
	};
	size_t cb_redeem_script;
	
	unsigned char sig[100];
	size_t cb_sig;
	
	uint32_t hash_type;
	
	unsigned char pubkey[MAX_SCRIPT_ELEMENT_SIZE];	/* pubkey or p2sh script */
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

size_t parse_tx_v1(const unsigned char * tx, 
	size_t tx_size, 
	satoshi_raw_tx_t * raw_tx);
void satoshi_raw_tx_dump(satoshi_raw_tx_t * raw_tx);

#ifdef __cplusplus
}
#endif
#endif
