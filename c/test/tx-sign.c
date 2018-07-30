/*
 * tx-sign.c
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
 * tx-sign
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

#include <stdint.h>

#include "sha256.h"
#include "base58.h"
#include "utils.h"
#include "satoshi-types.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <gmp.h> 
#include <secp256k1.h>





#define MAX_TX_BUFFER_SIZE (65536)

static inline void dump_mpz(const char * prefix, mpz_t m)
{
	unsigned char buf[100];
	size_t cb_buf = sizeof(buf);
	mpz_export(buf, &cb_buf, 1, 1, 1, 0, m);
	dump_line(stdout, prefix, buf, cb_buf);	
}

/* 
 * bitcoin address: 1xxxxxxx 
 * 	type: pay to public key hash
 *  
 */
static int p2pkh_to_redeem_script(varstr_t * vpub, unsigned char * redeem_script, size_t * cb_redeem_script)
{
	static unsigned char prefix[] = {	/* p2pkh script prefix */
		0x19,	 /* script length = 25 bytes */
		0x76, 	/* OP_DUP */
		0xa9, 	/* OP_HASH160 */
		0x14	/* OP_PUSH 20 bytes */
	};
	
	static unsigned char suffix[] = 
	{
		0x88,	/* OP_EQUALVERIFY */
		0xac	/* OP_CHECKSIG */
	};
	
	unsigned char * dst = redeem_script;
	 
	unsigned char hash[20];
	unsigned char * pubkey = (unsigned char *)varstr_get(vpub);
	size_t cb_pubkey = varstr_strlen(vpub);	
	hash160(pubkey, cb_pubkey, hash);
	
	
	memcpy(dst, prefix, sizeof(prefix));
	dst += sizeof(prefix);
	
	memcpy(dst, hash, sizeof(hash));
	dst += sizeof(hash);
	 
	memcpy(dst, suffix, sizeof(suffix));
	dst += sizeof(suffix);
	
	*cb_redeem_script = dst - redeem_script;
	return 0;
}

typedef struct raw_txin raw_txin_t;
struct raw_txin
{
	struct
	{
		uint8_t prev_hash[32];
		uint32_t index;
	}outpoint;
	
	unsigned char redeem_script[100];
	size_t cb_redeem_script;
	
	unsigned char sig[100];
	size_t cb_sig;
	
	uint32_t hash_type;
	
	unsigned char pubkey[65];
	size_t cb_pubkey;
	
	uint32_t sequence;
}__attribute__((packed));

typedef struct satoshi_raw_tx
{
	int32_t version;
	size_t txin_count;
	raw_txin_t * txins;
//	size_t txout_count;
	unsigned char * txouts_data;
	size_t cb_txouts;
//	uint32_t lock_time;
}satoshi_raw_tx_t;


void satoshi_raw_tx_cleanup(satoshi_raw_tx_t * raw_tx)
{
	if(raw_tx)
	{
		free(raw_tx->txins);
		free(raw_tx->txouts_data);
	}
}

int satoshi_raw_tx_get_preimage(satoshi_raw_tx_t * raw_tx, int index, unsigned char preimage[], size_t * cb_preimage)
{
	assert(index >= 0 && index < raw_tx->txin_count);
	unsigned char * dst = preimage;
	
	unsigned char * p_end = preimage + (*cb_preimage);
	
	*(int32_t *)dst = raw_tx->version; dst += sizeof(int32_t);
	varint_set((varint_t *)dst, raw_tx->txin_count);
	dst += varint_size((varint_t *)dst);
	
	uint32_t hash_type = 1;
	
	for(size_t i = 0; i < raw_tx->txin_count; ++i)
	{
		raw_txin_t * txin = &raw_tx->txins[i];
		memcpy(dst, &txin->outpoint, sizeof(satoshi_outpoint_t));
		dst += sizeof(satoshi_outpoint_t);
		
		
		if(i == index)	/* 如果是当前准备签名（或验证）的txin，就附加其公钥对应的[redeem_script] */
		{
			memcpy(dst, txin->redeem_script, txin->cb_redeem_script);
			dst += txin->cb_redeem_script;
			
			hash_type = txin->hash_type;
		}else /* 否则，将此处的脚本长度设为0 */
		{
			*dst++ = 0;
		}
		
		*(uint32_t *)dst = txin->sequence;
		dst += sizeof(uint32_t);
		assert(dst < p_end);
	}
	
	memcpy(dst, raw_tx->txouts_data, raw_tx->cb_txouts);
	dst += raw_tx->cb_txouts;
	assert(dst < p_end);
	
	*(uint32_t *)dst = hash_type;
	dst += sizeof(uint32_t);
	
	assert(dst <= p_end);
	
	*cb_preimage = (dst - preimage);
	return 0;
}

/* 
 * parse_tx:
 * 	parse binary tx data and generate prehash image (raw_tx) 
 */
static size_t parse_tx_v1(const unsigned char * tx, 
	size_t tx_size, 
	satoshi_raw_tx_t * raw_tx)
{
	assert(NULL != tx && tx_size > 100 && NULL != raw_tx);
	
	const unsigned char * src = tx;
	const unsigned char * p_end = tx + tx_size;
	
	// tx version
	raw_tx->version = *(int32_t *)src;	src += sizeof(int32_t);
	
	raw_tx->txin_count	= varint_get((varint_t *)src);
	src += varint_size((varint_t *)src);
	
	assert(raw_tx->txin_count > 0);
	
	/* parse txins */
	raw_tx->txins = (raw_txin_t *)calloc(raw_tx->txin_count, sizeof(raw_txin_t));
	
	for(size_t i = 0; i < raw_tx->txin_count; ++i)
	{
		raw_txin_t * txin = & raw_tx->txins[i];
		
		// copy outpoint
		memcpy(&txin->outpoint, src, sizeof(satoshi_outpoint_t));
		src += sizeof(satoshi_outpoint_t);
		
		// parse signature / hashtype / pubkey
		varstr_t * vsig_pubkey = (varstr_t *)src;
		varstr_t * vsig_hashtype = (varstr_t *)((unsigned char *)vsig_pubkey + varint_size((varint_t *)vsig_pubkey));	
		unsigned  char * sig_der = (unsigned char *)vsig_hashtype + varint_size((varint_t *)vsig_hashtype);
		
		/* copy signature */
		txin->cb_sig = varstr_strlen(vsig_hashtype) - 1;
		memcpy(txin->sig, sig_der, txin->cb_sig);
		
		/* get hash type */
		txin->hash_type = sig_der[txin->cb_sig];
		varstr_t * vpub = (varstr_t *)((unsigned char *)vsig_hashtype + varstr_size(vsig_hashtype));
		
		/* copy pubkey */
		txin->cb_pubkey = varstr_strlen(vpub);
		memcpy(txin->pubkey, varstr_get(vpub), txin->cb_pubkey);
		src += varstr_size(vsig_pubkey); // skip signature and pubkey
		
		/* calc redeem script */
		p2pkh_to_redeem_script(vpub, txin->redeem_script, &txin->cb_redeem_script);
		
		/* copy sequence */
		txin->sequence = *(uint32_t *)src; 
		src += sizeof(uint32_t);		
	}
	assert(src < p_end);
	
	raw_tx->cb_txouts = p_end - src;
	raw_tx->txouts_data = malloc(raw_tx->cb_txouts);
	assert(NULL != raw_tx->txouts_data);	
	memcpy(raw_tx->txouts_data, src, raw_tx->cb_txouts);
	
	src += raw_tx->cb_txouts;
	assert(src <= p_end);
	
	return (size_t)(src - tx);
}
 


int main(int argc, char **argv)
{
	/* txid: "3b97e57b45700f4f83507fc3d5751f9baa934e3986baea510ad61703775cf737" */
	const char * tx_hex = 
		"01000000"
		"02"
			"6d12d9477e1085c97660d5532e47b88fa2b0ab8c643af84b2ebe64b6db5bd80001000000"
			"6a"
				"47"
				"304402205684fe30d2b01d093d549f94d180f5df29cd007673ec995465a76d747f0cad7b"
					"02200a1db7abeec033875d5daa06f1bdb3f278b7e752b05f6f05a4c889e4b2f92217"
				"01"
				"210365d88cbea2ccea10888b328f070868dc3b841f152eea8817e3cc43c8d87b8afe"
			"ffffffff"
			"6d12d9477e1085c97660d5532e47b88fa2b0ab8c643af84b2ebe64b6db5bd80000000000"
			"6a"
				"47"
				"304402200b3d64b6d5f1f9854d4c85a55c22deb3fb49f6efcdcf5952953cdca82aa6c4af"
					"022056d2465cc0accbc2435dfce3f2f866debc1c347d79d7872c76590a1aa9bffd48"
				"01"
				"210398a27ae243c9a3ec9c264fd460e9faa0da342a8d2186985e138fe380a8cbf853"
			"ffffffff"
		"02"
			"24108a0000000000" "17a9146894eeb7a180709cb1ad48b20e18da5e2d6d564987"
			"f928b90000000000" "1976a91475ddc928990a7fbfabdcc5402cb366fd6cdc41eb88ac"
		"00000000";
	
	static unsigned char tx[MAX_TX_BUFFER_SIZE];
	size_t cb_tx;
	satoshi_raw_tx_t raw_tx[1];
	memset(raw_tx, 0, sizeof(satoshi_raw_tx_t));
	
	cb_tx = hex2bin(tx_hex, -1, tx);
	parse_tx_v1(tx, cb_tx, raw_tx);
	
	static unsigned char pre_image[MAX_TX_BUFFER_SIZE];
	size_t cb_preimage = sizeof(pre_image);
	
	size_t txin_count = raw_tx->txin_count;
	assert(txin_count > 0);
	
	secp256k1_context * secp = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
	
	printf("txin count: %d\n", (int)txin_count);
	
	for(size_t i = 0; i < txin_count; ++i)
	{
		int rc;
		secp256k1_pubkey pubkey;
		secp256k1_ecdsa_signature sig;
		
		raw_txin_t * txin = &raw_tx->txins[i];
		
		unsigned char hash[32];
		satoshi_raw_tx_get_preimage(raw_tx, i, pre_image, &cb_preimage);
		
		printf("======== preimage[%d] ========\n", (int)i); dump(pre_image, cb_preimage);
		
		hash256(pre_image, cb_preimage, hash);
		rc = secp256k1_ec_pubkey_parse(secp, &pubkey, txin->pubkey, txin->cb_pubkey);
		assert(rc > 0); 
		
		rc = secp256k1_ecdsa_signature_parse_der(secp, &sig, txin->sig, txin->cb_sig);
		assert(rc > 0); 
		
		rc = secp256k1_ecdsa_verify(secp, &sig, hash, &pubkey);		
		printf("\t ==> txin[%d]: secp256k1_ecdsa_verify(sig, hash, pubkey)=%d\n\n", (int)i, rc);
	}

	/* cleanup */
	satoshi_raw_tx_cleanup(raw_tx);
	secp256k1_context_destroy(secp);
	return 0;
}

