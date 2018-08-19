/*
 * tx.c
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
#include "tx.h"
#include <string.h>
#include <stdlib.h>
#include <assert.h>


#include "lightning.h"

#include "utils.h"
#include "base58.h"
#include "sha256.h"
#include "ripemd160.h"

#include <secp256k1.h>
#include <gmp.h>


#include "ch_keys.h"
#include <pthread.h>


#include "satoshi-script.h"
#include <inttypes.h>


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
	dst += 4; //sizeof(prefix);
	
	memcpy(dst, hash, sizeof(hash));
	dst += sizeof(hash);
	 
	memcpy(dst, suffix, sizeof(suffix));
	dst += 2; //sizeof(suffix);
	
	*cb_redeem_script = dst - redeem_script;
	return 0;
}




void satoshi_raw_tx_cleanup(satoshi_raw_tx_t * raw_tx)
{
	if(raw_tx)
	{
		free(raw_tx->txins);
		free(raw_tx->txouts_data);
		free(raw_tx->txouts);
		memset(raw_tx, 0, sizeof(satoshi_raw_tx_t));
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
size_t parse_tx_v1(const unsigned char * tx, 
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
		/* copy sigScripts */
		txin->cb_sig_script = varstr_size(vsig_pubkey);
		assert(txin->cb_sig_script <= sizeof(txin->sig_script));
		memcpy(txin->sig_script, src, txin->cb_sig_script);
		
		
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
	
	/* parse txouts */
	if(raw_tx->txouts_data){
		assert(raw_tx->cb_txouts > sizeof(uint32_t));
		unsigned char * p = raw_tx->txouts_data;
		unsigned char * p_locktime = p + raw_tx->cb_txouts - sizeof(uint32_t);
		
		ssize_t txout_count = varint_get((varint_t *)p);
		p += varint_size((varint_t *)p);
		
		assert(txout_count > 0);
		
		satoshi_txout_t * txouts = calloc(txout_count, sizeof(satoshi_txout_t));
		for(ssize_t i = 0; i < txout_count; ++i)
		{
			satoshi_txout_t * txout = &txouts[i];
			assert((p + sizeof(int64_t)) <= p_locktime);
			
			txout->value = *(int64_t *)p;	p += sizeof(int64_t);
			txout->pk_script = (varstr_t *)p;
			p += varstr_size(txout->pk_script);
		}
		
		raw_tx->txouts = txouts;
		raw_tx->txout_count = txout_count;
		
		raw_tx->lock_time = *(uint32_t *)p;
	}
	src += raw_tx->cb_txouts;
	assert(src <= p_end);
	
	return (size_t)(src - tx);
}

//~ 
//~ typedef struct satoshi_raw_tx
//~ {
	//~ int32_t version;
	//~ size_t txin_count;
	//~ raw_txin_t * txins;
//~ //	size_t txout_count;
	//~ unsigned char * txouts_data;
	//~ size_t cb_txouts;
	//~ 
	//~ size_t txout_count;
	//~ satoshi_txout_t * txouts;
	//~ uint32_t lock_time;
//~ }satoshi_raw_tx_t;
void satoshi_raw_tx_dump(satoshi_raw_tx_t * raw_tx)
{
	debug_printf("==== %s(%p)... ====\n", __FUNCTION__, raw_tx);
	#define TAB(n) do {	for(int i = 0; i < (int)(n); ++i) printf("\t"); }while(0)
	
	#define dump_int(klass, value) 		do { TAB(1); printf("%s: %d\n", #value, (int)klass->value); } while(0)
	#define dump_int64(klass, value) 	do { TAB(1); printf("%s: %ld(0x%.8x %.8x)\n", #value, \
				(int64_t)klass->value, \
				(uint32_t)((int64_t)klass->value >> 32), \
				(uint32_t)((uint32_t)klass->value & 0xFFFFFFFF) \
				); } while(0)
	
	#define dump_hex(klass, value) 		do { TAB(1); printf("%s: 0x%.8x\n", #value, (uint32_t)klass->value); } while(0)
	#define dump_data(klass, data, size) do { TAB(1); printf("%s(cb=%d): ", #data, (int)(size)); \
				dump2(stdout, &klass->data, size); printf("\n"); } while(0)
	#define dump_ptr(klass, ptr, size) do { TAB(1); printf("%s(cb=%d): ", #ptr, (int)(size)); \
				dump2(stdout, klass->ptr, size); printf("\n"); } while(0)
	
	
	dump_int(raw_tx, version);
	dump_int(raw_tx, txin_count);
	for(size_t i = 0; i < raw_tx->txin_count; ++i)
	{
		raw_txin_t * txin = &raw_tx->txins[i];
		TAB(1); printf("txin[%d]: \n", (int)i);
		TAB(1); dump_data(txin, outpoint, sizeof(txin->outpoint));
		TAB(1); dump_ptr(txin, sig_script, txin->cb_sig_script);
		TAB(1); dump_ptr(txin, redeem_script, txin->cb_redeem_script);
		TAB(1); dump_ptr(txin, sig, txin->cb_sig);
		TAB(1); dump_hex(txin, hash_type);
		TAB(1); dump_ptr(txin, pubkey, txin->cb_pubkey);
		TAB(1); dump_hex(txin, sequence);
	}
	
	dump_int(raw_tx, txout_count);
	for(size_t i = 0; i < raw_tx->txout_count; ++i)
	{
		satoshi_txout_t * txout = &raw_tx->txouts[i];
		
		TAB(1); printf("txout[%d]: \n", (int)i);
		TAB(1); dump_int64(txout, value);
		TAB(1); dump_ptr(txout, pk_script, varstr_size(txout->pk_script));
		//~ TAB(1); dump_data(txout, value, sizeof(txin->outpoint));
		//~ TAB(1); dump_ptr(txin, sig_script, txin->cb_sig_script);
		//~ TAB(1); dump_ptr(txin, redeem_script, txin->cb_redeem_script);
		//~ TAB(1); dump_ptr(txin, sig, txin->cb_sig);
		//~ TAB(1); dump_hex(txin, hash_type);
		//~ TAB(1); dump_ptr(txin, pubkey, txin->cb_pubkey);
		//~ TAB(1); dump_hex(txin, sequence);
	}
	
	dump_hex(raw_tx, lock_time);
	
	#undef dump_int
	#undef dump_data
	#undef TAB
	
}
 //~ struct raw_txin
//~ {
	//~ struct
	//~ {
		//~ uint8_t prev_hash[32];
		//~ uint32_t index;
	//~ }outpoint;
	//~ 
	//~ unsigned char sig_script[4096];
	//~ size_t cb_sig_script;
	//~ 
	//~ unsigned char redeem_script[100];
	//~ size_t cb_redeem_script;
	//~ 
	//~ unsigned char sig[100];
	//~ size_t cb_sig;
	//~ 
	//~ uint32_t hash_type;
	//~ 
	//~ unsigned char pubkey[65];
	//~ size_t cb_pubkey;
	//~ 
	//~ uint32_t sequence;
//~ };

#ifdef _STAND_ALONE

#include <json-c/json.h>
#include <pthread.h>
#include <sys/stat.h>

/* txid: "3b97e57b45700f4f83507fc3d5751f9baa934e3986baea510ad61703775cf737" */
#define DATA_PATH 	"data"
#define TX_ID 		"3b97e57b45700f4f83507fc3d5751f9baa934e3986baea510ad61703775cf737"

#define DATA_FILE 	DATA_PATH "/" TX_ID ".dat"

static const char * tx_hex = 
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

pthread_once_t once_key = PTHREAD_ONCE_INIT;

static void save_tx()
{
	FILE * fp = fopen(DATA_FILE, "wb+");
	assert(fp);
	
	static unsigned char tx[1 * 1024 * 1024];
	size_t cb = 0;
	cb = hex2bin(tx_hex, -1, tx);
	assert(cb);
	
	fwrite(tx, 1, cb, fp);
	fclose(fp);
}

static int load_tx(unsigned char ** p_tx, size_t * p_size)
{
	assert(p_tx && p_size);
	struct stat st[1];
	int rc;
	
	rc = stat(DATA_FILE, st);
	assert(rc == 0);
	
	size_t file_size = st->st_size;
	assert(file_size);
	
	
	FILE * fp = fopen(DATA_FILE, "rb");
	assert(fp);
	
	unsigned char * tx = *p_tx;
	if(NULL == tx)
	{
		tx = malloc(file_size);
		assert(tx);
		*p_tx = tx;
	}
	*p_size = fread(tx, 1, file_size, fp);
	fclose(fp);
	return 0;
}

int main(int argc, char **argv)
{
	pthread_once(&once_key, save_tx);
	
	unsigned char * tx = NULL;
	size_t cb_tx = 0;
	int rc = 0;
	
	load_tx(&tx, &cb_tx);
	
	printf("tx_size: %ld\n", cb_tx);
	
	satoshi_raw_tx_t raw_tx[1];
	memset(raw_tx, 0, sizeof(raw_tx));
	size_t cb = parse_tx_v1(tx, cb_tx, raw_tx);
	
	printf("cb: %ld\n", cb);
	
	
	satoshi_raw_tx_dump(raw_tx);
	
	satoshi_script_t script[1];
	satoshi_script_init(script);
	script->version = raw_tx->version;
	script->locktime = raw_tx->lock_time;
	
	satoshi_stack_node_dump(script->main);
	
	static unsigned char pre_image[1 * 1024 * 1024];
	
	/* parse and verify scripts for every txin */
	for(size_t i = 0; i < raw_tx->txin_count; ++i)
	{
		raw_txin_t * txin = &raw_tx->txins[i];
		
		/* set sequence and msg_hash of the current txin */
		script->sequence = txin->sequence;
		
		size_t cb_preimage = sizeof(pre_image);
		rc = satoshi_raw_tx_get_preimage(raw_tx, i, pre_image, &cb_preimage);
		assert(0 == rc);
		
		hash256(pre_image, cb_preimage, script->msg_hash);
		
		
		/* parse sig_script */
		rc = satoshi_script_parse_sig_script(script, 
			(unsigned char *)varstr_get((varstr_t *)txin->sig_script),
			varstr_strlen((varstr_t *)txin->sig_script));
		assert(0 == rc);
		
		//~ unsigned char * sig_script = (unsigned char *)varstr_get((varstr_t *)txin->sig_script);
		//~ unsigned char * p = sig_script;
		//~ unsigned char * p_end = p + varstr_strlen((varstr_t *)txin->sig_script);		
		//~ script->p_begin = p;
		//~ script->p_end = p_end;
		//~ script->p_cur = p;
		//~ script->flags = 0;
		//~ while(script->p_cur < script->p_end)
		//~ {
			//~ unsigned char op = * (script->p_cur++);
			//~ rc = satoshi_script_op(script, op);
			//~ assert(0 == rc);
		//~ }
	
		
		/* verify redeem_script */
		rc = satoshi_script_verify_redeem_script(script, 
			(unsigned char *)varstr_get((varstr_t *)txin->redeem_script),
			varstr_strlen((varstr_t *)txin->redeem_script));
		assert(0 == rc);
		
		//~ 
		//~ script->p_begin = p = txin->redeem_script + 1;
		//~ script->p_end = p + txin->cb_redeem_script - 1;
		//~ script->p_cur = p;
		//~ script->flags = 1;
		//~ while(script->p_cur < script->p_end)
		//~ {
			//~ unsigned char op = * (script->p_cur++);
			//~ rc = satoshi_script_op(script, op);
			//~ assert(0 == rc);
		//~ }
		
		//~ satoshi_stack_node_dump(script->main);
		
		/* check result */
		int64_t result = satoshi_script_pop_result(script);
		assert(result > 0);
		
		printf("result: %" PRIi64"\n", result);
		
		satoshi_script_reset(script);
	}
	
	
	
	satoshi_script_cleanup(script);
	
	satoshi_raw_tx_cleanup(raw_tx);
	free(tx);
	return 0;
}
#endif

