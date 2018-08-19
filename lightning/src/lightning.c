/*
 * lightning.c
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


#include "lightning.h"

#include "utils.h"
#include "base58.h"
#include "sha256.h"
#include "ripemd160.h"

#include <secp256k1.h>
#include <gmp.h>


#include "ch_keys.h"
#include <pthread.h>


#define _TEST

#ifdef _TEST
static void test(int index);
#else
#define test(index) UNUSED((index))
#endif


static const char * p2sh_tx1_hex = "01000000"
	"01"
		"da75479f893cccfaa8e4558b28ec7cb4309954389f251f2212eabad7d7fda34200000000"
		"6a"
			"47"
				"3044022048d1468895910edafe53d4ec4209192cc3a8f0f21e7b9811f83b5e419bfb57e0"
					"02203fef249b56682dbbb1528d4338969abb14583858488a3a766f609185efe68bca"
				"01"
			"21"
				"031a455dab5e1f614e574a2f4f12f22990717e93899695fb0d81e4ac2dcfd25d00"
		"ffffffff"
	"01"
		"301b0f0000000000"
		"17a914e9c3dd0c07aac76179ebc76a6c78d4d67c6c160a87"
	"00000000";
	
static const char * redeem_tx1_hex = "01000000"
	"01"
		"c8cc2b56525e734ff63a13bc6ad06a9e5664df8c67632253a8e36017aee3ee4000000000"
		"90"
			"00"
			"48"
				"3045022100ad0851c69dd756b45190b5a8e97cb4ac3c2b0fa2f2aae23aed6ca97ab33bf883"
					"02200b248593abc1259512793e7dea61036c601775ebb23640a0120b0dba2c34b790"
				"01"
			"45"
				"51"
					"41"
						"042f90074d7a5bf30c72cf3a8dfd1381bdbd30407010e878f3a11269d5f74a5878"
						  "8505cdca22ea6eab7cfb40dc0e07aba200424ab0d79122a653ad0c7ec9896bdf"
				"51"
				"ae"
		"feffffff"
	"01"
		"20f40e0000000000"
		"1976a9141d30342095961d951d306845ef98ac08474b36a088ac"
	"a7270400";






int main(int argc, char **argv)
{
	test(0);
	return 0;
}



#ifdef _TEST

#undef _STAND_ALONE
#include "tx.h"
//~ #include "tx.c"
static void test(int index)
{
	int rc;
	static unsigned char tx[2][65536];
	size_t cb_tx[2], cb;
	
	cb_tx[0] = hex2bin(p2sh_tx1_hex, -1, tx[0]);
	cb_tx[1] = hex2bin(redeem_tx1_hex, -1, tx[1]);
	
	satoshi_raw_tx_t raw_tx[2];
	
	cb = parse_tx_v1(tx[0], cb_tx[0], &raw_tx[0]);
	assert(cb == cb_tx[0]);
	
	satoshi_raw_tx_dump(&raw_tx[0]);
	
	cb = parse_tx_v1(tx[1], cb_tx[1], &raw_tx[1]);
	assert(cb == cb_tx[1]);
	
	satoshi_raw_tx_dump(&raw_tx[1]);
	
	printf("cb=%ld\n",cb);
	
	
	unsigned char hash[32];

	
	/* check p2sh parse result */
	dump_line(stdout, "p2sh", 
		raw_tx[1].txins[0].pubkey,
		raw_tx[1].txins[0].cb_pubkey);
	
	hash160(raw_tx[1].txins[0].pubkey,
		raw_tx[1].txins[0].cb_pubkey,
		hash);
		
	dump_line(stdout, "hash160", hash, 20);
	
	/* test p2sh_script_verify */
	satoshi_script_t script[1];
	satoshi_script_init(script);
	
	rc = satoshi_script_parse_sig_script(script, 
		raw_tx[1].txins[0].sig_script + 1, 
		raw_tx[1].txins[0].cb_sig_script - 1);
	
	assert(0 == rc);
	
	rc = satoshi_script_verify_redeem_script(script, 
		raw_tx[1].txins[0].redeem_script + 1, 
		raw_tx[1].txins[0].cb_redeem_script - 1);
	assert(0 == rc);
	
	int64_t result = satoshi_script_pop_result(script);
	assert(result);
	
	if(script->bip16)
	{
		printf("\n================ parse p2sh script ========================\n");
		
		static unsigned char pre_image[1 * 1024 * 1024];
		size_t cb_preimage = sizeof(pre_image);
		satoshi_raw_tx_get_preimage(&raw_tx[1], 0, pre_image, &cb_preimage);
		
		hash256(pre_image, cb_preimage, script->msg_hash);
		
		printf("cb_preimage: %ld, data: [", cb_preimage);
		dump2(stdout, pre_image, cb_preimage);
		printf("]\n");
		printf("hash: [");
		dump2(stdout, script->msg_hash, 32);
		printf("]\n");
		
		rc = satoshi_script_parse_p2sh_script(script, 
			raw_tx[1].txins[0].pubkey, 
			raw_tx[1].txins[0].cb_pubkey);
		assert(rc == 0 );
		
		//~ satoshi_stack_node_t * top = satoshi_stack_pop(&script->main);
		//~ printf("++++++++++++++++++++++++++++++++++++++++++\n");
		//~ 
		//~ int count = 0;
		//~ while(top)
			//~ {
			//~ satoshi_stack_node_dump(top);
			//~ top = satoshi_stack_pop(&script->main);
			//~ ++count;
		//~ }
	//~ 
		//~ printf("count=%d\n", count);
	}
	
	
	/* test p2sh sig */
	if(0){
		char pre_image_hex[] = "01000000"
			"01"
			"c8cc2b56525e734ff63a13bc6ad06a9e5664df8c67632253a8e36017aee3ee4000000000"
			
				//~ "4800"
				//~ "4c"
				//~ "45"
				//~ "47"
				//~ "00"
				"45"
					"5141042f90074d7a5bf30c72cf3a8dfd1381bdbd30407010e878f3a11269d5f74a58788505cdca22ea6eab7cfb40dc0e07aba200424ab0d79122a653ad0c7ec9896bdf51ae"
				//~ "17a914e9c3dd0c07aac76179ebc76a6c78d4d67c6c160a87"
				"feffffff"
			"01"
				"20f40e0000000000"
				"1976a9141d30342095961d951d306845ef98ac08474b36a088ac"
			"a7270400"
			"01000000"
			;
		
		
		int len = strlen("5141042f90074d7a5bf30c72cf3a8dfd1381bdbd30407010e878f3a11269d5f74a58788505cdca22ea6eab7cfb40dc0e07aba200424ab0d79122a653ad0c7ec9896bdf51ae");
		len /= 2;
		printf("redeem script len: %d (0x%x)\n", len, len);
		unsigned char pre_image[1024];
		size_t cb_preimage;
		
		cb_preimage = hex2bin(pre_image_hex, -1, pre_image);
		assert(cb_preimage);
		
		unsigned char hash[32];
		hash256(pre_image, cb_preimage, hash);
		
		dump_line(stdout, "hash", hash, 32);
		
		secp256k1_context * secp = script->secp;
		secp256k1_pubkey pub;
		secp256k1_ecdsa_signature sig;
		
		char pubkey_hex[] = "042f90074d7a5bf30c72cf3a8dfd1381bdbd30407010e878f3a11269d5f74a58788505cdca22ea6eab7cfb40dc0e07aba200424ab0d79122a653ad0c7ec9896bdf";
		char sig_der_hex[] = "3045"
			"022100ad0851c69dd756b45190b5a8e97cb4ac3c2b0fa2f2aae23aed6ca97ab33bf883"
			"02200b248593abc1259512793e7dea61036c601775ebb23640a0120b0dba2c34b79001";
		
		unsigned char pubkey[100];
		unsigned char sig_der[100];
		int rc;
		
		size_t cb_pubkey = sizeof(pubkey);
		size_t cb_sig_der = sizeof(sig_der);
		
		cb_pubkey = hex2bin(pubkey_hex, -1, pubkey);
		cb_sig_der = hex2bin(sig_der_hex, -1, sig_der);
		
		rc = secp256k1_ec_pubkey_parse(secp, &pub, pubkey, cb_pubkey);
		assert(rc);
		
		rc = secp256k1_ecdsa_signature_parse_der(secp, &sig, sig_der, cb_sig_der - 1);
		assert(rc);
		
		rc = secp256k1_ecdsa_verify(secp, &sig, hash, &pub);
		printf("secp256k1_ecdsa_verify()=%d\n", rc);
		
		
	}
	
	satoshi_script_cleanup(script);
	satoshi_raw_tx_cleanup(&raw_tx[0]);
	satoshi_raw_tx_cleanup(&raw_tx[1]);
	
	return;
}



#endif
