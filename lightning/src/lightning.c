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
	"17a914e9c3dd0c07aac76179ebc76a6c78d4d67c6c160a8700000000";
	
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
		"1976a9141d30342095961d951d306845ef98ac08474b36a088aca7270400";






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
	return;
}
#endif
