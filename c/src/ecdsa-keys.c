/*
 * ecdsa-keys.c
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
#include <stdlib.h>
#include <string.h>

#include <gmp.h>

#ifdef _USE_OPENSSL
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#else

#include <secp256k1.h>
#endif

#include <stdint.h>

#include "sha256.h"
#include "base58.h"
#include "utils.h"
#include "satoshi-types.h"

#include <assert.h>


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

/* 
 * parse_tx:
 * 	parse binary tx data and generate prehash image (raw_tx) 
 */
static uint32_t parse_tx(const unsigned char * tx, size_t tx_size, 
	unsigned char sig[],	/* der format signature */
	size_t * cb_sig,	 
	unsigned char pubkey[],	/* public key, size == 65 bytes or 33 bytes */
	size_t * cb_pubkey, 
	unsigned char ** p_raw_tx,
	size_t * cb_raw_tx)
{
	assert(NULL != tx && tx_size > 100 && NULL != p_raw_tx);
	
	int rc = 0;
	const unsigned char * src = tx;
	const unsigned char * p_end = tx + tx_size;
	unsigned char * raw_tx = * p_raw_tx;

	
	if(NULL == raw_tx) {	
		raw_tx = malloc(tx_size + 100);
		assert(NULL != raw_tx);
		*p_raw_tx = raw_tx;
	}
	
	unsigned char * dst = raw_tx;	
	
	
	*(uint32_t *)dst = *(uint32_t *)src; 	// copy tx version
	dst += sizeof(uint32_t); src += sizeof(uint32_t);
	
	/* parse txin */ 
	size_t txin_count = varint_get((varint_t *)src);
	// 为简化代码，这里只处理仅包含1个【TXIN】的交易。
	assert(txin_count == 1);
	
	size_t size = 1 + 36; // txin_count（1 byte) + outpoint (36 bytes)
	memcpy(dst, src, size);	// copy TXIN_OUTPOINT
	dst += size; src += size;
	
	
	/* parse signature / hashtype / pubkey */
		
	varstr_t * vsig_pubkey = (varstr_t *)src;
	varstr_t * vsig_hashtype = (varstr_t *)((unsigned char *)vsig_pubkey + varint_size((varint_t *)vsig_pubkey));	
	unsigned  char * sig_der = (unsigned char *)vsig_hashtype + varint_size((varint_t *)vsig_hashtype);
	*cb_sig = varstr_strlen(vsig_hashtype) - 1;
		
	uint32_t hash_type = *(sig_der + *cb_sig);	
	varstr_t * vpub = (varstr_t *)((unsigned char *)vsig_hashtype + varstr_size(vsig_hashtype));
	
	/* copy signature */	
	memcpy(sig, sig_der, *cb_sig);
	
	//~ printf("sig(cb=%d; ", (int)(*cb_sig)); dump2(stdout, sig, *cb_sig); printf("\n");
	//~ printf("hashtype: %0x\n", hash_type);
	//~ 
	/* copy pubkey */
	*cb_pubkey = varstr_strlen(vpub);
	memcpy(pubkey, varstr_get(vpub), *cb_pubkey);
	
	src += varstr_size(vsig_pubkey); // skip signature and pubkey
	
	/* replace with redeem script */
	size_t cb_redeem_script = 0;
	rc = p2pkh_to_redeem_script(vpub, dst, &cb_redeem_script);

	assert(0 == rc && cb_redeem_script > 20);
	dst += cb_redeem_script;
	
	/* copy data */
	size = p_end - src;
	memcpy(dst, src, size);	
	dst += size;
	
	/* append hash byte */
	*(uint32_t *)dst = hash_type;
	dst += sizeof(uint32_t);
	
	* cb_raw_tx = dst - raw_tx;
	return 0;
}
 

int main(int argc, char **argv)
{
	static const char * tx1_hex = "01000000014154f4916e4eed85fefcfd9f50df44d28c42c89e0db751ee60dcea4defa7a7e001000000"
				"6a4730440220538d2959108c11f0a34dd65c084af69765c66988b04e09eb0eebb7be69dde9510220551bf9a08a7dd489fe003c29fc71eb682d86d189c599e291d019a1ba47fb71e701"
				"2103c88e78a3f105d99b7b0643f3cfca56bad5ffd2c8e1bc055d8c6d51475bc6b2cf"
				"ffffffff02b0531000000000001976a9142c308577af5181072e8209461a1f3966b93b2ca788ac9a5fc42c000000001976a91472c563a65ab710115940785db85c4e766f064a5588ac00000000";
				
	static const char * tx2_hex = "0100000001a729b521b793df7b9a19c742964d1a56a63f7185bee3d760b9e0f39b975e5334010000006a4730440220538d2959108c11f0a34dd65c084af69765c66988b04e09eb0eebb7be69dde95102201bbcbd5d556d056c822a1ccb080d66d8144b4cb49a3bbf5c8e24a822248edf32012103c88e78a3f105d99b7b0643f3cfca56bad5ffd2c8e1bc055d8c6d51475bc6b2cfffffffff0280969800000000001976a9148391d76670cecf2b99c2cd6b92f65ed72a56387b88ac0aa22b2c000000001976a91472c563a65ab710115940785db85c4e766f064a5588ac00000000";
	
	static unsigned char tx1[MAX_TX_BUFFER_SIZE];
	static unsigned char tx2[MAX_TX_BUFFER_SIZE];
	
	
	
	static unsigned char raw_tx1[MAX_TX_BUFFER_SIZE];
	static unsigned char raw_tx2[MAX_TX_BUFFER_SIZE];
	
	unsigned char pubkey1[65];
	unsigned char pubkey2[65];
	
	unsigned char sig_der1[100];
	unsigned char sig_der2[100];
	
	unsigned char msg_hash1[32];
	unsigned char msg_hash2[32];
	
	size_t cb_tx1, cb_tx2;
	size_t cb_rawtx1, cb_rawtx2, cb_pubkey1, cb_pubkey2, cb_sig1, cb_sig2;
	
	
	secp256k1_context * secp = secp = secp256k1_context_create(
		SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
	secp256k1_pubkey pub[2];
	secp256k1_ecdsa_signature sig[2];
	int rc = 0;
	
/* step 0): prepare data */
	// hex to binary 	
	cb_tx1 = hex2bin(tx1_hex, -1, tx1);
	cb_tx2 = hex2bin(tx2_hex, -1, tx2);
	
	
	unsigned char * raw_tx = NULL;
	
	
	printf("--------------- parse tx1 -------------------\n");
	raw_tx = raw_tx1;
	parse_tx(tx1, cb_tx1, sig_der1, &cb_sig1, pubkey1, &cb_pubkey1, &raw_tx, &cb_rawtx1);  
	hash256(raw_tx1, cb_rawtx1, msg_hash1); 
	
	dump_line(stdout, "tx1", tx1, cb_tx1);
	dump_line(stdout, "raw_tx1", raw_tx1, cb_rawtx1);
	dump_line(stdout, "e1", msg_hash1, 32);
	
	/* 验证签名是否有效 （1 == ok)  */
	rc = secp256k1_ec_pubkey_parse(secp, &pub[0], pubkey1, cb_pubkey1);
	printf("secp256k1_ec_pubkey_parse(pub1)=%d\n", rc);
	rc = secp256k1_ecdsa_signature_parse_der(secp, &sig[0], sig_der1, cb_sig1);
	printf("secp256k1_ecdsa_signature_parse_der(sig1)=%d\n", rc);
	rc = secp256k1_ecdsa_verify(secp, &sig[0], msg_hash1, &pub[0]);
	printf("secp256k1_ecdsa_verify(sig1, e1, pub1)=%d\n", rc);
	
	
	printf("--------------- parse tx2 -------------------\n");
	raw_tx = raw_tx2;
	parse_tx(tx2, cb_tx2, sig_der2, &cb_sig2, pubkey2, &cb_pubkey2, &raw_tx, &cb_rawtx2);  
	hash256(raw_tx2, cb_rawtx2, msg_hash2); 
	
	dump_line(stdout, "tx2", tx2, cb_tx2);
	dump_line(stdout, "raw_tx2", raw_tx2, cb_rawtx2);
	dump_line(stdout, "e2", msg_hash2, 32);
	
	// verify signature
	rc = secp256k1_ec_pubkey_parse(secp, &pub[1], pubkey2, cb_pubkey2);
	printf("secp256k1_ec_pubkey_parse(pub1)=%d\n", rc);
	rc = secp256k1_ecdsa_signature_parse_der(secp, &sig[1], sig_der2, cb_sig2);
	printf("secp256k1_ecdsa_signature_parse_der(sig1)=%d\n", rc);
	rc = secp256k1_ecdsa_verify(secp, &sig[1], msg_hash2, &pub[1]);
	printf("secp256k1_ecdsa_verify(sig2, e2, pub2)=%d\n", rc);
	
	
// step 1)  检查一下r, s1, s2, e1, e2 以及ECC的n值是否初始化正确		
	struct
	{
		unsigned char r[32];
		unsigned char s[32];
	}sig_data[2];
	
	/* parse ecdsa signature to [r,s] data*/
	secp256k1_ecdsa_signature_serialize_compact(secp, (unsigned char *)&sig_data[0], &sig[0]);
	secp256k1_ecdsa_signature_serialize_compact(secp, (unsigned char * )&sig_data[1], &sig[1]);
	
	
	
	// 检查两个 r 值是否相等	
	assert(memcmp(sig_data[0].r, sig_data[1].r, 32) == 0);
	
	
	mpz_t r, s1, s2, e1, e2, n;	
	mpz_inits(r, s1, s2, e1, e2, n, NULL);
	mpz_import( r, 4, 1, sizeof(uint64_t), 1, 0, sig_data[0].r);
	mpz_import(s1, 4, 1, sizeof(uint64_t), 1, 0, sig_data[0].s);
	mpz_import(s2, 4, 1, sizeof(uint64_t), 1, 0, sig_data[1].s);
	mpz_import(e1, 4, 1, sizeof(uint64_t), 1, 0, msg_hash1);
	mpz_import(e2, 4, 1, sizeof(uint64_t), 1, 0, msg_hash2);
	
	/* init ECC's n */
	printf("init ECC's n\n");
	unsigned char ecc_n[32];
	const char * ecc_n_hex = "FFFFFFFF" "FFFFFFFF" "FFFFFFFF" "FFFFFFFE" "BAAEDCE6" "AF48A03B" "BFD25E8C" "D0364141";
	hex2bin(ecc_n_hex, -1, ecc_n);
	mpz_import(n, 4, 1, sizeof(uint64_t), 1, 0, ecc_n);
	
	printf("1)  检查一下r, s1, s2, e1, e2 以及ECC的n值是否初始化正确\n");
	dump_mpz("r=", r);
	dump_mpz("s1=", s1);
	dump_mpz("s2=", s2);
	dump_mpz("e1=", e1);
	dump_mpz("e2=", e2);
	dump_mpz("(n)=", n);
	 

// step 2) 计算k
	printf("\n2) 计算k\n");
	mpz_t e, s, _s, k;
	mpz_inits(e, s, _s, k, NULL);
	
	mpz_sub(e, e1, e2); 	dump_mpz("e = e1 - e2", e);
	mpz_sub(s, s1, s2);		dump_mpz("s = s1 - s2", s);
	mpz_invert(_s, s, n);	dump_mpz("_s = s^(-1)", _s);
	
	mpz_mul(k, e, _s);	mpz_mod(k,k,n);	dump_mpz("k = e * _s mod n",k);
	

// step 3) 计算d
	printf("\n3) 计算d\n");
	mpz_t _r, d;
	mpz_inits(_r, d, NULL);
	
	mpz_invert(_r, r, n); dump_mpz("_r = r^(-1)", _r);
	
	// d = [(s1 * k) - e1] / r MOD n
	mpz_mul(d, s1, k);
	mpz_sub(d, d, e1);
	mpz_mul(d, d, _r);
	mpz_mod(d, d, n);
	dump_mpz("d = [(s1 * k) - e1] / r mod n", d);


// Step 4) 校验私钥d是否计算正确:
	printf("\n4) 校验私钥d是否计算正确:\n");
	unsigned char sec_key[32];
	size_t cb_key = sizeof(sec_key);
	mpz_export(sec_key, &cb_key, 1, 1, 1, 0, d);	// mpz -> unsigned char

	secp256k1_pubkey pubkey_verify;
	unsigned char pubkey_buf[100];
	size_t cb_pubkey = sizeof(pubkey_buf);
	
	rc = secp256k1_ec_pubkey_create(secp, &pubkey_verify, sec_key);
	assert(rc);
	rc = secp256k1_ec_pubkey_serialize(secp, pubkey_buf, &cb_pubkey, &pubkey_verify, SECP256K1_EC_COMPRESSED);
	assert(rc);
	
	dump_line(stdout, "d -> pubkey", pubkey_buf, cb_pubkey);



/* cleanup memory */
	mpz_clears(_r, d, NULL);
	mpz_clears(e, s, _s, k, NULL);
	mpz_clears(r, s1, s2, e1, e2, n, NULL);
	secp256k1_context_destroy(secp);
	return 0;
}
