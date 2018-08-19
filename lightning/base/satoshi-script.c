/*
 * satoshi-scripts.c
 * 
 * Copyright 2017 chehw <chehw@chehw-HP8200>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 * 
 * 
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

#include <stdbool.h>

#include "satoshi-script.h"

#include <secp256k1.h>
#include "ripemd160.h"
#include "sha256.h"
#include "utils.h"


// Maximum number of bytes pushable to the stack
static const unsigned int MAX_SCRIPT_ELEMENT_SIZE = 520;

// Maximum number of non-push operations per script
static const int MAX_OPS_PER_SCRIPT = 201;

// Maximum number of public keys per multisig
static const int MAX_PUBKEYS_PER_MULTISIG = 20;

// Maximum script length in bytes
static const int MAX_SCRIPT_SIZE = 10000;

// Maximum number of values on script interpreter stack
static const int MAX_STACK_SIZE = 1000;

// Threshold for nLockTime: below this value it is interpreted as block number,
// otherwise as UNIX timestamp.
static const unsigned int LOCKTIME_THRESHOLD = 500000000; // Tue Nov  5 00:53:20 1985 UTC


static bool opcode_enabled[256] = 
{
	1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, 	// 0x00 - 0F
	1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, 	// 0x10 - 1F
	1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, 	// 0x20 - 2F
	1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, 	// 0x30 - 3F
	1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, 	// 0x40 - 4F
	0,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, 	// 0x50 - 5F
	1,1,0,1,1,0,0,1, 1,1,1,1,1,1,1,1, 	// 0x60 - 6F
	1,1,1,1,1,1,1,1, 1,1,1,1,1,1,0,0, 	// 0x70 - 7F
	
	0,0,1,0,0,0,0,1, 1,0,0,1,1,1,1,1, 	// 0x80 - 8F
	1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, 	// 0x90 - 9F
	1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, 	// 0xa0 - aF
	1,1,1,1,1,1,1,1, 1,1,				// 0xb0 - b9
};



/*******************************************************
 * stack
 ******************************************************/
enum satoshi_stack_node_type
{
	satoshi_stack_node_type_null = 0,
	satoshi_stack_node_type_data = 1,
	satoshi_stack_node_type_int = 2,	/* input: int32, internal_storage: int64 */
	satoshi_stack_node_type_bool = 3,
	satoshi_stack_node_type_pointer = 4,
	satoshi_stack_node_type_op = 5
};

typedef struct satoshi_stack_node
{
	enum satoshi_stack_node_type type;
	size_t size;
	union
	{
		void * ptr;
		int64_t i64;
		bool ok;
		unsigned char op;
	};
	struct satoshi_stack_node * next;
}satoshi_stack_node_t;
void satoshi_stack_node_free(satoshi_stack_node_t * node);

void satoshi_stack_node_dump(satoshi_stack_node_t * node)
{
	printf("==== node(%p) ====\n", node);
	if(NULL == node) return;
	
	printf("\ttype: %d\n", (int)node->type);
	printf("\tsize: %d\n", (int)node->size);
	switch(node->type)
	{
	case satoshi_stack_node_type_data:
	case satoshi_stack_node_type_pointer:
		printf("\tdata: "); dump2(stdout, node->ptr, node->size);
		break;
	default:
		printf("\tvalue: %ld\n", node->i64);
		break;
	}
}


#define auto_stack_node_ptr __attribute__((cleanup(auto_cleanup_node_ptr))) satoshi_stack_node_t * 

static inline void auto_cleanup_node_ptr(void * p)
{
	if(p) 
	{
		satoshi_stack_node_free(*(satoshi_stack_node_t **)p);
	}
}

static int satoshi_stack_node_compare(const satoshi_stack_node_t * a, const satoshi_stack_node_t * b)
{
	enum satoshi_stack_node_type type_a = a->type;
	enum satoshi_stack_node_type type_b = b->type;
	if(type_a == satoshi_stack_node_type_data) type_a = satoshi_stack_node_type_pointer;
	if(type_b == satoshi_stack_node_type_data) type_b = satoshi_stack_node_type_pointer;
	
	if(type_a != type_b) return (int)type_a - (int)type_b;
	switch(type_a)
	{
	case satoshi_stack_node_type_pointer:
		if(a->size > b->size) return 1;
		else if(a->size < b->size) return -1;
		else 
			return memcmp(a->ptr, b->ptr, a->size);
	case satoshi_stack_node_type_null:
		return 0;
	case satoshi_stack_node_type_bool:
		return (a->ok == b->ok);
	case satoshi_stack_node_type_int:
		if(a->i64 > b->i64) return 1;
		else if(a->i64 < b->i64) return -1;
		else return 0;
	case satoshi_stack_node_type_op:
		return (a->op == b->op);
	default:
		break;
	}
	return 0xFFFF;	/* unknown error */
}


satoshi_stack_node_t * satoshi_stack_node_new(enum satoshi_stack_node_type type, const void * data, size_t size)
{
	satoshi_stack_node_t * node = calloc(1, sizeof(satoshi_stack_node_t));
	if(type == satoshi_stack_node_type_null)
	{
		return node;
	}
	node->type = type;
	
	switch(type)
	{
	case satoshi_stack_node_type_data:
	case satoshi_stack_node_type_pointer:
		if(size > MAX_SCRIPT_ELEMENT_SIZE) break;
		if(size == 0)
		{
			node->type = satoshi_stack_node_type_null;
			return node;
		}
		if(type == satoshi_stack_node_type_data)
		{
			node->ptr = malloc(size);
			memcpy(node->ptr, data, size);
		}else
		{
			node->ptr = (void *)data;
		}
		node->size = size;
		return node;
	case satoshi_stack_node_type_int:
		node->i64 = *(int32_t *)data;
		node->size = 0;
		return node;
	case satoshi_stack_node_type_bool:
		node->ok = data?true:false;
		node->size = 0;
		return node;
	
	default:
		break;
	}
	free(node);
	return NULL;
}

void satoshi_stack_node_free(satoshi_stack_node_t * node)
{
	if(node)
	{
		if(node->type == satoshi_stack_node_type_data) free(node->ptr);
		free(node);
	}
}


typedef struct satoshi_stack_node * satoshi_stack_t;

void satoshi_stack_destroy(satoshi_stack_t *p_stack)
{
	assert(p_stack);
	satoshi_stack_node_t * node = NULL;
	while((node = *p_stack))
	{
		*p_stack = node->next;
		satoshi_stack_node_free(node);
	}
}

satoshi_stack_t satoshi_stack_push(satoshi_stack_t stack, satoshi_stack_node_t * node)
{
	assert(node);
	debug_printf("%s(%p)\n", __FUNCTION__, node);
	satoshi_stack_node_dump(node);
	
	node->next = stack;
	stack = node;
	return stack;
}

satoshi_stack_node_t * satoshi_stack_pop(satoshi_stack_t * p_stack)
{
	assert(p_stack);
	satoshi_stack_node_t * top = *p_stack;
	if(top)
	{
		debug_printf("%s(%p)\n", __FUNCTION__, top);
		satoshi_stack_node_dump(top);
	
		*p_stack = top->next;
		top->next = NULL;
	}
	return top;
}



int satoshi_script_init(satoshi_script_t * script)
{
	assert(script);
	memset(script, 0, sizeof(satoshi_script_t));
	
	script->secp = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
	assert(script->secp);
	
	return 0;
}

void satoshi_script_reset(satoshi_script_t * script)
{
	satoshi_stack_destroy(&script->main);
	satoshi_stack_destroy(&script->alt);
	script->p_begin = script->p_end = script->p_cur = NULL;
}

void satoshi_script_cleanup(satoshi_script_t * script)
{
	satoshi_script_reset(script);
	if(script->secp)
	{
		secp256k1_context_destroy(script->secp);
		script->secp = NULL;
	}
	memset(script, 0, sizeof(satoshi_script_t));
}

static inline bool is_opcode_valid(unsigned char op, int flags)
{
	if(flags == 0) return (op <= OP_PUSHDATA4);
	else
	{
		return opcode_enabled[op];
	}
}

static int script_opcode_handler(satoshi_script_t * script, unsigned char op);
int satoshi_script_op(satoshi_script_t * script, unsigned char op)
{
	/* reset err status */
	script->err_code = 0;
	script->last_op = op;
	
	printf("\t%s(0x%.2x)\n", __FUNCTION__, (uint32_t)op);
	
	/* push data */
	if(op <= OP_PUSHDATA4)
	{
		size_t size = 0;
		if(op < OP_PUSHDATA1)
		{
			size = op;
			
		}else if(op == OP_PUSHDATA1)
		{
			size = * script->p_cur++;
		}else if(op == OP_PUSHDATA2)
		{
			size = le16toh(*(uint32_t *)script->p_cur);
			script->p_cur += 2;
		}else if(op == OP_PUSHDATA4)
		{
			size = le32toh(*(uint32_t *)script->p_cur);
			script->p_cur += 4;
		}
		
		
		assert((script->p_cur + size) <= script->p_end);
		
		script->main = satoshi_stack_push(script->main,
			satoshi_stack_node_new(satoshi_stack_node_type_data, script->p_cur, size));
		script->p_cur += size;
		return 0;
	}
	
	return script_opcode_handler(script, op);
	
	//~ switch(op)
	//~ {
	//~ case OP_PUSHDATA1:
		//~ size = * script->p_cur++;
		//~ break;
	//~ case OP_PUSHDATA2:
		//~ size = le16toh(*(uint32_t *)script->p_cur);
		//~ script->p_cur += 2;
		//~ break;
	//~ case OP_PUSHDATA4:
		//~ size = le32toh(*(uint32_t *)script->p_cur);
		//~ script->p_cur += 4;
		//~ break;
	//~ default:
		//~ return script_opcode_handler(script, op);
	//~ }
	//~ 
	//~ if(size > MAX_SCRIPT_ELEMENT_SIZE) return -1;
	//~ if(size)
	//~ {
		//~ assert((script->p_cur + size) <= script->p_end);
		//~ 
		//~ script->main = satoshi_stack_push(script->main,
			//~ satoshi_stack_node_new(satoshi_stack_node_type_data, script->p_cur, size));
		//~ script->p_cur += size;
		//~ return 0;
	//~ }
	//~ 
	//~ return 0;
}

static inline int script_opcode_dup(satoshi_script_t * script)
{
	printf("\t\t%s(%p)\n", __FUNCTION__, script);
	assert(script->main);
	script->main = satoshi_stack_push(script->main,
			satoshi_stack_node_new(script->main->type, script->main->ptr, script->main->size));
	return 0;
}

static inline int script_opcode_checksig(satoshi_script_t * script)
{
	printf("\t\t%s(%p)\n", __FUNCTION__, script);
	
	auto_stack_node_ptr pub_node = satoshi_stack_pop(&script->main);
	auto_stack_node_ptr sig_node = satoshi_stack_pop(&script->main);
	assert(pub_node && sig_node);
	
	secp256k1_pubkey pub;
	secp256k1_ecdsa_signature sig;
	int rc;
	
	assert(pub_node->size && sig_node->size);
	
	rc = secp256k1_ec_pubkey_parse(script->secp, &pub, (unsigned char *)pub_node->ptr, pub_node->size);
	assert(rc > 0);
	//~ if(rc <= 0) return -1;
	
	rc = secp256k1_ecdsa_signature_parse_der(script->secp, &sig, (unsigned char *)sig_node->ptr, sig_node->size - 1);
	assert(rc > 0);
	//~ if(rc <= 0) return -1;
	
	//~ satoshi_stack_node_free(pub_node);
	//~ satoshi_stack_node_free(sig_node);
	
	rc = secp256k1_ecdsa_verify(script->secp, &sig, script->msg_hash, &pub);
	{
		printf("\t== secp256k1_ecdsa_verify()=%d: \n", rc);
		unsigned char pubkey[65], sig_der[100];
		size_t cb_pubkey = sizeof(pubkey), cb_sig_der = sizeof(sig_der);
		
		rc = secp256k1_ec_pubkey_serialize(script->secp, pubkey, &cb_pubkey, &pub, SECP256K1_EC_COMPRESSED);
		assert(rc > 0);
		
		rc = secp256k1_ecdsa_signature_serialize_der(script->secp, sig_der, &cb_sig_der, &sig);
		assert(rc > 0);
		
		printf("\t\tmsg_hash: "); dump2(stdout, script->msg_hash, 32); printf("\n");
		printf("\t\tpubkey: "); dump2(stdout, pubkey, cb_pubkey); printf("\n");
		printf("\t\tpubkey: "); dump2(stdout, sig_der, cb_sig_der); printf("\n");
	}
	
	script->main = satoshi_stack_push(script->main,
			satoshi_stack_node_new(satoshi_stack_node_type_bool, (void *)(long)(bool)rc, 0));
	return 0;
}

static inline int script_opcode_equal(satoshi_script_t * script)
{	
	auto_stack_node_ptr node1 = satoshi_stack_pop(&script->main);
	auto_stack_node_ptr node2 = satoshi_stack_pop(&script->main);
	int rc;
	
	rc = satoshi_stack_node_compare(node1, node2);
	
	script->main = satoshi_stack_push(script->main,
			satoshi_stack_node_new(satoshi_stack_node_type_bool, (void *)(long)(bool)rc, 0));
	return 0;
}

static inline int script_opcode_equal_verify(satoshi_script_t * script)
{
	auto_stack_node_ptr node1 = satoshi_stack_pop(&script->main);
	auto_stack_node_ptr node2 = satoshi_stack_pop(&script->main);
	int rc;
	
	rc = satoshi_stack_node_compare(node1, node2);
	assert(rc == 0);
	if(rc) return -1;
	
	return 0;
}

static inline int script_opcode_ripemd160(satoshi_script_t * script)
{
	auto_stack_node_ptr node1 = satoshi_stack_pop(&script->main);
	
	void * data = NULL;
	size_t size = 0;
	
	unsigned char hash[20];
	
	switch(node1->type)
	{
	case satoshi_stack_node_type_data:
	case satoshi_stack_node_type_pointer:
		data = node1->ptr;
		size = node1->size;
		break;
	case satoshi_stack_node_type_int:
		data = &node1->i64;
		size = sizeof(uint32_t);
		break;
	default:
		return -1;
	}
	ripemd160_ctx_t ctx[1];
	ripemd160_init(ctx);
	ripemd160_update(ctx, data, size);
	ripemd160_final(ctx, hash);
	
	
	script->main = satoshi_stack_push(script->main,
			satoshi_stack_node_new(satoshi_stack_node_type_data, hash, 20));
	return 0;
}


static inline int script_opcode_sha256(satoshi_script_t * script)
{
	auto_stack_node_ptr node1 = satoshi_stack_pop(&script->main);
	
	void * data = NULL;
	size_t size = 0;
	
	unsigned char hash[20];
	
	switch(node1->type)
	{
	case satoshi_stack_node_type_data:
	case satoshi_stack_node_type_pointer:
		data = node1->ptr;
		size = node1->size;
		break;
	case satoshi_stack_node_type_int:
		data = &node1->i64;
		size = sizeof(uint32_t);
		break;
	default:
		return -1;
	}
	sha256_ctx_t ctx[1];
	sha256_init(ctx);
	sha256_update(ctx, data, size);
	sha256_final(ctx, hash);
	
	
	script->main = satoshi_stack_push(script->main,
			satoshi_stack_node_new(satoshi_stack_node_type_data, hash, 32));
	return 0;
}


static inline int script_opcode_hash160(satoshi_script_t * script)
{
	auto_stack_node_ptr node1 = satoshi_stack_pop(&script->main);
	
	void * data = NULL;
	size_t size = 0;
	
	unsigned char hash[20];
	
	switch(node1->type)
	{
	case satoshi_stack_node_type_data:
	case satoshi_stack_node_type_pointer:
		data = node1->ptr;
		size = node1->size;
		break;
	case satoshi_stack_node_type_int:
		data = &node1->i64;
		size = sizeof(uint32_t);
		break;
	default:
		return -1;
	}
	
	hash160(data, size, hash);
	
	
	script->main = satoshi_stack_push(script->main,
			satoshi_stack_node_new(satoshi_stack_node_type_data, hash, 20));
	return 0;
}


static inline int script_opcode_hash256(satoshi_script_t * script)
{
	auto_stack_node_ptr node1 = satoshi_stack_pop(&script->main);
	
	void * data = NULL;
	size_t size = 0;
	
	unsigned char hash[20];
	
	switch(node1->type)
	{
	case satoshi_stack_node_type_data:
	case satoshi_stack_node_type_pointer:
		data = node1->ptr;
		size = node1->size;
		break;
	case satoshi_stack_node_type_int:
		data = &node1->i64;
		size = sizeof(uint32_t);
		break;
	default:
		return -1;
	}
	
	hash256(data, size, hash);
	script->main = satoshi_stack_push(script->main,
			satoshi_stack_node_new(satoshi_stack_node_type_data, hash, 32));
	return 0;
}

static int script_opcode_handler(satoshi_script_t * script, unsigned char op)
{
	//if(!is_opcode_valid(op, script->flags) return -1;
	
	switch(op)
	{
	case OP_0: // 0x00,
	//~ case OP_FALSE: // OP_0,
	case OP_PUSHDATA1: // 0x4c,
	case OP_PUSHDATA2: // 0x4d,
	case OP_PUSHDATA4: // 0x4e,
		return -1;
	
	case OP_1NEGATE: // 0x4f,
	case OP_RESERVED: // 0x50,
	case OP_1: // 0x51,
	//~ case OP_TRUE: // OP_1,
	case OP_2: // 0x52,
	case OP_3: // 0x53,
	case OP_4: // 0x54,
	case OP_5: // 0x55,
	case OP_6: // 0x56,
	case OP_7: // 0x57,
	case OP_8: // 0x58,
	case OP_9: // 0x59,
	case OP_10: // 0x5a,
	case OP_11: // 0x5b,
	case OP_12: // 0x5c,
	case OP_13: // 0x5d,
	case OP_14: // 0x5e,
	case OP_15: // 0x5f,
	case OP_16: // 0x60,

	//control
	case OP_NOP: // 0x61,
	case OP_VER: // 0x62,
	case OP_IF: // 0x63,
	case OP_NOTIF: // 0x64,
	case OP_VERIF: // 0x65,
	case OP_VERNOTIF: // 0x66,
	case OP_ELSE: // 0x67,
	case OP_ENDIF: // 0x68,
	case OP_VERIFY: // 0x69,
	case OP_RETURN: // 0x6a,

	//stackops
	case OP_TOALTSTACK: // 0x6b,
	case OP_FROMALTSTACK: // 0x6c,
	case OP_2DROP: // 0x6d,
	case OP_2DUP: // 0x6e,
	case OP_3DUP: // 0x6f,
	case OP_2OVER: // 0x70,
	case OP_2ROT: // 0x71,
	case OP_2SWAP: // 0x72,
	case OP_IFDUP: // 0x73,
	case OP_DEPTH: // 0x74,
	case OP_DROP: // 0x75,
		break;
	case OP_DUP: // 0x76,
		return script_opcode_dup(script);
	case OP_NIP: // 0x77,
	case OP_OVER: // 0x78,
	case OP_PICK: // 0x79,
	case OP_ROLL: // 0x7a,
	case OP_ROT: // 0x7b,
	case OP_SWAP: // 0x7c,
	case OP_TUCK: // 0x7d,

	//spliceops
	case OP_CAT: // 0x7e,
	case OP_SUBSTR: // 0x7f,
	case OP_LEFT: // 0x80,
	case OP_RIGHT: // 0x81,
	case OP_SIZE: // 0x82,

	//bitlogic
	case OP_INVERT: // 0x83,
	case OP_AND: // 0x84,
	case OP_OR: // 0x85,
	case OP_XOR: // 0x86,
		break;
	case OP_EQUAL: // 0x87,
		return script_opcode_equal(script);
	case OP_EQUALVERIFY: // 0x88,
		return script_opcode_equal_verify(script);
	case OP_RESERVED1: // 0x89,
	case OP_RESERVED2: // 0x8a,

	//numeric
	case OP_1ADD: // 0x8b,
	case OP_1SUB: // 0x8c,
	case OP_2MUL: // 0x8d,
	case OP_2DIV: // 0x8e,
	case OP_NEGATE: // 0x8f,
	case OP_ABS: // 0x90,
	case OP_NOT: // 0x91,
	case OP_0NOTEQUAL: // 0x92,

	case OP_ADD: // 0x93,
	case OP_SUB: // 0x94,
	case OP_MUL: // 0x95,
	case OP_DIV: // 0x96,
	case OP_MOD: // 0x97,
	case OP_LSHIFT: // 0x98,
	case OP_RSHIFT: // 0x99,

	case OP_BOOLAND: // 0x9a,
	case OP_BOOLOR: // 0x9b,
	case OP_NUMEQUAL: // 0x9c,
	case OP_NUMEQUALVERIFY: // 0x9d,
	case OP_NUMNOTEQUAL: // 0x9e,
	case OP_LESSTHAN: // 0x9f,
	case OP_GREATERTHAN: // 0xa0,
	case OP_LESSTHANOREQUAL: // 0xa1,
	case OP_GREATERTHANOREQUAL: // 0xa2,
	case OP_MIN: // 0xa3,
	case OP_MAX: // 0xa4,

	case OP_WITHIN: // 0xa5,
		break;
	//crypto
	case OP_RIPEMD160: // 0xa6,
		return script_opcode_ripemd160(script); 
	case OP_SHA1: // 0xa7,
		break;
	case OP_SHA256: // 0xa8,
		return script_opcode_sha256(script); 
	case OP_HASH160: // 0xa9,
		return script_opcode_hash160(script); 
	case OP_HASH256: // 0xaa,
		return script_opcode_hash256(script); 
	case OP_CODESEPARATOR: // 0xab,
		break;
	case OP_CHECKSIG: // 0xac,
		return script_opcode_checksig(script);
	case OP_CHECKSIGVERIFY: // 0xad,
	case OP_CHECKMULTISIG: // 0xae,
	case OP_CHECKMULTISIGVERIFY: // 0xaf,

	//expansion
	case OP_NOP1: // 0xb0,
	case OP_CHECKLOCKTIMEVERIFY: // 0xb1,
	//~ case OP_NOP2: // OP_CHECKLOCKTIMEVERIFY,
	case OP_CHECKSEQUENCEVERIFY: // 0xb2,
	//~ case OP_NOP3: // OP_CHECKSEQUENCEVERIFY,
	case OP_NOP4: // 0xb3,
	case OP_NOP5: // 0xb4,
	case OP_NOP6: // 0xb5,
	case OP_NOP7: // 0xb6,
	case OP_NOP8: // 0xb7,
	case OP_NOP9: // 0xb8,
	case OP_NOP10: // 0xb9,


	//templatematchingparams
	case OP_SMALLINTEGER: // 0xfa,
	case OP_PUBKEYS: // 0xfb,
	case OP_PUBKEYHASH: // 0xfd,
	case OP_PUBKEY: // 0xfe,

	case OP_INVALIDOPCODE: // 0xff,
	default:
		return -1;
	}
	return -1;
}


int64_t satoshi_script_pop_result(satoshi_script_t * script)
{
	if(NULL == script || NULL == script->main) return -1;
	auto_stack_node_ptr top = satoshi_stack_pop(&script->main);
	int64_t result = top->i64;	
	return result;
}



int satoshi_script_parse_sig_script(satoshi_script_t * script, const unsigned char * sig_script, size_t size)
{
	satoshi_script_reset(script);
	script->flags = 0;
	
	/* parse sig_script */
	script->p_cur = script->p_begin = sig_script;
	script->p_end = sig_script + size;
	
	while(script->p_cur < script->p_end)
	{
		unsigned char op = * (script->p_cur++);
		int rc = satoshi_script_op(script, op);
		if(rc) return rc;	/* parse failed. */
	}
	
	return 0;
}

int satoshi_script_verify_redeem_script(satoshi_script_t * script, const unsigned char * redeem_script, size_t size)
{
	script->flags = 1;
	
	/* verify redeem_script */		
	script->p_cur = script->p_begin = redeem_script;
	script->p_end = redeem_script + size;

	while(script->p_cur < script->p_end)
	{
		unsigned char op = * (script->p_cur++);
		int rc = satoshi_script_op(script, op);
		if(rc) return rc;	/* parse failed. */
	}
	return 0;
}
