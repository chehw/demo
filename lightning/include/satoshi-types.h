#ifndef _SATOSHI_TYPES_H_
#define _SATOSHI_TYPES_H_

#include <stdio.h>
#include <stdint.h>

#define SATOSHI_PROTOCOL_VERSION 70015

#ifdef __cplusplus
extern "C" {
#endif


typedef uint8_t uint256_t[32];
typedef union compact_int
{
	uint32_t value;
	struct
	{
		uint8_t mantissa[3];
		uint8_t exp;
	}__attribute__((packed));
}compact_int_t;

typedef struct varint
{
	uint8_t vch[9];
}varint_t;
void varint_set(varint_t * vint, uint64_t value);
uint64_t varint_get(const varint_t * vint);
//~ uint32_t varint_size(const varint_t * vint);
//~ uint32_t varint_calc_size(uint64_t value);

static inline uint32_t varint_size(const varint_t * vint)
{
	if(vint->vch[0] < 0xFD) return 1;
	else if(vint->vch[0] == 0xFD) return 3;
	else if(vint->vch[0] == 0xFE) return 5;
	return 9;
}

static inline uint32_t varint_calc_size(uint64_t value)
{
	if(value > 0xFFFFFFFFULL) return 9;
	else if(value > 0xFFFF) return 5;
	else if(value > 0xFC) return 3;
	return 1;
}


typedef struct varstr
{
	uint8_t vch[1];
}varstr_t;
varstr_t * varstr_new(size_t size);
varstr_t * varstr_set(varstr_t * vstr, const void * data, size_t size);
const char * varstr_get(const varstr_t * vstr);
ssize_t varstr_strlen(const varstr_t * vstr);
ssize_t varstr_size(const varstr_t * vstr);
void varstr_free(varstr_t * vstr);



typedef struct satoshi_msg_header satoshi_msg_header_t;
struct satoshi_msg_header
{
	uint32_t magic;
	char command[12];
	uint32_t size;
	unsigned char checksum[4];
	unsigned char payload[0];
} __attribute__((packed));

enum service_flags
{
	NODE_NONE = 0,
	NODE_NETWORK = 1,
	NODE_GETUTXO = (1 << 1),
	NODE_BLOOM = (1 << 2),
	NODE_WITNESS = (1 << 3),
	NODE_XTHIN = (1 << 4),
};


enum satoshi_inv_type
{
	MSG_ERROR = 0,
	MSG_TX = 1,
	MSG_BLOCK = 2, 
	MSG_FILTERED_BLOCK = 3,
	MSG_CMPCT_BLOCK = 4,
};

typedef struct satoshi_netaddr_legacy satoshi_netaddr_legacy_t;
struct satoshi_netaddr_legacy
{
	uint64_t services;
	char ip[16];
	uint16_t port;
} __attribute__((packed));


typedef struct satoshi_netaddr satoshi_netaddr_t;
struct satoshi_netaddr
{
#if SATOSHI_PROTOCOL_VERSION >= 31402
	uint32_t time;
#endif
	uint64_t services;
	char ip[16];
	uint16_t port;
} __attribute__((packed));


typedef struct satoshi_version satoshi_version_t;
struct satoshi_version
{
	int32_t version;	// protocol version
	uint64_t services;
	int64_t timestamp;
	satoshi_netaddr_legacy_t addr_recv;
#if SATOSHI_PROTOCOL_VERSION >= 106
	satoshi_netaddr_legacy_t addr_from;
	uint64_t nonce;
	varstr_t user_agent;
	// int32_t start_height;
#endif

#if SATOSHI_PROTOCOL_VERSION >= 70001	
//	int8_t relay;
#endif
}__attribute__((packed));
void satoshi_version_dump(const satoshi_version_t * p_ver);

typedef struct satoshi_inventory satoshi_inventory_t;
struct satoshi_inventory
{
	uint32_t type;
	uint256_t hash;
} __attribute__((packed));

typedef struct satoshi_outpoint satoshi_outpoint_t;
struct satoshi_outpoint
{
	uint256_t hash;
	uint32_t index;
}__attribute__((packed));

typedef struct satoshi_txin satoshi_txin_t;
struct satoshi_txin
{
	struct satoshi_outpoint outpoint;
	varstr_t * sig_script;
	uint32_t sequence;
}__attribute__((packed));

typedef struct satoshi_txout satoshi_txout_t;
struct satoshi_txout
{
	int64_t value;
	varstr_t * pk_script;	
}__attribute__((packed));
static inline void satoshi_txout_cleanup(satoshi_txout_t * txout)
{
	if(txout->pk_script) {
		varstr_free(txout->pk_script);
		txout->pk_script = NULL;
	}
}


typedef struct satoshi_tx satoshi_tx_t;
struct satoshi_tx
{
	unsigned char * raw_data;
	size_t size;
	uint256_t txid;
		
	int32_t version;
	varint_t txin_count;
	satoshi_txin_t * p_txin;
	
	varint_t txout_count;
	satoshi_txout_t * p_txout;
	
	uint32_t lock_time;
}__attribute__((packed));

typedef struct satoshi_raw_txin satoshi_raw_txin_t;
struct satoshi_raw_txin
{
	satoshi_outpoint_t outpoint;
	unsigned char sig_script[1]; // allways 0
	uint32_t sequence;
}__attribute__((packed));

#ifdef __cplusplus
}
#endif
#endif
