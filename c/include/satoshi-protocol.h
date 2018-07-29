#ifndef _SATOSHI_PROTOCOL_H_
#define _SATOSHI_PROTOCOL_H_

//~ #include "compatible.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//~ #define SATOSHI_PROTOCOL_VERSION 70015
#define SATOSHI_MAGIC_MAIN 		"\xf9\xbe\xb4\xd9"
#define SATOSHI_MAGIC_TEST 		"\xfa\xbf\xb5\xda"
#define SATOSHI_MAGIC_TEST3 	"\x0b\x11\x09\x07"
#define SATOSHI_MAGIC_NAMECOIN 	"\xf9\xbe\xb4\xfe"

#include "satoshi-types.h"

#ifdef __cplusplus
extern "C" {
#endif

extern uint64_t satoshi_service_flags;

enum satoshi_command_type
{
	SATOSHI_CMD_VERSION,
	SATOSHI_CMD_VERACK,
	SATOSHI_CMD_ADDR,
	SATOSHI_CMD_INV,
	SATOSHI_CMD_GETDATA,
	SATOSHI_CMD_NOTFOUND,
	SATOSHI_CMD_GETBLOCKS,
	SATOSHI_CMD_GETHEADERS,
	SATOSHI_CMD_TX,
	SATOSHI_CMD_BLOCK,
	SATOSHI_CMD_HEADERS,
	SATOSHI_CMD_GETADDR,
	SATOSHI_CMD_MEMPOOL,
	SATOSHI_CMD_CHECKORDER,
	SATOSHI_CMD_SUBMITORDER,
	SATOSHI_CMD_REPLY,
	SATOSHI_CMD_PING,
	SATOSHI_CMD_PONG,
	SATOSHI_CMD_REJECT,
	SATOSHI_CMD_FILTERLOAD,
	SATOSHI_CMD_FILTERADD,
	SATOSHI_CMD_FILTERCLEAR,
	SATOSHI_CMD_MERKLEBLOCK,
	SATOSHI_CMD_ALERT,
	SATOSHI_CMD_SENDHEADERS,
	SATOSHI_CMD_FEEFILTER,
	SATOSHI_CMD_SENDCMPCT,
	SATOSHI_CMD_CMPCTBLOCK,
	SATOSHI_CMD_GETBLOCKTXN,
	SATOSHI_CMD_BLOCKTXN,	
	SATOSHI_CMD_COUNT
};

typedef int (* satoshi_msg_callback_ptr)(satoshi_msg_header_t *, void *, void *);
typedef struct satoshi_msg_handler {
	char command[12];
	int (* on_msg_callback)(satoshi_msg_header_t * hdr, void * payload, void * user_data);	
}satoshi_msg_handler_t;

extern satoshi_msg_handler_t satoshi_msg_handler[];

#ifdef __cplusplus
}
#endif
#endif
