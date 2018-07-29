/*
 * satoshi-protocol.c
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
#include "satoshi-protocol.h"
#include "utils.h"


//~ const char * satoshi_command[] = {
	//~ [SATOSHI_CMD_VERSION] = "version",
	//~ [SATOSHI_CMD_VERACK] = "verack",
	//~ [SATOSHI_CMD_ADDR] = "addr",
//~ };



uint64_t satoshi_service_flags = NODE_NETWORK | NODE_WITNESS | NODE_XTHIN;
#define msg_dummy(hdr, payload, user_data) do { fprintf(stderr, __FILE__ "::%s() @line %d: dummy func.\n", __FUNCTION__, __LINE__);} while(0)

static int on_msg_version(satoshi_msg_header_t * hdr, void * payload, void * user_data)
{
	debug_printf("command: %s, size: %u\n", hdr->command, hdr->size);
	return 0;
}
static int on_msg_verack(satoshi_msg_header_t * hdr, void * payload, void * user_data)
{
	debug_printf("command: %s, size: %u\n", hdr->command, hdr->size);
	return 0;
}
static int on_msg_addr(satoshi_msg_header_t * hdr, void * payload, void * user_data)
{
	debug_printf("command: %s, size: %u\n", hdr->command, hdr->size);
	return 0;
}
static int on_msg_inv(satoshi_msg_header_t * hdr, void * payload, void * user_data)
{
	debug_printf("command: %s, size: %u\n", hdr->command, hdr->size);
	return 0;
}
static int on_msg_getdata(satoshi_msg_header_t * hdr, void * payload, void * user_data)
{
	debug_printf("command: %s, size: %u\n", hdr->command, hdr->size);
	return 0;
}
static int on_msg_notfound(satoshi_msg_header_t * hdr, void * payload, void * user_data)
{
	debug_printf("command: %s, size: %u\n", hdr->command, hdr->size);
	return 0;
}
static int on_msg_getblocks(satoshi_msg_header_t * hdr, void * payload, void * user_data)
{
	debug_printf("command: %s, size: %u\n", hdr->command, hdr->size);
	return 0;
}
static int on_msg_getheaders(satoshi_msg_header_t * hdr, void * payload, void * user_data)
{
	debug_printf("command: %s, size: %u\n", hdr->command, hdr->size);
	return 0;
}
static int on_msg_tx(satoshi_msg_header_t * hdr, void * payload, void * user_data)
{
	debug_printf("command: %s, size: %u\n", hdr->command, hdr->size);
	return 0;
}
static int on_msg_block(satoshi_msg_header_t * hdr, void * payload, void * user_data)
{
	debug_printf("command: %s, size: %u\n", hdr->command, hdr->size);
	return 0;
}
static int on_msg_headers(satoshi_msg_header_t * hdr, void * payload, void * user_data)
{
	debug_printf("command: %s, size: %u\n", hdr->command, hdr->size);
	return 0;
}
static int on_msg_getaddr(satoshi_msg_header_t * hdr, void * payload, void * user_data)
{
	debug_printf("command: %s, size: %u\n", hdr->command, hdr->size);
	return 0;
}
static int on_msg_mempool(satoshi_msg_header_t * hdr, void * payload, void * user_data)
{
	debug_printf("command: %s, size: %u\n", hdr->command, hdr->size);
	return 0;
}
static int on_msg_checkorder(satoshi_msg_header_t * hdr, void * payload, void * user_data)
{
	debug_printf("command: %s, size: %u\n", hdr->command, hdr->size);
	return 0;
}
static int on_msg_submitorder(satoshi_msg_header_t * hdr, void * payload, void * user_data)
{
	debug_printf("command: %s, size: %u\n", hdr->command, hdr->size);
	return 0;
}
static int on_msg_reply(satoshi_msg_header_t * hdr, void * payload, void * user_data)
{
	debug_printf("command: %s, size: %u\n", hdr->command, hdr->size);
	return 0;
}
static int on_msg_ping(satoshi_msg_header_t * hdr, void * payload, void * user_data)
{
	debug_printf("command: %s, size: %u\n", hdr->command, hdr->size);
	return 0;
}
static int on_msg_pong(satoshi_msg_header_t * hdr, void * payload, void * user_data)
{
	debug_printf("command: %s, size: %u\n", hdr->command, hdr->size);
	return 0;
}
static int on_msg_reject(satoshi_msg_header_t * hdr, void * payload, void * user_data)
{
	debug_printf("command: %s, size: %u\n", hdr->command, hdr->size);
	return 0;
}
static int on_msg_filterload(satoshi_msg_header_t * hdr, void * payload, void * user_data)
{
	debug_printf("command: %s, size: %u\n", hdr->command, hdr->size);
	return 0;
}
static int on_msg_filteradd(satoshi_msg_header_t * hdr, void * payload, void * user_data)
{
	debug_printf("command: %s, size: %u\n", hdr->command, hdr->size);
	return 0;
}
static int on_msg_filterclear(satoshi_msg_header_t * hdr, void * payload, void * user_data)
{
	debug_printf("command: %s, size: %u\n", hdr->command, hdr->size);
	return 0;
}
static int on_msg_merkleblock(satoshi_msg_header_t * hdr, void * payload, void * user_data)
{
	debug_printf("command: %s, size: %u\n", hdr->command, hdr->size);
	return 0;
}
static int on_msg_alert(satoshi_msg_header_t * hdr, void * payload, void * user_data)
{
	debug_printf("command: %s, size: %u\n", hdr->command, hdr->size);
	return 0;
}
static int on_msg_sendheaders(satoshi_msg_header_t * hdr, void * payload, void * user_data)
{
	debug_printf("command: %s, size: %u\n", hdr->command, hdr->size);
	return 0;
}
static int on_msg_feefilter(satoshi_msg_header_t * hdr, void * payload, void * user_data)
{
	debug_printf("command: %s, size: %u\n", hdr->command, hdr->size);
	return 0;
}
static int on_msg_sendcmpct(satoshi_msg_header_t * hdr, void * payload, void * user_data)
{
	debug_printf("command: %s, size: %u\n", hdr->command, hdr->size);
	return 0;
}
static int on_msg_cmpctblock(satoshi_msg_header_t * hdr, void * payload, void * user_data)
{
	debug_printf("command: %s, size: %u\n", hdr->command, hdr->size);
	return 0;
}
static int on_msg_getblocktxn(satoshi_msg_header_t * hdr, void * payload, void * user_data)
{
	debug_printf("command: %s, size: %u\n", hdr->command, hdr->size);
	return 0;
}
static int on_msg_blocktxn(satoshi_msg_header_t * hdr, void * payload, void * user_data)
{
	debug_printf("command: %s, size: %u\n", hdr->command, hdr->size);
	return 0;
}


satoshi_msg_handler_t satoshi_msg_handler[SATOSHI_CMD_COUNT] = {
	[SATOSHI_CMD_VERSION] 		= {"version", on_msg_version},
	[SATOSHI_CMD_VERACK] 		= {"verack", on_msg_verack},
	[SATOSHI_CMD_ADDR] 			= {"addr", on_msg_addr},
	[SATOSHI_CMD_INV]			= {"inv", on_msg_inv},
	[SATOSHI_CMD_GETDATA]		= {"getdata", on_msg_getdata},
	[SATOSHI_CMD_NOTFOUND]		= {"notfound", on_msg_notfound},
	[SATOSHI_CMD_GETBLOCKS]		= {"getblocks", on_msg_getblocks},
	[SATOSHI_CMD_GETHEADERS]	= {"getheaders", on_msg_getheaders},
	[SATOSHI_CMD_TX]			= {"tx", 		on_msg_tx},
	[SATOSHI_CMD_BLOCK]			= {"block", 	on_msg_block},
	[SATOSHI_CMD_HEADERS]		= {"headers", 	on_msg_headers},
	[SATOSHI_CMD_GETADDR]		= {"getaddr", 	on_msg_getaddr},
	[SATOSHI_CMD_MEMPOOL]		= {"mempool", 	on_msg_mempool},
	[SATOSHI_CMD_CHECKORDER]	= {"checkorder", 	on_msg_checkorder},
	[SATOSHI_CMD_SUBMITORDER]	= {"submitorder", 	on_msg_submitorder},
	[SATOSHI_CMD_REPLY]			= {"reply", 		on_msg_reply},
	[SATOSHI_CMD_PING]			= {"ping", 			on_msg_ping},
	[SATOSHI_CMD_PONG]			= {"pong", 			on_msg_pong},
	[SATOSHI_CMD_REJECT]		= {"reject", 		on_msg_reject},
	[SATOSHI_CMD_FILTERLOAD]	= {"filterload", 	on_msg_filterload},
	[SATOSHI_CMD_FILTERADD]		= {"filteradd", 	on_msg_filteradd},
	[SATOSHI_CMD_FILTERCLEAR]	= {"filterclear", 	on_msg_filterclear},
	[SATOSHI_CMD_MERKLEBLOCK]	= {"merkleblock", 	on_msg_merkleblock},
	[SATOSHI_CMD_ALERT]			= {"alert", 		on_msg_alert},
	[SATOSHI_CMD_SENDHEADERS]	= {"sendheaders", 	on_msg_sendheaders},
	[SATOSHI_CMD_FEEFILTER]		= {"feefilter", 	on_msg_feefilter},
	[SATOSHI_CMD_SENDCMPCT]		= {"sendcmpct", 	on_msg_sendcmpct},
	[SATOSHI_CMD_CMPCTBLOCK]	= {"cmpctblock", 	on_msg_cmpctblock},
	[SATOSHI_CMD_GETBLOCKTXN]	= {"getblocktxn", 	on_msg_getblocktxn},
	[SATOSHI_CMD_BLOCKTXN]		= {"blocktxn", 		on_msg_blocktxn},
};

		
	//~ SATOSHI_CMD_COUNT
//~ };

