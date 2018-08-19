/*
 * satoshi-types.c
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
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include <inttypes.h>
#include <time.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include "satoshi-types.h"
#include "utils.h"

#include <limits.h>
#include <sys/socket.h>
#include <netdb.h>

#include <stdbool.h>

/*
 * varint
 */ 
void varint_set(varint_t * vint, uint64_t value)
{
	uint32_t len = varint_calc_size(value);
	if(len == 1) vint->vch[0] = (unsigned char)value;
	else if(len == 3)
	{
		vint->vch[0] = 0xFD;
		vint->vch[1] = (unsigned char)(value & 0xFF);
		vint->vch[2] = (unsigned char)((value >> 1) & 0xFF);		
	}else if(len == 5)
	{
		vint->vch[0] = 0xFD;
		memcpy(&vint->vch[1], &value, 4);
	}else if(len == 9)
	{
		memcpy(&vint->vch[1], &value, 8);
	}
}

uint64_t varint_get(const varint_t * vint)
{
	uint64_t val = 0;
	uint32_t len = varint_size(vint);
	if(len == 1) return (uint64_t)vint->vch[0];
	
	memcpy(&val, &vint->vch[1], len - 1);
	return val;
}

/*
 * varstr
 */ 
varstr_t * varstr_new(size_t size)
{
	varstr_t * vstr = NULL;
	uint32_t vint_len = varint_calc_size(size);
	vstr = (varstr_t *)malloc(vint_len + size);
	if(vstr)
	{
		varint_set((varint_t *)vstr, size);
	//	vstr->vch[vint_len + size] = '\0';
	}
	return vstr;
}
varstr_t * varstr_set(varstr_t * vstr, const void * data, size_t size)
{
	ssize_t vstr_len = 0;
	uint32_t vint_len = 1;
	if(NULL == vstr) 
	{		
		vstr = varstr_new(size);
		if(NULL == vstr) return NULL;
		vint_len = varint_size((varint_t *)vstr);
		memcpy(&vstr->vch[vint_len], data, size);
	}
	else
	{
		vstr_len = varstr_strlen(vstr);
		if(0 == vstr_len) 
		{
			varint_set((varint_t *)vstr, size);
			vstr_len = (ssize_t)varint_get((varint_t *)vstr);
		}
		vint_len = varint_size((varint_t *)vstr);
		assert(vstr_len == size);
		memcpy(&vstr->vch[vint_len], data, size);
	}	
	return vstr;
}
const char * varstr_get(const varstr_t * vstr)
{
	uint32_t vint_len = varint_size((varint_t *)vstr);
	return (const char *)&vstr->vch[vint_len];
}
ssize_t varstr_size(const varstr_t * vstr)
{
	ssize_t cb_vint = varint_size((varint_t *)vstr);
	ssize_t cb_str = (ssize_t)varint_get((varint_t *)vstr);
	return cb_vint + cb_str;
}
ssize_t varstr_strlen(const varstr_t * vstr)
{
	return (ssize_t)varint_get((varint_t *)vstr);
}

void varstr_free(varstr_t * vstr)
{
	free(vstr);
}



void satoshi_version_dump(const satoshi_version_t * p_ver)
{
	struct tm * t;
	printf("protocol_version: %u\n", p_ver->version);
	printf("service: 0x%"PRIx64"\n", p_ver->services);
	time_t timestamp = p_ver->timestamp;
	t = localtime(&timestamp);
	
	printf("timestamp: %lu (%.4d-%.2d-%.2d %.2d:%.2d:%.2d GMT+8)\n", 
		p_ver->timestamp,
		t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
		t->tm_hour, t->tm_min, t->tm_sec);
	dump_line(stdout, "addr recv", p_ver->addr_recv.ip, 16);
	
	
	
	struct sockaddr_in6 in6;
	memset(&in6, 0, sizeof(in6));
	in6.sin6_family = AF_INET6;
	in6.sin6_port = p_ver->addr_recv.port;
	memcpy(&in6.sin6_addr, p_ver->addr_recv.ip, 16);
	
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	int rc = getnameinfo((struct sockaddr *)&in6, sizeof(in6),
		hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
		NI_NUMERICHOST | NI_NUMERICSERV);
	if(0 == rc)
	{
		printf("addr_recv: %s:%s\n", hbuf, sbuf);
	}
	
	memset(&in6, 0, sizeof(in6));
	in6.sin6_family = AF_INET6;
	in6.sin6_port = p_ver->addr_from.port;
	memcpy(&in6.sin6_addr, p_ver->addr_from.ip, 16);
	
	
	rc = getnameinfo((struct sockaddr *)&in6, sizeof(in6),
		hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
		NI_NUMERICHOST | NI_NUMERICSERV);
	if(0 == rc)
	{
		printf("addr_from: %s:%s\n", hbuf, sbuf);
	}
	
	size_t cb_vstr = varstr_size(&p_ver->user_agent);
	printf("nonce: %"PRIu64"\n", p_ver->nonce);
	printf("user_agent: (size = %lu), ", cb_vstr);
	fwrite(varstr_get(&p_ver->user_agent),  1, varstr_strlen(&p_ver->user_agent), stdout);
	printf("\n");
	
	unsigned char * p = (unsigned char *)&p_ver->user_agent;
	p += cb_vstr;
	printf("start_height = %d\n", *(uint32_t *)p);
	p += 4;
	printf("relay: %d\n", (int)*(bool *)p);
	
}
