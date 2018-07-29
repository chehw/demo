/*
 * shared_ptr.c
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
#include <search.h>
#include <assert.h>
#include <pthread.h>



typedef struct shared_ptr_ctx
{
	void * ptr;
	size_t size;
	long refs;	
	void (* cleanup)(void *);
}shared_ptr_ctx_t;


static void * shared_ptr_root;
pthread_mutex_t s_mutex = PTHREAD_MUTEX_INITIALIZER;
static inline void lock() 	{ pthread_mutex_lock(&s_mutex); }
static inline void unlock() { pthread_mutex_unlock(&s_mutex); }

static int shared_ptr_compare(const void * l, const void * r)
{
	long addr1 = (long)((shared_ptr_ctx_t *)l)->ptr;
	long addr2 = (long)((shared_ptr_ctx_t *)r)->ptr;
	if(addr1 > addr2) return 1;
	else if(addr1 < addr2) return -1;
	return 0;
}

static void shared_ptr_cleanup(void * node)
{
	shared_ptr_ctx_t * sptr = (shared_ptr_ctx_t *)node;
	if(sptr) 
	{
		if(sptr->cleanup) sptr->cleanup(sptr->ptr);
		else free(sptr->ptr);
	}
	free(sptr);
}


void * shared_ptr_new(void * ptr, void (* cleanup)(void *))
{
	if(NULL == ptr) return NULL;
	shared_ptr_ctx_t * sptr = calloc(1, sizeof(shared_ptr_ctx_t));
	void ** p_node = NULL;
	assert(NULL != sptr);
	
	lock();
	sptr->ptr = ptr;
	if(cleanup) sptr->cleanup = cleanup;
	
		
	p_node = tsearch(sptr, &shared_ptr_root, shared_ptr_compare);
	if(NULL == p_node) {
		unlock();
		return NULL;
	}
	
	if(*(shared_ptr_ctx_t **)p_node != sptr)
	{
		free(sptr);
		sptr = *(shared_ptr_ctx_t **)p_node;
	}
	++sptr->refs;	
	unlock();
	return ptr;
}

void * shared_ptr_malloc(size_t size)
{
	void * ptr = malloc(size);
	assert(NULL != ptr);
	return shared_ptr_new(ptr, free);
}

void shared_ptr_free(void * ptr)
{
	shared_ptr_ctx_t pattern = {
		.ptr = ptr
	};
	void *p_node;
	shared_ptr_ctx_t * sptr;
	lock();
	p_node = tfind(&pattern, &shared_ptr_root, shared_ptr_compare);
	if(p_node)
	{
		sptr = *(shared_ptr_ctx_t **)p_node;
	}
	if(sptr)
	{
		if(sptr->refs > 0) --sptr->refs;	
		if(0 == sptr->refs)
		{
			tdelete(&pattern, &shared_ptr_root, shared_ptr_compare);			
			shared_ptr_cleanup(sptr);
		//	free(sptr);			
		}	
	}	
	unlock();
	return;	
}

long shared_ptr_get_refs_count(void * ptr)
{
	long count = -1;
	lock();
	shared_ptr_ctx_t pattern = {
		.ptr = ptr
	};
	void *p_node;
	shared_ptr_ctx_t * sptr;
	lock();
	p_node = tfind(&pattern, &shared_ptr_root, shared_ptr_compare);
	if(p_node)
	{
		sptr = *(shared_ptr_ctx_t **)p_node;
		if(sptr)
		{
			count = sptr->refs;
		}
	}	
	unlock();
	return count;
}


long shared_ptr_ref(void *ptr)
{
	long count = -1;
	lock();
	shared_ptr_ctx_t pattern = {
		.ptr = ptr
	};
	void *p_node;
	shared_ptr_ctx_t * sptr;
	lock();
	p_node = tfind(&pattern, &shared_ptr_root, shared_ptr_compare);
	if(p_node)
	{
		sptr = *(shared_ptr_ctx_t **)p_node;
		if(sptr)
		{
			count = ++sptr->refs;
		}
	}	
	unlock();
	return count;
}

long shared_ptr_unref(void * ptr)
{
	long count = -1;
	lock();
	shared_ptr_ctx_t pattern = {
		.ptr = ptr
	};
	void *p_node;
	shared_ptr_ctx_t * sptr;
	lock();
	p_node = tfind(&pattern, &shared_ptr_root, shared_ptr_compare);
	if(p_node)
	{
		sptr = *(shared_ptr_ctx_t **)p_node;
		if(sptr && sptr->refs > 0)
		{
			count = --sptr->refs;
			if(0 == sptr->refs)
			{
				tdelete(&pattern, &shared_ptr_root, shared_ptr_compare);				
			//	free(sptr);	
			}	
		}
	}	
	unlock();
	if(0 == count) shared_ptr_cleanup(sptr);
	return count;
}

void shared_ptr_global_init()
{
	pthread_mutex_init(&s_mutex, NULL);
}

void shared_ptr_global_cleanup()
{
	tdestroy(&shared_ptr_root, shared_ptr_cleanup);	
	pthread_mutex_destroy(&s_mutex);
}

