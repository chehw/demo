#ifndef _SHARED_PTR_H_
#define _SHARED_PTR_H_

#include <stdio.h>



#ifdef __cplusplus
extern "C" {
#endif

void * shared_ptr_new(void * ptr, void (* cleanup)(void *));
void * shared_ptr_malloc(size_t size);
void   shared_ptr_free(void * ptr);

long shared_ptr_ref(void *ptr);
long shared_ptr_unref(void * ptr);
long   shared_ptr_get_refs_count(void * ptr);

void   shared_ptr_global_init();
void   shared_ptr_global_cleanup();


#ifdef __cplusplus
}
#endif
#endif
