#ifndef _SATOSHI_NETWORK_H_
#define _SATOSHI_NETWORK_H_

#include <stdio.h>
#include <stdint.h>

#include <pthread.h>
#include <netdb.h>

#include "satoshi-protocol.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef struct satoshi_network_ctx satoshi_network_ctx_t;
typedef struct peer_info
{	
	satoshi_network_ctx_t * server_ctx;
	int fd;
	struct addrinfo ai;
	
	int64_t start_time;
	int64_t last_access_time;
	
	satoshi_version_t client_version;
	int64_t ping_data;
	
	char recv_buf[4096];	
	ssize_t in_pos;
	char * recv_data;
	size_t recv_data_len;
	
	char send_buf[4096];
	ssize_t out_pos;
	char * send_data;
	size_t send_data_len;	
	
	pthread_mutex_t mutex;
		
	void * user_data;
	int quit;
}peer_info_t;
peer_info_t * peer_info_init(peer_info_t * pi, satoshi_network_ctx_t * server);
void peer_info_cleanup(peer_info_t * pi);


typedef int (* satoshi_network_callback_ptr)(satoshi_network_ctx_t * ctx, peer_info_t * peer, void * user_data);

#define MAX_CONNECTIONS (4096)
struct satoshi_network_ctx
{
	char hostname[256];
	char port[64];
	struct addrinfo ai;
	pthread_t server_th[1];
	void * user_data;
	int quit;
	
	int sfd; // server fd
	int efd; // epoll fd		
	
	satoshi_network_callback_ptr on_accept;
	satoshi_network_callback_ptr on_recv;
	satoshi_network_callback_ptr on_send;
	satoshi_network_callback_ptr on_error;
	
	peer_info_t * peers[MAX_CONNECTIONS];
	int peers_count;
};

satoshi_network_ctx_t * satoshi_network_init(satoshi_network_ctx_t * ctx, const char * hostname, const char * port);
int satoshi_network_run(satoshi_network_ctx_t * ctx, 
	satoshi_network_callback_ptr on_accept,
	satoshi_network_callback_ptr on_recv,
	satoshi_network_callback_ptr on_send,
	satoshi_network_callback_ptr on_error,
	//~ int (* on_accept)(satoshi_network_ctx_t * ctx, peer_data_t * peer, void * user_data),
	//~ int (* on_recv)(satoshi_network_ctx_t * ctx, peer_data_t * peer, void * user_data),
	//~ int (* on_send)(satoshi_network_ctx_t * ctx, peer_data_t * peer, void * user_data),	
	//~ int (* on_error)(satoshi_network_ctx_t * ctx, peer_data_t * peer, void * user_data),
	void * user_data);
void satoshi_network_stop(satoshi_network_ctx_t * ctx);
void satoshi_network_cleanup(satoshi_network_ctx_t * ctx, void (* on_cleanup)(void *), void * user_data);

int satoshi_network_msg_send(satoshi_network_ctx_t * ctx, 
	int peer_fd,
	satoshi_msg_header_t * hdr, 
	const void * payload,
	size_t size);
	
peer_info_t	* satoshi_client_connect2(const char * serv_name, const char * port, 
	const satoshi_version_t * version,
	satoshi_network_callback_ptr on_connect,
	satoshi_network_callback_ptr on_read,
	satoshi_network_callback_ptr on_write,
	void * user_data);
	


#ifdef __cplusplus
}
#endif
#endif
