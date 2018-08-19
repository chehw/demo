#ifndef _BITCOIN_SCRIPTS_H_
#define _BITCOIN_SCRIPTS_H_

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct ch_stack_node * ch_stack_t;
typedef struct bitcoin_script
{
	ch_stack_t st_data;	/* main stack */
	ch_stack_t st_alt;	/* alt stack  */
	
	/* tx data */
	unsigned char msg_hash[32];
	uint32_t sequence;
	uint32_t locktime;
	
	const unsigned char * p_begin;
	const unsigned char * p_end;
	const unsigned char * p_cur;
	
	int stage;		/* 0=parse sig_script; 1=verify_redeem_script */
	int err_code;
}bitcoin_script_t;

bitcoin_script_t * bitcoin_script_init(bitcoin_script_t * script);
void bitcoin_script_cleanup(bitcoin_script_t * script);

int bitcoin_script_parse_sig_script(bitcoin_script_t * script, const unsigned char * p_script, size_t length);
void bitcoin_script_set_msg_hash(bitcoin_script_t * script, const unsigned char * msg_hash);
int bitcoin_script_verify_redeem_script(bitcoin_script_t * script, const unsigned char * p_script, size_t length);


#ifdef __cplusplus
}
#endif
#endif
