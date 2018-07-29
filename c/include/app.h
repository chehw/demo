#ifndef _APP_H_
#define _APP_H_

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct app_context app_context_t;
app_context_t * app_init(app_context_t * app, int *p_argc, char *** p_argv, int (* init_proc)(app_context_t * ctx, void * user_data), void * user_data);
int app_run(app_context_t * app, int (* main_proc)(app_context_t * app, void * user_data), void * user_data);
void app_cleanup(app_context_t * app, void (* on_cleanup)(void *));

int app_log(app_context_t * app, int level, const char * fmt, ...);


#ifdef __cplusplus
}
#endif

#endif
