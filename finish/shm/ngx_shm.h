
#ifndef __NGX_SHM_DICT_H__
#define __NGX_SHM_DICT_H__

#include <ngx_config.h>
#include <ngx_core.h>
#include <stdint.h>

#define NGX_SHM_HIT 0
#define NGX_SHM_MISS -1

typedef struct {
	ngx_rbtree_t		rbtree;
	ngx_rbtree_node_t	sentinel;
	ngx_queue_t			queue;
} ngx_http_token_shm_t;

typedef struct {
	u_char				rbtree_node_data;
	ngx_queue_t			queue;
	size_t				len;

	u_char				session[33];
	u_char				aesKey[33];
	u_char				appDevice[16];
	uint64_t			timer;

	u_char				data[1];
} ngx_http_token_node_t;

typedef struct {
	ssize_t				shmsize;
	ngx_str_t			*name;
	ngx_log_t			*log;
	ngx_slab_pool_t		*shpool;
	ngx_http_token_shm_t *sh;
} ngx_http_token_conf_t;

typedef struct{
	/* url args */
	u_char				usrid[33];
	u_char				aesData[128];
	uint64_t			requesttime;	
	/* token msg */
	u_char				session[33];
	u_char				aesKey[33];
	u_char				appDevice[16];
	uint64_t			timer;

	ngx_str_t			ip;
	ngx_str_t			ser_data;
	ngx_pool_t			*pool;
	ngx_shm_zone_t		*shm_zone;
}ngx_http_token_ctx_t;

ngx_shm_zone_t * ngx_shm_init(ngx_conf_t *cf, ngx_str_t* name, size_t size, void* module);
ngx_int_t ngx_http_token_lookup(ngx_http_token_conf_t* conf,ngx_uint_t hash,ngx_http_token_ctx_t *myctx);
ngx_int_t ngx_http_token_insert(ngx_http_token_conf_t* conf,ngx_http_token_ctx_t *myctx);
ngx_int_t ngx_http_token_update(ngx_http_token_conf_t* conf,ngx_uint_t hash,ngx_http_token_ctx_t *myctx); 
ngx_shm_zone_t * ngx_http_get_shm_zone(ngx_str_t *shm_name);

#endif

