 ///
 /// @file    ngx_http_token_module.h
 /// @author  faith(kh_faith@qq.com)
 /// @date    2018-08-27 11:48:30
 ///
 
#ifndef __NGX_HTTP_TEST_MODULE_H__
#define __NGX_HTTP_TEST_MODULE_H__

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <stdint.h>
#include "../shm/ngx_http_shm_module.h"
#include "cJSON.h"

#define NGX_URI_RIGHT 0
#define NGX_URI_ERROR -1
#define SPILT_RIGHT 0
#define SPILT_ERROR -1

#define NGX_TEST_ERROR -2
#define NGX_TIMER_EXPIRES -1
#define NGX_TIMER_VALID 0
#define NGX_TIMER_UPDATE 1

char * ngx_http_token(ngx_conf_t *cf,ngx_command_t *cmd,void *conf);
ngx_int_t ngx_http_token_handler(ngx_http_request_t *r);

ngx_int_t ngx_http_upstream_realServer_handler(ngx_http_request_t *r);
ngx_int_t token_subrequest_post_real_handler(ngx_http_request_t *r,void *data,ngx_int_t rc);
ngx_int_t token_post_real_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_upstream_tokenServer_toGet_handler(ngx_http_request_t *r);
ngx_int_t token_subrequest_post_get_handler(ngx_http_request_t *r,void *data,ngx_int_t rc);
ngx_int_t ngx_http_upstream_tokenServer_toUpdate_handler(ngx_http_request_t *r);
ngx_int_t token_subrequest_post_update_handler(ngx_http_request_t *r,void *data,ngx_int_t rc);
ngx_int_t token_post_get_handler(ngx_http_request_t *r);
ngx_int_t token_post_update_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_sendmsg_client(ngx_http_request_t *r,ngx_str_t response);

unsigned char w[11][4][4];
unsigned char* InvCipher(unsigned char* input,unsigned char *key);
unsigned char* Cipher(unsigned char* input,unsigned char *key);
unsigned char* InvCipher_n(void* input, int length,unsigned char *key);
unsigned char* Cipher_n(void* input, int length,unsigned char *key);
void KeyExpansion(unsigned char* key, unsigned char w[][4][4]);
unsigned char FFmul(unsigned char a, unsigned char b);
void SubBytes(unsigned char state[][4]);
void MixColumns(unsigned char state[][4]);
void ShiftRows(unsigned char state[][4]);
void AddRoundKey(unsigned char state[][4], unsigned char k[][4]);
void InvSubBytes(unsigned char state[][4]);
void InvShiftRows(unsigned char state[][4]);
void InvMixColumns(unsigned char state[][4]);

ngx_int_t query_string(ngx_http_request_t *r,ngx_http_token_ctx_t *myctx);
u_char * bigDataSub(u_char *a,u_char *b);
ngx_int_t str_n(u_char *str,u_char (*p)[33],ngx_int_t n);
u_char **ngx_strtok(u_char *str,ngx_int_t n);
ngx_int_t deaes_data(ngx_http_request_t *r,ngx_http_token_ctx_t *myctx);
ngx_str_t aes_data(ngx_http_request_t *r,ngx_http_token_ctx_t *myctx);
ngx_int_t cJSON_to_str(char *json_string,ngx_http_token_ctx_t *myctx);
ngx_int_t ngx_time_cmp(ngx_http_request_t *r,u_char *c,ngx_http_token_ctx_t *myctx);

#endif
