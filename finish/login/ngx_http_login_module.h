 ///
 /// @file    ngx_http_token_module.h
 /// @author  faith(kh_faith@qq.com)
 /// @date    2018-08-27 11:48:30
 ///
 
#ifndef __NGX_HTTP_LOGIN_MODULE_H__
#define __NGX_HTTP_LOGIN_MODULE_H__

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "../shm/ngx_http_shm_module.h"
#include "../token/ngx_http_token_module.h"

char * ngx_http_login(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
ngx_int_t ngx_http_login_handler(ngx_http_request_t *r);
ngx_int_t ngx_http_upstream_tokenServer_toPut_handler(ngx_http_request_t *r);
ngx_int_t login_subrequest_post_put_handler(ngx_http_request_t *r,void *data,ngx_int_t rc);
ngx_int_t login_post_put_handler(ngx_http_request_t *r);

ngx_int_t ngx_put_request_uri(ngx_http_request_t *r,ngx_http_token_ctx_t *myctx);
ngx_int_t ngx_str_n(u_char *str,u_char (*d)[33],ngx_int_t n);
ngx_int_t cJSON_to_token(char *json_str,ngx_http_token_ctx_t *myctx);
#endif
