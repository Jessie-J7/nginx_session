 ///
 /// @file    ngx_http_token_module.c
 /// @author  faith(kh_faith@qq.com)
 /// @date    2018-08-27 10:16:13
 ///
 
#include <ngx_core.h>
#include <ngx_config.h>
#include <ngx_http.h>

typedef struct{
	u_char usrid[33];
	u_char appDevice[16];
}ngx_http_test_ctx_t;

char * ngx_http_test(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
ngx_int_t ngx_http_test_handler(ngx_http_request_t *r);
ngx_int_t ngx_put_request_uri(ngx_http_request_t *r,ngx_http_test_ctx_t *myctx);
static ngx_command_t ngx_http_test_commands[] = {
	{
		ngx_string("test"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
		ngx_http_test,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL
	},
	ngx_null_command
};

static ngx_http_module_t ngx_http_test_module_ctx = {
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};

ngx_module_t ngx_http_test_module = {
	NGX_MODULE_V1,
	&ngx_http_test_module_ctx,
	ngx_http_test_commands,
	NGX_HTTP_MODULE,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NGX_MODULE_V1_PADDING
};

char * ngx_http_test(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_core_loc_conf_t * clcf;
	clcf = (ngx_http_core_loc_conf_t *)ngx_http_conf_get_module_loc_conf(cf,ngx_http_core_module);
	clcf->handler = ngx_http_test_handler;
	return NGX_CONF_OK;
}

ngx_int_t ngx_http_test_handler(ngx_http_request_t *r)
{
	ngx_http_test_ctx_t *ctx = ngx_http_get_module_ctx(r,ngx_http_test_module);
	if(ctx == NULL)
	{
		ctx = ngx_pcalloc(r->pool,sizeof(ngx_http_test_ctx_t));
		if(ctx == NULL)
			return NGX_ERROR;
		ngx_http_set_ctx(r,ctx,ngx_http_test_module);
	}
	ngx_int_t ret = ngx_put_request_uri(r,ctx);
	if(ret == -1)
		return NGX_ERROR;
	
	ngx_str_t type = ngx_string("text/plain; charset=GBK");
	ngx_str_t response;
	response.len = ngx_strlen(ctx->usrid)+4;
	response.data = ngx_pcalloc(r->pool,response.len+1);
	ngx_snprintf(response.data,response.len,"190:%s",ctx->usrid);

	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = response.len;
	r->headers_out.content_type = type;
	
	ngx_int_t rc = ngx_http_send_header(r);
	if(rc == NGX_ERROR || rc > NGX_OK || r->header_only){
		return rc;
	}
	ngx_buf_t *b;
	b = ngx_create_temp_buf(r->pool,response.len);
	if(b == NULL){
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	ngx_memcpy(b->pos,response.data,response.len);
	b->last = b->pos + response.len;
	b->last_buf = 1;
	
	ngx_chain_t out;
	out.buf = b;
	out.next = NULL;

	return ngx_http_output_filter(r,&out);
}

ngx_int_t ngx_put_request_uri(ngx_http_request_t *r,ngx_http_test_ctx_t *myctx)
{
	u_char args[256] = {0};
	ngx_memcpy(args,r->args.data,r->args.len);
	u_char *p = args;
	u_char match[2][12] = {"usrid","applist"};
	ngx_uint_t i = 0;
	ngx_uint_t j = 0;
	ngx_int_t c = 0;
	for(; i <= r->args.len; i++)
	{
		if(ngx_strncmp(p + i,match[c],ngx_strlen(match[c])) == 0
				&& *(p + i + ngx_strlen(match[c])) == '=')
		{
			i = i + ngx_strlen(match[c]) + 1;
			for(j = i;j <= r->args.len;j++)
			{	if(*(p + j) == '&' || c == 1)
				{
					switch(c)
					{
						case 0:
							   ngx_memcpy(myctx->usrid,p+i,j-i);
							   break;
						case 1:
							   ngx_memcpy(myctx->appDevice,p+i,r->args.len-i);
							   break;
						default:
							   return -1;
					}
					c++;
					i = j;
					break;
				}
			}
		}
	}
	if(c == 2)
		return 0;
	return -1;
}

