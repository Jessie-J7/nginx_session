 ///
 /// @file    ngx_http_token_module.c
 /// @author  faith(kh_faith@qq.com)
 /// @date    2018-08-27 10:16:13
 ///
 
#include <ngx_core.h>
#include <ngx_config.h>
#include <ngx_http.h>
#include "ngx_http_login_module.h"

static ngx_command_t ngx_http_login_commands[] = {
	{
		ngx_string("login"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
		ngx_http_login,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL
	},
	ngx_null_command
};

static ngx_http_module_t ngx_http_login_module_ctx = {
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};

ngx_module_t ngx_http_login_module = {
	NGX_MODULE_V1,
	&ngx_http_login_module_ctx,
	ngx_http_login_commands,
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

char * ngx_http_login(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_core_loc_conf_t * clcf;
	clcf = (ngx_http_core_loc_conf_t *)ngx_http_conf_get_module_loc_conf(cf,ngx_http_core_module);
	clcf->handler = ngx_http_login_handler;
	return NGX_CONF_OK;
}

ngx_int_t ngx_http_login_handler(ngx_http_request_t *r)
{
	ngx_http_token_ctx_t * ctx = ngx_http_get_module_ctx(r,ngx_http_login_module);
	if(ctx == NULL)
	{
		ctx = ngx_pcalloc(r->pool,sizeof(ngx_http_token_ctx_t));
		if(ctx == NULL)
			return NGX_ERROR;
		ngx_http_set_ctx(r,ctx,ngx_http_login_module);
	}
	ngx_str_t zName = ngx_string("test");
	ngx_shm_zone_t *shm_zone = ngx_http_get_shm_zone(&zName);
	ctx->shm_zone = shm_zone;
	ctx->pool = r->pool;

	ngx_int_t ret = ngx_put_request_uri(r,ctx);//解析uri
	if(ret == -1)
		return NGX_HTTP_NOT_FOUND;

	//反向代理，拿到新的session key timer 插入
	ngx_http_upstream_tokenServer_toPut_handler(r);
	return NGX_OK;
}

ngx_int_t ngx_http_upstream_tokenServer_toPut_handler(ngx_http_request_t *r)
{
	ngx_http_token_ctx_t * myctx = ngx_http_get_module_ctx(r,ngx_http_login_module);
	ngx_http_post_subrequest_t * psr = ngx_pcalloc(r->pool,sizeof(ngx_http_post_subrequest_t));
	if(psr == NULL)
	{
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	psr->handler = login_subrequest_post_put_handler;
	psr->data = myctx;

	ngx_str_t sub_prefix = ngx_string("/rest/putsession");
	ngx_str_t sub_args;
	sub_args.len = 64;
	sub_args.data = ngx_pcalloc(r->pool,sub_args.len + 1);
	sprintf((char*)sub_args.data,"usrid=%s&applist=%s",myctx->usrid,myctx->appDevice);

	ngx_http_request_t *sr;
	ngx_int_t rc = ngx_http_subrequest(r,&sub_prefix,&sub_args,&sr,psr,NGX_HTTP_SUBREQUEST_IN_MEMORY);
	if(rc != NGX_OK)
		return NGX_HTTP_BAD_REQUEST;
	return NGX_DONE;
}

ngx_int_t login_subrequest_post_put_handler(ngx_http_request_t *r,void *data,ngx_int_t rc)
{
	ngx_http_request_t			*pr = r->parent;
	ngx_http_token_ctx_t		*myctx = data;
	ngx_http_token_conf_t		*conf = myctx->shm_zone->data;
	pr->headers_out.status = r->headers_out.status;

	if(r->headers_out.status != NGX_HTTP_OK)
	{
		ngx_log_debug0(NGX_LOG_DEBUG_CORE,r->pool->log,
				0,"putsession subrequest failed");
	}
	u_char item[5][33] = {0};
	ngx_buf_t * pRecvBuf = &r->upstream->buffer;
	ngx_log_debug1(NGX_LOG_DEBUG_CORE,r->pool->log,
				0,"putsession subrequest,respone = %s",pRecvBuf->pos);

	myctx->ser_data.len = pRecvBuf->last - pRecvBuf->pos;
	myctx->ser_data.data = pRecvBuf->pos;
	u_char *json_str = ngx_pcalloc(r->pool,pRecvBuf->last - pRecvBuf->pos+1);
	ngx_memcpy(json_str,pRecvBuf->pos,pRecvBuf->last - pRecvBuf->pos);
	cJSON_to_token((char *)json_str,myctx);

	ngx_int_t ret = ngx_str_n(json_str,item,5);
	if(ret == -1)
		return NGX_HTTP_BAD_REQUEST;
	ngx_pfree(r->pool,json_str);

	ngx_memcpy(myctx->session,item[1],ngx_strlen(item[1]));
	ngx_memcpy(myctx->aesKey,item[2],ngx_strlen(item[2]));
	ngx_memcpy(myctx->appDevice,item[3],ngx_strlen(item[3]));
	myctx->timer = (uint64_t)ngx_atosz(item[4],ngx_strlen(item[4]));  //atoi

	size_t len = ngx_strlen(myctx->usrid);
	uint32_t hash = ngx_crc32_short(myctx->usrid,len);
	ngx_shmtx_lock(&conf->shpool->mutex);
	rc = ngx_http_token_update(conf,hash,myctx);
	if(rc < 0)
		rc = ngx_http_token_insert(conf,myctx);
	ngx_shmtx_unlock(&conf->shpool->mutex);
	
	pr->write_event_handler = (void*)login_post_put_handler;
	return NGX_OK;
}

ngx_int_t login_post_put_handler(ngx_http_request_t *r)
{
	if(r->headers_out.status != NGX_HTTP_OK)
	{
		ngx_http_finalize_request(r,r->headers_out.status);
		return NGX_HTTP_BAD_REQUEST;
	}
	ngx_http_token_ctx_t * myctx = ngx_http_get_module_ctx(r,ngx_http_login_module);
	ngx_int_t rc = ngx_http_sendmsg_client(r,myctx->ser_data);
	ngx_http_finalize_request(r,rc);
	return NGX_OK;
}

ngx_int_t ngx_put_request_uri(ngx_http_request_t *r,ngx_http_token_ctx_t *myctx)
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

ngx_int_t ngx_str_n(u_char *str,u_char (*d)[33],ngx_int_t n)
{
	ngx_int_t i=0,j=0,k=0;
	u_char *temp = str;
	ngx_int_t len = ngx_strlen(str);
	while(i <= len)
	{
		if(str[i] == ' '||str[i] == '\0')
		{
			ngx_memzero(d[j],i-k);
			ngx_memcpy(d[j],temp,i-k);
			temp = temp + (i-k+1);
			j++;
			k = i + 1;
		}
		if(j == n)
			break;
		i++;
	}
	if(j == n)
		return 0;
	return -1;
}

ngx_int_t cJSON_to_token(char *json_string,ngx_http_token_ctx_t *myctx)
{
	cJSON *root=cJSON_Parse(json_string);
	if (!root)
	{
		return -1;
	}
	else
	{
		cJSON *item=cJSON_GetObjectItem(root,"body");
		if(item!=NULL)
		{
			ngx_memzero(json_string,ngx_strlen(json_string));
			ngx_memcpy(json_string,item->valuestring,ngx_strlen(item->valuestring));
			cJSON_Delete(root);
			return 0;
		}
	}
	cJSON_Delete(root);
	return -1;
}
