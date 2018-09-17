 ///
 //
 /// @file    ngx_http_token_module.c
 /// @author  faith(kh_faith@qq.com)
 /// @date    2018-08-27 10:16:13
 ///
 
#include <ngx_core.h>
#include <ngx_config.h>
#include <ngx_http.h>
#include "ngx_http_token_module.h"

ngx_int_t ngx_http_sendmsg_client(ngx_http_request_t *r,ngx_str_t response);

static ngx_command_t ngx_http_token_commands[] = {
	{
		ngx_string("token"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
		ngx_http_token,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL
	},
	ngx_null_command
};

static ngx_http_module_t ngx_http_token_module_ctx = {
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};

ngx_module_t ngx_http_token_module = {
	NGX_MODULE_V1,
	&ngx_http_token_module_ctx,
	ngx_http_token_commands,
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

char * ngx_http_token(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_core_loc_conf_t * clcf;
	clcf = (ngx_http_core_loc_conf_t *)ngx_http_conf_get_module_loc_conf(cf,ngx_http_core_module);
	clcf->handler = ngx_http_token_handler;
	return NGX_CONF_OK;
}

ngx_int_t ngx_http_token_handler(ngx_http_request_t *r)
{
	ngx_str_t response;
	ngx_http_token_ctx_t * ctx = ngx_http_get_module_ctx(r,ngx_http_token_module);
	if(ctx == NULL)
	{
		ctx = ngx_pcalloc(r->pool,sizeof(ngx_http_token_ctx_t));
		if(ctx == NULL)
			return NGX_ERROR;
		ngx_http_set_ctx(r,ctx,ngx_http_token_module);
	}
	ngx_str_t zName = ngx_string("test");
	ngx_shm_zone_t *shm_zone = ngx_http_get_shm_zone(&zName);
	ngx_http_token_conf_t * conf = shm_zone->data;
	ctx->shm_zone = shm_zone;

	ngx_int_t ret = query_string(r,ctx);
	if(ret == -1)
		return NGX_HTTP_NOT_FOUND;

	ngx_log_error(NGX_LOG_INFO,r->pool->log,
			0,"[request uri] %s %s %L",ctx->usrid,ctx->aesData,ctx->requesttime);

	size_t len = ngx_strlen(ctx->usrid);
	uint32_t hash = ngx_crc32_short(ctx->usrid,len);

	ngx_shmtx_lock(&conf->shpool->mutex);
	ngx_int_t rc = ngx_http_token_lookup(conf,hash,ctx);
	ngx_shmtx_unlock(&conf->shpool->mutex);

	uint64_t validTime = 259200000;
	if(rc == NGX_SHM_HIT){
		if(validTime >= ctx->requesttime - ctx->timer)
			ret = deaes_data(r,ctx);
		else
			ret = NGX_TIMER_EXPIRES;
		ngx_log_error(NGX_LOG_INFO,r->pool->log,0,
			"[token message des]%d %s %s %s %L",ret,ctx->session,ctx->aesKey,ctx->appDevice,ctx->timer);
		if(ret == NGX_TIMER_VALID || ret == NGX_TIMER_UPDATE){
			ngx_shmtx_lock(&conf->shpool->mutex);
			ngx_int_t rc = ngx_http_token_update(conf,hash,ctx);
			ngx_shmtx_unlock(&conf->shpool->mutex);
			ngx_log_debug1(NGX_LOG_DEBUG_CORE,r->pool->log,0,"myctx->timer:%L",ctx->timer);
			if(rc == NGX_SHM_MISS)
				return NGX_ERROR;

			if(ret == NGX_TIMER_UPDATE)
				ngx_http_upstream_tokenServer_toUpdate_handler(r);
			if(ret == NGX_TIMER_VALID)
				ngx_http_upstream_realServer_handler(r);
		}
		else if(ret == NGX_TIMER_EXPIRES) 
		{	
			ngx_str_set(&response,"expires");
			return ngx_http_sendmsg_client(r,response);
		}
		else 
		{	
			ngx_str_set(&response,"failed");
			return ngx_http_sendmsg_client(r,response);
		}
	}
	else
		ngx_http_upstream_tokenServer_toGet_handler(r);
	return NGX_OK;
}

ngx_int_t ngx_http_upstream_realServer_handler(ngx_http_request_t *r)
{
	ngx_http_token_ctx_t * myctx = ngx_http_get_module_ctx(r,ngx_http_token_module);
	ngx_http_post_subrequest_t *psr = ngx_pcalloc(r->pool,sizeof(ngx_http_post_subrequest_t));
	if(psr == NULL)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	psr->handler = token_subrequest_post_real_handler;
	psr->data = myctx;
	
	ngx_str_t sub_prefix = ngx_string("/rest/index");
	ngx_http_request_t *sr;
	ngx_int_t rc = ngx_http_subrequest(r,&sub_prefix,NULL,&sr,psr,NGX_HTTP_SUBREQUEST_IN_MEMORY);
	if(rc != NGX_OK)
		return NGX_HTTP_BAD_REQUEST;
	return NGX_DONE;
}

ngx_int_t token_subrequest_post_real_handler(ngx_http_request_t *r,void *data,ngx_int_t rc)
{
	ngx_http_request_t			*pr = r->parent;
	ngx_http_token_ctx_t		*myctx = data;

	pr->headers_out.status = r->headers_out.status;
	if(r->headers_out.status == NGX_HTTP_OK)
	{
		ngx_log_debug0(NGX_LOG_DEBUG_CORE,r->pool->log,0,"realServer success");
	}
	ngx_buf_t * pRecvBuf = &r->upstream->buffer;
	u_char *json = pRecvBuf->pos;
	ngx_log_debug1(NGX_LOG_DEBUG_CORE,r->pool->log,0,"realServer response = %s",pRecvBuf->pos);

	ngx_int_t ret = cJSON_to_str((char *)json,myctx);
	if(ret == -1)
		ngx_log_debug0(NGX_LOG_DEBUG_CORE,r->pool->log,0,"cJSON_ERROR");
	ngx_log_debug1(NGX_LOG_DEBUG_CORE,r->pool->log,0,"JSON body = %s",json);
	myctx->ser_data.len = ngx_strlen(json);
	myctx->ser_data.data = json;

	pr->write_event_handler = (void *)token_post_real_handler;
	return NGX_OK;
}

ngx_int_t token_post_real_handler(ngx_http_request_t *r)
{
	if(r->headers_out.status != NGX_HTTP_OK)
	{
		ngx_http_finalize_request(r,r->headers_out.status);
		return NGX_HTTP_BAD_REQUEST;
	}
	ngx_http_token_ctx_t * myctx = ngx_http_get_module_ctx(r,ngx_http_token_module);
	ngx_str_t response = aes_data(r,myctx);
	ngx_int_t rc = ngx_http_sendmsg_client(r,response);
	ngx_http_finalize_request(r,rc);
	return NGX_OK;
}


ngx_int_t ngx_http_upstream_tokenServer_toGet_handler(ngx_http_request_t *r)
{
	ngx_http_token_ctx_t * myctx = ngx_http_get_module_ctx(r,ngx_http_token_module);
	ngx_http_post_subrequest_t * psr = ngx_pcalloc(r->pool,sizeof(ngx_http_post_subrequest_t));
	if(psr == NULL)
	{
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
	psr->handler = token_subrequest_post_get_handler;
	psr->data = myctx;

	ngx_str_t sub_prefix = ngx_string("/rest/updatesession");
	ngx_str_t sub_args;
	sub_args.len = 13+ngx_strlen(myctx->usrid)+13;
	sub_args.data = ngx_pcalloc(r->pool,sub_args.len+1);
	sprintf((char*)sub_args.data,"usrid=%s&timer=%ld",myctx->usrid,myctx->requesttime);

	ngx_http_request_t *sr;
	ngx_int_t rc = ngx_http_subrequest(r,&sub_prefix,&sub_args,&sr,psr,NGX_HTTP_SUBREQUEST_IN_MEMORY);
	if(rc != NGX_OK)
		return NGX_HTTP_BAD_REQUEST;
	ngx_pfree(r->pool,sub_args.data);
	return NGX_DONE;
}

ngx_int_t token_subrequest_post_get_handler(ngx_http_request_t *r,void *data,ngx_int_t rc)
{
	ngx_http_request_t			*pr = r->parent;
	ngx_http_token_ctx_t		*myctx = data;
	pr->headers_out.status = r->headers_out.status;

	if(r->headers_out.status == NGX_HTTP_OK)
	{
		ngx_log_debug0(NGX_LOG_DEBUG_CORE,r->pool->log,
				0,"getsession subrequest success");
	}
	ngx_uint_t i = 0;
	u_char item[128] = {0};
	ngx_buf_t * pRecvBuf = &r->upstream->buffer;
	ngx_log_debug1(NGX_LOG_DEBUG_CORE,r->pool->log,
			0,"getsession response = %s",pRecvBuf->pos);
	ngx_memcpy(item,pRecvBuf->pos,r->upstream->length);
	ngx_log_debug1(NGX_LOG_DEBUG_CORE,r->pool->log,
			0,"getsession response item = %s",item);
	
	u_char *temp;
	temp = (u_char *)strtok((char*)item," ");
	while(i++ < 4)
	{
		switch(i)
		{
			case 1:temp = (u_char*)strtok(NULL," ");
				   ngx_memcpy(myctx->session,temp,ngx_strlen(temp));break;
			case 2:temp = (u_char*)strtok(NULL," ");
				   ngx_memcpy(myctx->aesKey,temp,ngx_strlen(temp));break;
			case 3:temp = (u_char*)strtok(NULL," ");
				   ngx_memcpy(myctx->appDevice,temp,ngx_strlen(temp));break;
			case 4:temp = (u_char*)strtok(NULL," ");break;
			default:ngx_log_debug0(NGX_LOG_DEBUG_CORE,r->pool->log,0,"SPILT_ERROR");
		}
	}
	myctx->timer = (uint64_t)ngx_atosz(temp,ngx_strlen(temp)); 

	ngx_log_debug4(NGX_LOG_DEBUG_CORE,r->pool->log,0,
		"[token message] %s %s %s %L",myctx->session,myctx->aesKey,myctx->appDevice,myctx->timer);
	pr->write_event_handler = (void *)token_post_get_handler;
	return NGX_OK;
}

ngx_int_t token_post_get_handler(ngx_http_request_t *r)
{
	ngx_str_t response;
	if(r->headers_out.status != NGX_HTTP_OK)
	{
		ngx_http_finalize_request(r,r->headers_out.status);
		return NGX_HTTP_BAD_REQUEST;
	}

	ngx_http_token_ctx_t * myctx = ngx_http_get_module_ctx(r,ngx_http_token_module);
	ngx_http_token_conf_t		*conf = myctx->shm_zone->data;
	ngx_int_t ret = deaes_data(r,myctx);
	ngx_log_error(NGX_LOG_INFO,r->pool->log,0,
		"[token message des]%d %s %s %s %L",ret,myctx->session,myctx->aesKey,myctx->appDevice,myctx->timer);
	if(ret == NGX_TIMER_VALID || ret == NGX_TIMER_UPDATE)
	{
		ngx_shmtx_lock(&conf->shpool->mutex);
		ngx_int_t rc = ngx_http_token_insert(conf,myctx);
		ngx_shmtx_unlock(&conf->shpool->mutex);
		if( rc != NGX_DECLINED)
			return NGX_HTTP_BAD_REQUEST;
		ngx_http_upstream_realServer_handler(r);
		return NGX_OK;
	}
	else if(ret == NGX_TIMER_EXPIRES)
	{	
		ngx_str_set(&response,"expires");
		return ngx_http_sendmsg_client(r,response);
	}
	else
	{	
		ngx_str_set(&response,"failed");
		return ngx_http_sendmsg_client(r,response);
	}
}

ngx_int_t ngx_http_upstream_tokenServer_toUpdate_handler(ngx_http_request_t *r)
{
	ngx_http_token_ctx_t * myctx = ngx_http_get_module_ctx(r,ngx_http_token_module);
	ngx_http_post_subrequest_t *psr = ngx_pcalloc(r->pool,sizeof(ngx_http_post_subrequest_t));
	if(psr == NULL)
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	psr->handler = token_subrequest_post_update_handler;
	psr->data = myctx;
	ngx_str_t sub_prefix = ngx_string("/rest/updatesession");

	ngx_str_t sub_args;
	sub_args.len = 13+ngx_strlen(myctx->usrid)+13;
	sub_args.data = ngx_pcalloc(r->pool,sub_args.len+1);
	sprintf((char*)sub_args.data,"usrid=%s&timer=%ld",myctx->usrid,myctx->timer);

	ngx_http_request_t *sr;
	ngx_int_t rc = ngx_http_subrequest(r,&sub_prefix,&sub_args,&sr,psr,NGX_HTTP_SUBREQUEST_IN_MEMORY);
	if(rc != NGX_OK)
		return NGX_HTTP_BAD_REQUEST;
	ngx_pfree(r->pool,sub_args.data);
	return NGX_DONE;
}

ngx_int_t token_subrequest_post_update_handler(ngx_http_request_t *r,void *data,ngx_int_t rc)
{
	ngx_http_request_t			*pr = r->parent;
	pr->headers_out.status = r->headers_out.status;
	if(r->headers_out.status == NGX_HTTP_OK)
	{
		ngx_log_debug0(NGX_LOG_DEBUG_CORE,r->pool->log,0,"update subrequest success");
	}
	ngx_buf_t *pRecvBuf = &r->upstream->buffer;
	ngx_log_debug1(NGX_LOG_DEBUG_CORE,r->pool->log,0,"update response = %s",pRecvBuf->pos);

	pr->write_event_handler = (void *)token_post_update_handler;
	return NGX_OK;
}

ngx_int_t token_post_update_handler(ngx_http_request_t *r)
{
	if(r->headers_out.status != NGX_HTTP_OK)
	{
		ngx_http_finalize_request(r,r->headers_out.status);
		return NGX_HTTP_BAD_REQUEST;
	}
	ngx_http_upstream_realServer_handler(r);
	return NGX_OK;
}

ngx_int_t ngx_http_sendmsg_client(ngx_http_request_t *r,ngx_str_t response)
{
	ngx_log_error(NGX_LOG_INFO,r->pool->log,0,"[response] %s",response.data);
	ngx_str_t type = ngx_string("text/plain; charset=GBK");

	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = response.len;
	r->headers_out.content_type = type;

	ngx_int_t rc = ngx_http_send_header(r);
	if( rc == NGX_ERROR || rc > NGX_OK || r->header_only){
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
