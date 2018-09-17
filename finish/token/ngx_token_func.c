 ///
 /// @file    func.c
 /// @author  faith(kh_faith@qq.com)
 /// @date    2018-07-04 09:43:01
 ///
 
#include "ngx_http_token_module.h"
#include <stdint.h>

ngx_int_t query_string(ngx_http_request_t *r,ngx_http_token_ctx_t *myctx)//解析uri
{
	ngx_uint_t			i = 0;
	u_char				*temp;
	u_char				*str;

	temp = (u_char*)strtok((char*)r->args.data,"&");
	str = ngx_strnstr(temp,"=",ngx_strlen(temp));
	ngx_memcpy(myctx->usrid,str+1,ngx_strlen(str));
	ngx_log_debug1(NGX_LOG_DEBUG_CORE,r->pool->log,0,"[usrid] %s ",myctx->usrid);
	while(i++ < 2)
	{
		switch(i)
		{
			case 1:temp = (u_char*)strtok(NULL,"&");
				   str = ngx_strnstr(temp,"=",ngx_strlen(temp));
				   ngx_memcpy(myctx->aesData,str+1,ngx_strlen(str)-1);
				   ngx_log_debug1(NGX_LOG_DEBUG_CORE,r->pool->log,
						   0,"[aesData] %s ",myctx->aesData);break;
			case 2:temp = (u_char*)strtok(NULL," ");
				   str = ngx_strnstr(temp,"=",ngx_strlen(temp));
				   myctx->requesttime = (uint64_t)ngx_atosz(str+1,ngx_strlen(str)-1);
				   ngx_log_debug2(NGX_LOG_DEBUG_CORE,r->pool->log,
						   0,"[requesttime]%s %L ",str,myctx->requesttime);break;
			default: return NGX_URI_ERROR;
		}
	}
	return NGX_URI_RIGHT;
}
//解密，并对比requesttime，可添加设备号的对比
ngx_int_t deaes_data(ngx_http_request_t *r,ngx_http_token_ctx_t *myctx)
{
	ngx_str_t			pencode;   //编码数据
	ngx_str_t			pdecode;   //解码数据
	u_char				c[128];
	ngx_memzero(c,128);

	pencode.len = ngx_strlen(myctx->aesData);
	pencode.data = ngx_pcalloc(r->pool,pencode.len + 1);
	ngx_memcpy(pencode.data,myctx->aesData,pencode.len);

	pdecode.len = ngx_base64_decoded_length(pencode.len);
	pdecode.data = ngx_pcalloc(r->pool,pdecode.len + 1);
	ngx_decode_base64(&pdecode,&pencode);     //base64解码

	ngx_memcpy(c,pdecode.data,pdecode.len);
	ngx_int_t clen = pdecode.len;
	InvCipher_n(c,clen,myctx->aesKey);         //aes算法解密

	ngx_log_error(NGX_LOG_INFO,r->pool->log,0,"c : %s",c);
	
	return ngx_time_cmp(r,c,myctx);
}
ngx_int_t ngx_time_cmp(ngx_http_request_t *r,u_char *c,ngx_http_token_ctx_t *myctx)
{
	ngx_uint_t i = 0;
	u_char *temp;
	temp = (u_char*)strtok((char*)c," ");
	uint64_t aesTime = (uint64_t)ngx_atosz(temp,ngx_strlen(temp));
	while(temp)
	{
		i++;
		temp = (u_char*)strtok(NULL," ");
		if(i == 1)
		{
			ngx_int_t ret = ngx_strcmp(myctx->appDevice,temp);
			ngx_log_debug3(NGX_LOG_DEBUG_CORE,r->pool->log,0,
					"myctx : %s,Device : %s,ret = %d",myctx->appDevice,temp,ret);
			if(ret != 0)
				return NGX_TEST_ERROR;
		}
		if(i == 2)
			break;
	}
	ngx_log_debug3(NGX_LOG_INFO,r->pool->log,0,
			"requesttime:%L,aesTime:%L,ret:%d",myctx->requesttime,
			aesTime,myctx->requesttime-aesTime);
	if(myctx->requesttime-aesTime == 0)  //对比请求时间
	{
		uint64_t updateTime = 86400000;
		if(updateTime >= myctx->requesttime - myctx->timer)
			return NGX_TIMER_VALID;
		else
			return NGX_TIMER_UPDATE;
	}	
	else
		return NGX_TEST_ERROR;
}
ngx_str_t aes_data(ngx_http_request_t *r,ngx_http_token_ctx_t *myctx)
{
	u_char p[16];
	ngx_memcpy(p,myctx->ser_data.data,myctx->ser_data.len);
	ngx_int_t plen = myctx->ser_data.len;
//	if(plen == 0)

	ngx_int_t i;
	ngx_int_t pstrlen = plen;
	if(pstrlen % 16 != 0) {
		plen = (plen / 16 + 1) * 16;
		for(i=pstrlen;i<plen;i++)
			p[i] = 0;
	}
	Cipher_n(p,plen,myctx->aesKey);//加密
	ngx_str_t pcur;
	pcur.len = plen;
	pcur.data = ngx_pcalloc(r->pool,pcur.len + 1);
	ngx_memcpy(pcur.data,p,pcur.len);

	ngx_str_t pencode;//base64编码
	pencode.len = ngx_base64_encoded_length(pcur.len);
	pencode.data = ngx_pcalloc(r->pool,pencode.len + 1);
	ngx_encode_base64(&pencode,&pcur);

	return pencode;
}
ngx_int_t cJSON_to_str(char *json_string,ngx_http_token_ctx_t *myctx)
{
	cJSON *root=cJSON_Parse(json_string);
	if (!root)
		return -1;
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
