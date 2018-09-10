 ///
 /// @file    func.c
 /// @author  faith(kh_faith@qq.com)
 /// @date    2018-07-04 09:43:01
 ///
 
#include "ngx_http_token_module.h"
#include <stdint.h>

ngx_int_t query_string(ngx_http_request_t *r,ngx_http_token_ctx_t *myctx)//解析uri
{
	u_char args[300] = {0};
	u_char requesttime[64] = {0};
	ngx_memcpy(args,r->args.data,r->args.len);
	u_char *p = args;
	u_char match[3][16]={"usrid","data","requesttime"};
	ngx_uint_t i = 0;
	ngx_uint_t j = 0;
	ngx_int_t c = 0;
	for (; i <= r->args.len; i++)
	{
		if(ngx_strncmp(p + i, match[c],ngx_strlen(match[c])) == 0
				&& *(p + i + ngx_strlen(match[c])) == '=')
		{
			i = i + ngx_strlen(match[c]) + 1;
			for(j = i;j <= r->args.len;j++)
			{
				if(*(p + j) == '&' || c == 2)
				{
					switch(c)
					{
						case 0:
							   ngx_memzero(myctx->usrid,j-i+1);
							   ngx_memcpy(myctx->usrid,p+i,j-i);
							   break;
						case 1:
							   ngx_memzero(myctx->aesData,j-i+1);
							   ngx_memcpy(myctx->aesData,p+i,j-i);
							   break;
						case 2:
							   ngx_memcpy(requesttime,p+i,r->args.len-i);
							   myctx->requesttime = (uint64_t)ngx_atosz(requesttime,ngx_strlen(requesttime));
							   ngx_log_debug1(NGX_LOG_DEBUG_CORE,r->pool->log,0,"myctx->requesttime = %L",myctx->requesttime);
							   break;
						default:
							   return NGX_URI_ERROR;
					}
					c++;
					i = j;
					break;
				}
			}
		}
	}
	if(c == 3)
		return NGX_URI_RIGHT;
	return NGX_URI_ERROR;
}
//ngx_int_t query_string(ngx_http_request_t *r,ngx_http_token_ctx_t *myctx)//解析uri
//{
//	char match[3][12]={"usrid","data","requesttime"};
//	u_char* str1 = ngx_strnstr(r->args.data,match[1],strlen(match[1]));
//	u_char* str2 = ngx_strnstr(r->args.data,match[2],strlen(match[2]));
//	u_char* str3 = ngx_strnstr(r->args.data,match[3],strlen(match[3]));
//
//	ngx_int_t slen1 = strlen(match[1])+1;
//	ngx_int_t slen2 = strlen(match[2])+1;
//	ngx_int_t slen3 = strlen(match[3])+1;
//	myctx->usrid = ngx_pcalloc(r->pool,str2-(str1+slen1+2));
//	ngx_memcpy(myctx->usrid,str1+slen1,str2-(str1+slen1+1));
//	ngx_log_debug1(NGX_LOG_DEBUG_CORE,r->pool->log,0,"[usrid] %s ",myctx->usrid);
//	myctx->aesData = ngx_pcalloc(r->pool,str3-(str2+slen2+2));
//	ngx_memcpy(myctx->aesData,str2+slen2,str3-(str2+slen2+1));
//	ngx_log_debug1(NGX_LOG_DEBUG_CORE,r->pool->log,0,"[aesData] %s ",myctx->aesData);
//	u_char *requesttime = ngx_pcalloc(r->pool,r->args.data+r->args.len-(str3+slen3+1));
//	ngx_memcpy(requesttime,str3+slen3,r->args.data+r->args.len-(str3+slen3));
//	myctx->requesttime = (uint64_t)ngx_atosz(requesttime,ngx_strlen(requesttime));
//	ngx_log_debug1(NGX_LOG_DEBUG_CORE,r->pool->log,0,"[requesttime] %L ",myctx->requesttime);
//	return NGX_URI_RIGHT;
//}
ngx_int_t str_n(u_char *str,u_char (*p)[33],ngx_int_t n)
{
	ngx_int_t i=0,j=0,k=0;
	u_char *temp = str;
	ngx_int_t len = ngx_strlen(str);
	while(i <= len)             //数据分段
	{
		if(str[i] == ' '||str[i] == '\0')
		{
			ngx_memzero(p[j],i-k);
			ngx_memcpy(p[j],temp,i-k);
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
//解密，并对比requesttime，可添加设备号的对比
ngx_int_t deaes_data(ngx_http_request_t *r,ngx_http_token_ctx_t *myctx)
{
	ngx_str_t pencode;   //编码数据
	ngx_str_t pdecode;   //解码数据
	u_char c[128];
	ngx_memzero(c,128);

	pencode.len = ngx_strlen(myctx->aesData);
	pencode.data = ngx_pcalloc(r->pool,pencode.len + 1);
	ngx_memcpy(pencode.data,myctx->aesData,pencode.len);
	//ngx_log_stderr(0,"pencode: %s",pencode.data);

	pdecode.len = ngx_base64_decoded_length(pencode.len);
	pdecode.data = ngx_pcalloc(r->pool,pdecode.len + 1);
	ngx_decode_base64(&pdecode,&pencode);     //base64解码
	//ngx_log_stderr(0,"pdecode: %s",pdecode.data);

	ngx_memcpy(c,pdecode.data,pdecode.len);
	ngx_int_t clen = pdecode.len;
	InvCipher_n(c,clen,myctx->aesKey);         //aes算法解密
	//ngx_log_stderr(0,"c: %s",c);
	ngx_pfree(r->pool,pencode.data);
	ngx_pfree(r->pool,pdecode.data);
	
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
			ngx_log_debug2(NGX_LOG_DEBUG_CORE,r->pool->log,0,"Device : %s,ret = %d",temp,ret);
			if(ret != 0)
				return NGX_TEST_ERROR;
		}
		if(i == 2)
			break;
	}
	ngx_log_debug3(NGX_LOG_DEBUG_CORE,r->pool->log,0,"requesttime:%L,aesTime:%L,ret:%d",myctx->requesttime,aesTime,myctx->requesttime-aesTime);
	if(myctx->requesttime-aesTime == 0)  //对比请求时间
	{
		uint64_t validTime = 259200000;
		uint64_t updateTime = 86400000;
		ngx_log_debug3(NGX_LOG_DEBUG_CORE,r->pool->log,0,"requesttime:%L,myctx->timer:%L,ret:%L",myctx->requesttime,myctx->timer,myctx->requesttime-myctx->timer);
		if(validTime >= myctx->requesttime - myctx->timer)
		{
			if(updateTime >= myctx->requesttime - myctx->timer)
				return NGX_TIMER_VALID;
			else
				return NGX_TIMER_UPDATE;
		}
		else
			return NGX_TIMER_EXPIRES;
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

	ngx_pfree(r->pool,pcur.data);
	
	return pencode;
}
ngx_int_t cJSON_to_str(char *json_string,ngx_http_token_ctx_t *myctx)
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
