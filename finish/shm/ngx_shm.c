#include "ngx_shm.h"
#include <assert.h>

ngx_array_t *g_shm_list;

void ngx_http_token_rbtree_insert_value(ngx_rbtree_node_t* temp,ngx_rbtree_node_t* node,ngx_rbtree_node_t* sentinel);
ngx_int_t ngx_shm_init_zone(ngx_shm_zone_t *shm_zone, void *data);

ngx_shm_zone_t* 
ngx_shm_init(ngx_conf_t *cf, ngx_str_t* name, size_t size, void* module)
{
	ngx_http_token_conf_t* 		conf;
	ngx_shm_zone_t                  *zone;
	
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_token_conf_t));
    if (conf == NULL) {
        return NULL; 
    }

    zone = ngx_shared_memory_add(cf, name, size, module);
    if (zone == NULL) {
		conf = NULL;
        return NULL;
    }

    conf->shmsize = size;
	conf->name = name;	
	conf->log = &cf->cycle->new_log;

    if (zone->data) {
        conf = zone->data;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "[ngx_shm] ngx_shm_init \"%V\" is already defined as "
                           "\"%V\"", name, conf->name);
        return NULL;
    }

    zone->init = ngx_shm_init_zone;
    zone->data = conf;

  	return zone;
}

ngx_int_t
ngx_shm_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_token_conf_t  *oconf = data;
	ngx_http_token_conf_t  *conf;
    size_t              len;
    

    conf = shm_zone->data;

    if (oconf) {
        conf->sh = oconf->sh;
        conf->shpool = oconf->shpool;

        goto done;
    }

    conf->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        conf->sh = conf->shpool->data;

        goto done;
    }

    conf->sh = ngx_slab_alloc(conf->shpool, sizeof(ngx_http_token_shm_t));
    if (conf->sh == NULL) {
        return NGX_ERROR;
    }

    conf->shpool->data = conf->sh;

    ngx_rbtree_init(&conf->sh->rbtree, &conf->sh->sentinel,
                    ngx_http_token_rbtree_insert_value);

    ngx_queue_init(&conf->sh->queue);

    len = sizeof(" in ngx_shared_map zone \"\"") + shm_zone->shm.name.len;

    conf->shpool->log_ctx = ngx_slab_alloc(conf->shpool, len);
    if (conf->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(conf->shpool->log_ctx, " in ngx_shared_map zone \"%V\"%Z",
                &shm_zone->shm.name);

done:

    return NGX_OK;
}


//红黑树插入方法，可以初始化红黑树conf->sh->rbtree
void ngx_http_token_rbtree_insert_value(ngx_rbtree_node_t* temp,ngx_rbtree_node_t* node,ngx_rbtree_node_t* sentinel) 
{
    ngx_rbtree_node_t** p;
    ngx_http_token_node_t* lrn;
    ngx_http_token_node_t* lrnt;
    for (;;) 
	{
        if (node->key < temp->key) 
		{
            p = &temp->left;
        }
		else if (node->key > temp->key)
		{
            p = &temp->right;
        }
		else 
		{
            lrn = (ngx_http_token_node_t*)&node->data;
            lrnt = (ngx_http_token_node_t*)&temp->data;
            p = ngx_memn2cmp(lrn->data, lrnt->data, lrn->len, lrnt->len) < 0? &temp->left : &temp->right;
        }
        if (*p == sentinel){
            break;
        }
        temp = *p;
    }
    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}

//释放共享内存空间，删除队列的最后一个结点
void ngx_http_token_expire( ngx_http_token_conf_t* conf)
{
    if (ngx_queue_empty(&conf->sh->queue))
	{
        return;
    }
	//找到conf->sh->queue,一个lru队列的最后一个结点
    ngx_queue_t* q = ngx_queue_last(&conf->sh->queue);
    ngx_http_token_node_t* lr =ngx_queue_data(q, ngx_http_token_node_t, queue);
    ngx_rbtree_node_t* node = (ngx_rbtree_node_t*)((u_char*)lr - offsetof(ngx_rbtree_node_t, data));

	size_t size = offsetof(ngx_rbtree_node_t, data) + offsetof(ngx_http_token_node_t,data) +lr->len;
	conf->shmsize += size;
	ngx_log_debug1(NGX_LOG_DEBUG_CORE, conf->log, 0,"conf->shmsize_expire = %d",conf->shmsize);

	//删除结点
    ngx_queue_remove(q);
    ngx_rbtree_delete(&conf->sh->rbtree, node);

    ngx_slab_free_locked(conf->shpool, node);
}
//在共享内存中查找key
ngx_int_t ngx_http_token_lookup(ngx_http_token_conf_t* conf,ngx_uint_t hash,ngx_http_token_ctx_t *myctx ) 
{
    ngx_rbtree_node_t* node = conf->sh->rbtree.root;
    ngx_rbtree_node_t* sentinel = conf->sh->rbtree.sentinel;

    ngx_http_token_node_t* lr; 
	//hash查找
    while (node != sentinel) {
        if (hash < node->key) {
            node = node->left;
            continue;
        }
        if (hash > node->key) {
            node = node->right;
            continue;
        }
        lr = (ngx_http_token_node_t*)&node->data;
        ngx_int_t rc = ngx_strncmp(myctx->usrid, lr->data, lr->len);
        if (rc == 0) {//如果找到
			ngx_log_debug0(NGX_LOG_DEBUG_CORE, conf->log, 0,"hit");
			ngx_memcpy(myctx->session,lr->session,ngx_strlen(lr->session));
			ngx_memcpy(myctx->aesKey,lr->aesKey,ngx_strlen(lr->aesKey));
			ngx_memcpy(myctx->appDevice,lr->appDevice,ngx_strlen(lr->appDevice));
			myctx->timer = lr->timer;
            return NGX_SHM_HIT;
        }
        node = rc < 0 ? node->left : node->right;
    }
    return NGX_SHM_MISS;    
}
ngx_int_t ngx_http_token_update(ngx_http_token_conf_t* conf,ngx_uint_t hash,ngx_http_token_ctx_t *myctx) 
{
    ngx_rbtree_node_t* node = conf->sh->rbtree.root;
    ngx_rbtree_node_t* sentinel = conf->sh->rbtree.sentinel;

    ngx_http_token_node_t* lr; 
	//hash查找
    while (node != sentinel) {
        if (hash < node->key) {
            node = node->left;
            continue;
        }
        if (hash > node->key) {
            node = node->right;
            continue;
        }
        lr = (ngx_http_token_node_t*)&node->data;
        ngx_int_t rc = ngx_strncmp(myctx->usrid, lr->data, lr->len);
        if (rc == 0) {//如果找到
			if(ngx_strncmp(myctx->session,lr->session,ngx_strlen(myctx->session)) != 0)
			{
				ngx_memcpy(lr->session,myctx->session,ngx_strlen(myctx->session));
				ngx_memcpy(lr->aesKey,myctx->aesKey,ngx_strlen(myctx->aesKey));
				ngx_memcpy(lr->appDevice,myctx->appDevice,ngx_strlen(myctx->appDevice));
			}
			lr->timer = myctx->requesttime;
            ngx_queue_remove(&lr->queue);
            ngx_queue_insert_head(&conf->sh->queue, &lr->queue);
            return NGX_SHM_HIT;
        }
        node = rc < 0 ? node->left : node->right;
    }
    return NGX_SHM_MISS;    
}
ngx_int_t ngx_http_token_insert(ngx_http_token_conf_t* conf,ngx_http_token_ctx_t *myctx) 
{
	size_t len = ngx_strlen(myctx->usrid);
	uint32_t hash = ngx_crc32_short(myctx->usrid, len);
    ngx_rbtree_node_t* node = conf->sh->rbtree.root;
    ngx_http_token_node_t* lr;    
	//计算要插入的长度
	size_t size = offsetof(ngx_rbtree_node_t, data)+ offsetof(ngx_http_token_node_t,data) +len;
	conf->shmsize -= size;
	ngx_log_debug1(NGX_LOG_DEBUG_CORE,conf->log, 0,"shm_zone_insert = %s",myctx->usrid);
	//如果共享内存空间不够，释放空间
    node = (ngx_rbtree_node_t*)ngx_slab_alloc_locked(conf->shpool,size);
    while (node == NULL) {//共享内存不足
		ngx_http_token_expire(conf);
		node = (ngx_rbtree_node_t*)ngx_slab_alloc_locked(conf->shpool,size);
    }
	node->key = hash;

    lr = (ngx_http_token_node_t*)&node->data;
	lr->len = ngx_strlen(myctx->usrid); 
    ngx_memcpy(lr->data,myctx->usrid,lr->len);
	ngx_memcpy(lr->session,myctx->session,ngx_strlen(myctx->session));
	ngx_memcpy(lr->aesKey,myctx->aesKey,ngx_strlen(myctx->aesKey));
	ngx_memcpy(lr->appDevice,myctx->appDevice,ngx_strlen(myctx->appDevice));
	lr->timer = myctx->timer;

//	ngx_log_debug4(NGX_LOG_DEBUG_CORE,myctx->pool->log,0,
//			"[shm insert] %s %s %s %L",lr->session,lr->aesKey,lr->appDevice,lr->timer);
	//插入红黑树，插入队首
    ngx_rbtree_insert(&conf->sh->rbtree, node);
    ngx_queue_insert_head(&conf->sh->queue, &lr->queue);
    return NGX_DECLINED;    
}


ngx_shm_zone_t * 
ngx_http_get_shm_zone(ngx_str_t *shm_name) {
	
	ngx_shm_zone_t 		**zone;
    size_t 				i;
    zone = g_shm_list->elts;

    if (g_shm_list == NULL || zone == NULL) {
    	return NULL;
    }

	for (i = 0; i < g_shm_list->nelts; i++) {
	
		if( shm_name->len == 0 && i == 0) {

			ngx_log_error(NGX_LOG_DEBUG, ((ngx_http_token_conf_t *)(zone[i]->data))->log, 0,
			                    "[shm_zone] process=[%d] get_shm_zone default name is  %V \n",
			                    ngx_getpid(),&zone[i]->shm.name);

			return zone[i];
		}
        
		if ( ngx_strcmp(shm_name->data, zone[i]->shm.name.data) == 0) {

			ngx_log_error(NGX_LOG_DEBUG, ((ngx_http_token_conf_t *)(zone[i]->data))->log, 0,
			                    "[shm_zone] process=[%d] get_shm_zone name is  %V \n",
			                    ngx_getpid(),shm_name);

            return zone[i];
		}
    }
	
	return NULL;
}


