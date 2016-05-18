/*
 * =====================================================================================
 *
 *       Filename:  ngx_http_upstreamTest_module.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  04/20/2016 02:43:05 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Dengbzh (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#include<ngx_config.h>
#include<ngx_core.h>
#include<ngx_http.h>

typedef struct{
    ngx_int_t port;
    ngx_str_t ip;
}ngx_cluster_t;

typedef struct{
    ngx_http_upstream_conf_t upstream;
    ngx_cluster_t clusterA;
    ngx_cluster_t clusterB;
    ngx_cluster_t clusterC;
}ngx_http_upstreamTest_conf_t;


typedef struct{
    ngx_http_status_t status;
}ngx_http_upstreamTest_ctx_t;

static ngx_int_t ngx_http_upstreamTest_create_request(ngx_http_request_t *r);
static void ngx_http_upstreamTest_finalize_request(ngx_http_request_t *r,ngx_int_t rc);

static void *ngx_http_upstreamTest_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_upstreamTest_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

//static ngx_int_t ngx_http_upstreamTest_init(ngx_conf_t *cf);
static char *ngx_conf_my_upstream(ngx_conf_t *cf,ngx_command_t *cmd,void *conf);
static ngx_command_t ngx_http_upstreamTest_commands[]={
    {
        ngx_string("My_upstream"),
        NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
        ngx_conf_my_upstream,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("upstream_connect_timeout"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_upstreamTest_conf_t,upstream.connect_timeout),
        NULL
    },
    {
        ngx_string("upstream_send_timeout"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_upstreamTest_conf_t,upstream.send_timeout),
        NULL
    },
    {
        ngx_string("upstream_read_timeout"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_upstreamTest_conf_t,upstream.read_timeout),
        NULL
    },

    {
        ngx_string("upstream_store_access"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_access_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_upstreamTest_conf_t,upstream.store_access),
        NULL
    },
    {
        ngx_string("upstream_buffering"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_upstreamTest_conf_t,upstream.buffering),
        NULL
    },
     
    {
        ngx_string("upstream_buffer_num"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_upstreamTest_conf_t,upstream.bufs.num),
        NULL
    },
    {
        ngx_string("children_port"),
        NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_upstreamTest_conf_t,clusterA.port),
        NULL
    },
    {
        ngx_string("children_ip"),
        NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_upstreamTest_conf_t,clusterA.ip),
        NULL
    },
    {
        ngx_string("youth_port"),
        NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_upstreamTest_conf_t,clusterB.port),
        NULL
    },
    {
        ngx_string("youth_ip"),
        NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_upstreamTest_conf_t,clusterB.ip),
        NULL
    },
    {
        ngx_string("adult_port"),
        NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_upstreamTest_conf_t,clusterC.port),
        NULL
    },
    {
        ngx_string("adult_ip"),
        NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_upstreamTest_conf_t,clusterC.ip),
        NULL
    },


    ngx_null_command
    

};

static ngx_http_module_t ngx_http_upstreamTest_module_ctx = {
    NULL,
    //ngx_http_upstreamTest_init,
    NULL,

    NULL,
    NULL,

    NULL,
    NULL,

    ngx_http_upstreamTest_create_loc_conf,
    ngx_http_upstreamTest_merge_loc_conf
//    NULL
};


ngx_module_t ngx_http_upstreamTest_module = {
    NGX_MODULE_V1,
    &ngx_http_upstreamTest_module_ctx,
    ngx_http_upstreamTest_commands,
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
static ngx_str_t children = ngx_string("%V&&type=children");
static ngx_str_t youth = ngx_string("%V&&type=youth");
static ngx_str_t adult = ngx_string("%V&&type=adult");

static ngx_int_t
ngx_http_upstreamTest_create_request(ngx_http_request_t *r)
{
    ngx_http_upstreamTest_conf_t *upstream_conf = (ngx_http_upstreamTest_conf_t *)ngx_http_get_module_loc_conf(r,ngx_http_upstreamTest_module);
    ngx_http_upstream_t *u = r->upstream;
    ngx_int_t age = -1;
    size_t age_len = 0;
    if(r->args.len !=0 )
    {
        u_char *p = r->args.data;
        u_char *ep = r->args.data + r->args.len - 1;
        for(;p != ep; ++p)
        {
            if(*p == 'A')
            {
                if(ngx_strncmp(p,"Age",3) == 0)
                {
                    p += 4;
                    u_char *e = p;
                    while(*e <= '9' && *e >= '0')
                    {
                        age_len++;
                        if(e == ep)
                            break;
                        e++;
                    }
                    age = ngx_atoi(p,age_len);
                    if(age == NGX_ERROR)
                        age = -1;
                    break;
                }
            }
        }
    }

    ngx_str_t *backendQueryLine = NULL;
    static struct sockaddr_in  backendSockAddr;
    backendSockAddr.sin_family = AF_INET;

    u->resolved->sockaddr = (struct sockaddr *)&backendSockAddr;
    u->resolved->socklen = sizeof(struct sockaddr_in);
    u->resolved->naddrs = 1;
    ngx_int_t port;
    static u_char ip[20];
    if(age!= -1)
    {
        if(age <= 10)
        {
            backendQueryLine = &children;
            port = upstream_conf->clusterA.port;
            memcpy(ip,upstream_conf->clusterA.ip.data,upstream_conf->clusterA.ip.len);
            ip[upstream_conf->clusterA.ip.len] = '\0';
        }
        else if(age <= 20)
        {
            backendQueryLine = &youth;
            port = upstream_conf->clusterB.port;
            memcpy(ip,upstream_conf->clusterB.ip.data,upstream_conf->clusterB.ip.len);
            ip[upstream_conf->clusterB.ip.len] = '\0';
        }
        else
        {
            backendQueryLine = &adult;
            port = upstream_conf->clusterC.port;
            memcpy(ip,upstream_conf->clusterC.ip.data,upstream_conf->clusterC.ip.len);
            ip[upstream_conf->clusterC.ip.len] = '\0';
        }
    }
    else
        return NGX_ERROR;

    backendSockAddr.sin_port = htons((in_port_t)port);
    backendSockAddr.sin_addr.s_addr = inet_addr((const char*)ip);

    ngx_int_t queryLineLen = backendQueryLine->len + r->args.len - 2;

    ngx_buf_t *b = ngx_create_temp_buf(r->pool, queryLineLen);

    if(b == NULL)
        return NGX_ERROR;

    b->last = b->pos + queryLineLen;   

    ngx_snprintf(b->pos,queryLineLen,(char *)backendQueryLine->data,&r->args);

    r->upstream->request_bufs = ngx_alloc_chain_link(r->pool);
    if(r->upstream->request_bufs == NULL)
        return NGX_ERROR;

    r->upstream->request_bufs->buf = b;
    r->upstream->request_bufs->next = NULL;
//    r->subrequest_in_memory = 1;
    r->upstream->request_sent = 0;
    r->upstream->header_sent = 0;
    r->header_hash = 1;
    
    return NGX_OK;
}
static ngx_int_t
ngx_http_upstreamTest_process_status_line(ngx_http_request_t *r)
{
    return NGX_OK;
}

static ngx_int_t
ngx_http_upstreamTest_handler(ngx_http_request_t *r)
{

    static ngx_int_t visited_times = 0;
    ngx_http_upstreamTest_ctx_t *upstreamctx = ngx_http_get_module_ctx(r,ngx_http_upstreamTest_module);
    if(upstreamctx == NULL)
    {
        upstreamctx = ngx_pcalloc(r->pool,sizeof(ngx_http_upstreamTest_ctx_t));
        if(upstreamctx == NULL)
        {
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r,upstreamctx,ngx_http_upstream_module);
    }

    if(ngx_http_upstream_create(r) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR,r->connection->log,0,"ngx_http_upstream_create() failed");
        return NGX_ERROR;
    }
    ngx_http_upstreamTest_conf_t *upstreamconf = (ngx_http_upstreamTest_conf_t *)ngx_http_get_module_loc_conf(r,ngx_http_upstreamTest_module);
    ngx_http_upstream_t *u = r->upstream;
    u->conf = &upstreamconf->upstream;
    u->buffering = upstreamconf->upstream.buffering;
    u->resolved = (ngx_http_upstream_resolved_t*)ngx_pcalloc(r->pool,sizeof(ngx_http_upstream_resolved_t));
    if(u->resolved == NULL)
    {
        ngx_log_error(NGX_LOG_ERR,r->connection->log,0,"ngx_pcalloc resolved error. %s",strerror(errno));
        return NGX_ERROR;
    }

//    static struct sockaddr_in  backendSockAddr;
//    backendSockAddr.sin_family = AF_INET;
//    backendSockAddr.sin_port = htons((in_port_t)7777);
//    backendSockAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

//    u->resolved->sockaddr = (struct sockaddr *)&backendSockAddr;
//    u->resolved->socklen = sizeof(struct sockaddr_in);
//    u->resolved->naddrs = 1;

    u->create_request = ngx_http_upstreamTest_create_request;
    u->process_header = ngx_http_upstreamTest_process_status_line;
    u->finalize_request = ngx_http_upstreamTest_finalize_request;
    
  //  r->main->count++;
 //   ngx_http_upstream_init(r);
    if(!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD)))
        return NGX_HTTP_NOT_ALLOWED;

    u_char ngx_upstream_string[1024];
    ngx_sprintf(ngx_upstream_string,"Visited times: %d",++visited_times);
    ngx_log_error(NGX_LOG_EMERG,r->connection->log,0,"ngx_upstream_string: %s",ngx_upstream_string); 
    ngx_uint_t content_length = ngx_strlen(ngx_upstream_string);
    ngx_int_t rc;
    
    if(!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD)))
        return NGX_HTTP_NOT_ALLOWED;

    rc = ngx_http_discard_request_body(r);
    if(rc != NGX_OK)
    {
        ngx_log_error(NGX_LOG_EMERG,r->connection->log,0,"discard requst_body failed!");
        return rc;
    }
    
    ngx_str_set(&r->headers_out.content_type,"text/html");

    if(r->method == NGX_HTTP_HEAD)
    {
        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = content_length;
        ngx_log_error(NGX_LOG_EMERG,r->connection->log,0,"send respond head!");
        return ngx_http_send_header(r);
    }

    ngx_buf_t *b;
    b =  ngx_pcalloc(r->pool,sizeof(ngx_buf_t));
    if(b == NULL)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;

    ngx_chain_t out;
    out.buf = b;
    out.next = NULL;

    b->pos = ngx_upstream_string;
    b->last = ngx_upstream_string + content_length;
    b->memory = 1;
    b->last_buf = 1;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n  = content_length;

    rc = ngx_http_send_header(r);

    if(rc == NGX_ERROR || rc > NGX_OK || r->header_only)
        return rc;

    ngx_http_output_filter(r,&out);
    r->main->count++;
    ngx_http_upstream_init(r);
    return NGX_OK;
}

static void *
ngx_http_upstreamTest_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_upstreamTest_conf_t *conf;
    
    conf = ngx_pcalloc(cf->pool,sizeof(ngx_http_upstreamTest_conf_t));
    if(conf == NULL)
    {
        return NULL;
    }

    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout =  NGX_CONF_UNSET_MSEC;

    conf->upstream.store_access = NGX_CONF_UNSET_UINT;
    conf->upstream.buffering = NGX_CONF_UNSET;

    conf->upstream.bufs.num = NGX_CONF_UNSET_UINT;

    conf->upstream.bufs.size =  ngx_pagesize;
    conf->upstream.buffer_size = ngx_pagesize;

    conf->upstream.busy_buffers_size = 2*ngx_pagesize;
    conf->upstream.temp_file_write_size = 2 * ngx_pagesize;

    conf->upstream.max_temp_file_size = 1024*1024*1024;

    conf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
    conf->upstream.pass_headers = NGX_CONF_UNSET_PTR;
    
    conf->clusterA.port = NGX_CONF_UNSET;
    conf->clusterB.port = NGX_CONF_UNSET;
    conf->clusterC.port = NGX_CONF_UNSET;
    
    ngx_str_null(&conf->clusterA.ip);
    ngx_str_null(&conf->clusterB.ip);
    ngx_str_null(&conf->clusterC.ip);
    return conf;
}

static void 
ngx_http_upstreamTest_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_error(NGX_LOG_DEBUG,r->connection->log,0,"upstreamTest_finalize_request");
}
 
static char *
ngx_http_upstreamTest_merge_loc_conf(ngx_conf_t *cf,void *parent,void *child)
{
    ngx_http_upstreamTest_conf_t *prev = parent;
    ngx_http_upstreamTest_conf_t *conf = child;

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,prev->upstream.connect_timeout,60000);
    ngx_conf_merge_msec_value(conf->upstream.send_timeout,prev->upstream.send_timeout,60000);
    ngx_conf_merge_msec_value(conf->upstream.read_timeout,prev->upstream.read_timeout,60000);
    ngx_conf_merge_uint_value(conf->upstream.store_access,prev->upstream.store_access,0600);
    ngx_conf_merge_value(conf->upstream.bufs.num,prev->upstream.bufs.num,8);
    ngx_conf_merge_value(conf->clusterA.port,prev->clusterA.port,7777);
    ngx_conf_merge_value(conf->clusterB.port,prev->clusterB.port,8888);
    ngx_conf_merge_value(conf->clusterC.port,prev->clusterC.port,9999);
    
    ngx_conf_merge_str_value(conf->clusterA.ip,prev->clusterA.ip,"127.0.0.1");
    ngx_conf_merge_str_value(conf->clusterB.ip,prev->clusterB.ip,"127.0.0.1");
    ngx_conf_merge_str_value(conf->clusterC.ip,prev->clusterC.ip,"127.0.0.1");
    return NGX_CONF_OK;
}
/* 
static ngx_int_t
ngx_http_upstreamTest_init(ngx_conf_t *cf)
{
    
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf,ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if(h == NULL)
    {
        return NGX_ERROR;
    }

    *h = ngx_http_upstreamTest_handler;
    
    return NGX_OK;
}*/

static char *ngx_conf_my_upstream(ngx_conf_t *cf,ngx_command_t *cmd,void *conf)
{
    ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf,ngx_http_core_module);

    clcf->handler = ngx_http_upstreamTest_handler;

    return NGX_CONF_OK;
}
