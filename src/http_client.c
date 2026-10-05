#define _GNU_SOURCE
#include "http_client.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct {
    char host[256];
    char port[16];
    char path[2048];
} UrlParts;

static bool parse_url(const char *url, UrlParts *u) {
    const char *p=url,*path;
    char hostport[512];
    char *colon;
    size_t n;
    memset(u,0,sizeof(*u));
    if (strncmp(p,"http://",7)!=0) return false;
    p += 7;
    path=strchr(p,'/');
    n=path?(size_t)(path-p):strlen(p);
    if(n==0||n>=sizeof(hostport)) return false;
    memcpy(hostport,p,n);hostport[n]='\0';
    colon=strrchr(hostport,':');
    if(colon){ *colon='\0'; snprintf(u->port,sizeof(u->port),"%s",colon+1); }
    else snprintf(u->port,sizeof(u->port),"80");
    if(snprintf(u->host,sizeof(u->host),"%s",hostport)>=(int)sizeof(u->host))return false;
    if(u->host[0]=='[' ) {
        char *end=strchr(u->host,']');
        if(!end) return false;
        memmove(u->host,u->host+1,(size_t)(end-(u->host+1)));
        u->host[end-u->host-1]='\0';
    }
    snprintf(u->path,sizeof(u->path),"%s",path?path:"/");
    return u->host[0] != '\0' && u->port[0] != '\0';
}

static int connect_url(const UrlParts *u) {
    struct addrinfo hints,*res,*rp;
    int fd=-1;
    memset(&hints,0,sizeof(hints));
    hints.ai_socktype=SOCK_STREAM;
    if(getaddrinfo(u->host,u->port,NULL,&res)!=0) return -1;
    for(rp=res;rp;rp=rp->ai_next) {
        fd=socket(rp->ai_family,rp->ai_socktype,rp->ai_protocol);
        if(fd<0) continue;
        if(connect(fd,rp->ai_addr,rp->ai_addrlen)==0) break;
        close(fd); fd=-1;
    }
    freeaddrinfo(res);
    return fd;
}

static int perform_request(const char *url,const char *hn,const char *hv,
                           FILE **body, long *status, size_t *header_size,
                           const char *method, const char *request_body) {
    UrlParts u; int fd; FILE *f; char line[4096]; size_t hs=0;
    if(!parse_url(url,&u)) return -1;
    fd=connect_url(&u); if(fd<0) return -1;
    f=fdopen(fd,"r+b"); if(!f){close(fd);return -1;}
    setvbuf(f,NULL,_IONBF,0);
   
    fprintf(f,"%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n",method,u.path,u.host);
    if(request_body) fprintf(f,"Content-Type: application/json\r\nContent-Length: %zu\r\n",strlen(request_body));
    if(hn && *hn && hv) fprintf(f,"%s: %s\r\n",hn,hv);
    fprintf(f,"\r\n"); if(request_body) fputs(request_body,f); fflush(f);
    if(!fgets(line,sizeof(line),f)) {fclose(f);return -1;}
   
    hs += strlen(line);
    *status=0;
    if(strncmp(line,"HTTP/1.",7)!=0) {fclose(f);return -1;}
    *status=strtol(line+8,NULL,10);
    if(*status<=0) {fclose(f);return -1;}
    size_t content_length=0;
    bool chunked=false;
    while(fgets(line,sizeof(line),f)) {
        hs += strlen(line);
       
        if(strcmp(line,"\r\n")==0 || strcmp(line,"\n")==0) break;
        if(strncasecmp(line,"Transfer-Encoding:",18)==0 && strcasestr(line,"chunked")!=NULL) chunked=true;
        if(strncasecmp(line,"Content-Length:",15)==0) content_length=(size_t)strtoul(line+15,NULL,10);
    }
    if(!chunked && content_length>0) {
        char tmpname[256]; snprintf(tmpname,sizeof(tmpname),"/tmp/rr-http-XXXXXX");
        int tfd=mkstemp(tmpname); FILE *tf;
        char buf[65536]; size_t left=content_length;
        if(tfd<0){fclose(f);return -1;}
        tf=fdopen(tfd,"w+b");
        if(!tf){close(tfd);unlink(tmpname);fclose(f);return -1;}
        while(left>0){size_t w=sizeof(buf); if(w>left)w=left; size_t n=fread(buf,1,w,f); if(n==0)break; fwrite(buf,1,n,tf);left-=n;}
        fclose(f); rewind(tf); unlink(tmpname); *body=tf; *header_size=hs; return 0;
    }
    *body=f; *header_size=hs;
    (void)chunked;
    return 0;
}

bool http_get(const char *url,const char *hn,const char *hv,HttpResponse *resp,size_t max_size) {
    FILE *body=NULL; long status=0; size_t hs=0; char buf[65536]; size_t n;
    memset(resp,0,sizeof(*resp));
    if(perform_request(url,hn,hv,&body,&status,&hs,"GET",NULL)!=0 || body==NULL) return false;
    resp->status=status;
    while((n=fread(buf,1,sizeof(buf),body))>0) {
        if(resp->size+n>max_size) {http_response_free(resp);fclose(body);return false;}
        char *ndata=realloc(resp->data,resp->size+n+1);
        if(!ndata){http_response_free(resp);fclose(body);return false;}
        resp->data=ndata; memcpy(resp->data+resp->size,buf,n); resp->size+=n; resp->data[resp->size]='\0';
    }
    fclose(body);
    return status>=200 && status<300;
}

void http_response_free(HttpResponse *r) { if(r){free(r->data);memset(r,0,sizeof(*r));} }

bool http_download(const char *url,const char *hn,const char *hv,const char *dest,
                   long long max_bytes,bool truncate_last_byte) {
    HttpResponse r;
    FILE *out;
    if(!http_get(url,hn,hv,&r,(size_t)max_bytes)) return false;
    out=fopen(dest,"wb");
    if(!out){http_response_free(&r);return false;}
    size_t n=r.size;
    if(truncate_last_byte && n>0) n-=1;
    bool ok=fwrite(r.data,1,n,out)==n;
    fclose(out); http_response_free(&r);
    return ok;
}

bool http_post_json(const char *url, const char *json, long *status) {
    FILE *body=NULL; size_t hs=0; char line[4096]; long st=0;
    if(perform_request(url,NULL,NULL,&body,&st,&hs,"POST",json)!=0 || body==NULL) return false;
    while(fgets(line,sizeof(line),body)!=NULL) { }
    fclose(body);
    if(status) *status=st;
    return st>=200 && st<300;
}
