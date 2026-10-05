#define _GNU_SOURCE
#include "resource_client.h"

#include <dirent.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "http_client.h"
#include "sha256.h"

static bool json_string(const char *json,const char *key,char *out,size_t n) {
    char pattern[128]; const char *p,*start,*end;
    snprintf(pattern,sizeof(pattern),"\"%s\"",key);
    p=strstr(json,pattern); if(!p)return false;
    p=strchr(p+strlen(pattern),':'); if(!p)return false;
    ++p; while(*p==' '||*p=='\t')++p;
    if(*p!='"')return false;
    start=++p;
    while(*p && *p!='"') { if(*p=='\\') ++p; if(*p) ++p; }
    if(*p!='"')return false;
    end=p;
    size_t len=(size_t)(end-start); if(len>=n)return false;
    memcpy(out,start,len);out[len]='\0';
    for(size_t i=0;i<len;++i) if((unsigned char)out[i]<' ') return false;
    return true;
}

static void appendf(char *out,size_t n,const char *fmt,...) {
    va_list ap; size_t l=strlen(out);
    va_start(ap,fmt); vsnprintf(out+l,n-l,fmt,ap); va_end(ap);
}

static bool make_device_id(char id[65]) {
    int fd=open("/dev/urandom",O_RDONLY); unsigned char b[32];
    if(fd<0 || read(fd,b,sizeof(b))!=sizeof(b)) {if(fd>=0)close(fd);return false;}
    close(fd); sha256_hex(b,id); return true;
}

bool rc_init_device(ResourceRoots *roots) {
    char data[128], id[65], body[256];
    if(rr_file_exists(roots->device) && rr_read_file(roots->device,data,sizeof(data)) && strstr(data,"device-id:")!=NULL) return true;
    if(!make_device_id(id)) return false;
    snprintf(body,sizeof(body),"device-id:%s\n",id);
    return rr_write_atomic(roots->device,body,strlen(body));
}

static bool read_device_id(ResourceRoots *roots,char id[65]) {
    char data[128],*p;
    if(!rc_init_device(roots)||!rr_read_file(roots->device,data,sizeof(data))) return false;
    p=strstr(data,"device-id:"); if(!p)return false; p+=10;
    if(strlen(p)<64)return false;
    memcpy(id,p,64);id[64]='\0';
    for(int i=0;i<64;++i){char c=id[i];if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))return false;}
    return true;
}

static void url_join(char *out,size_t n,const char *server,const char *path) {
    size_t l=strlen(server);
    if(l>0 && server[l-1]=='/') snprintf(out,n,"%s%s",server,path+1);
    else snprintf(out,n,"%s%s",server,path);
}

static bool read_state(const char *path,char id[65],char release[128],char version[128],char idx_rel[RR_MAX_PATH]) {
    char data[2048],*save=NULL,*line;
    id[0]=release[0]=version[0]=idx_rel[0]='\0';
    if(!rr_read_file(path,data,sizeof(data))) return false;
    line=strtok_r(data,"\n",&save);
    while(line) {
        while(*line==' ')++line;
        if(strncmp(line,"package-id:",11)==0)snprintf(id,65,"%.64s",line+11);
        else if(strncmp(line,"release-id:",11)==0)snprintf(release,128,"%s",line+11);
        else if(strncmp(line,"version:",8)==0)snprintf(version,128,"%s",line+8);
        else if(strncmp(line,"index:",6)==0)snprintf(idx_rel,RR_MAX_PATH,"%s",line+6);
        line=strtok_r(NULL,"\n",&save);
    }
    char *id_end=id+strlen(id); while(id_end>id && (id_end[-1]=='\r'||id_end[-1]=='\n'||id_end[-1]==' '))*--id_end='\0';
    char *idx_end=idx_rel+strlen(idx_rel); while(idx_end>idx_rel && (idx_end[-1]=='\r'||idx_end[-1]=='\n'||idx_end[-1]==' '))*--idx_end='\0';
    return strlen(id)==64 && rr_is_safe_relative(idx_rel);
}

static bool state_package_id(const char *path,char id[65]) {
    char release[128],version[128],idx[RR_MAX_PATH];
    id[0]='\0';
    return read_state(path,id,release,version,idx);
}

static bool load_state_package(ResourceRoots *roots,const char *state,RrPackage *pkg,char pid[65]) {
    char rel[RR_MAX_PATH],release[128],version[128],idx_abs[RR_MAX_PATH],data[1024*1024];
    if(!read_state(state,pid,release,version,rel))return false;
    if(!rr_join(idx_abs,sizeof(idx_abs),roots->meta,rel))return false;
    if(!rr_read_file(idx_abs,data,sizeof(data)))return false;
    return rr_pkg_parse_index(data,0,pkg);
}

static bool count_missing(ResourceRoots *roots,const RrPackage *pkg,long long *missing,long long *present) {
    *missing=0;*present=0;
    for(int i=0;i<pkg->entry_count;++i) {
        char p[RR_MAX_PATH],h[65];
        if(!rr_blob_path(p,sizeof(p),roots->root,pkg->entries[i].sha256))return false;
        if(rr_file_exists(p) && rr_file_size(p)==pkg->entries[i].size &&
           sha256_file(p,h)==0 && strcmp(h,pkg->entries[i].sha256)==0)
            *present += pkg->entries[i].size;
        else *missing += pkg->entries[i].size;
    }
    return true;
}

static void package_url_from_index(char *out,size_t n,const char *index_url) {
    snprintf(out,n,"%s",index_url);
    char *slash=strrchr(out,'/');
    if(slash) snprintf(slash+1,n-(size_t)(slash-out+1),"package");
}

bool rc_enroll_and_update(ResourceRoots *roots,const char *server,const char *group,
                          char package_id[RR_ID_SIZE],char reason[RR_MAX_LINE]) {
    char dev[65], url[RR_MAX_PATH], body[512], pkg_path[RR_MAX_PATH+80], event[768];
    HttpResponse assign={0}; long post_status=0;
    RrPackage idx; long long missing=0,present=0,freeb,need;
    if(reason){reason[0]='\0';}
    if(package_id){package_id[0]='\0';}
    if(!read_device_id(roots,dev)){snprintf(reason,RR_MAX_LINE,"cannot initialize device identity");return false;}
    snprintf(body,sizeof(body),"{\"device_id\":\"%.64s\",\"group_id\":\"%s\"}",dev,group);
    url_join(url,sizeof(url),server,"/api/devices/enroll");
    if(!http_post_json(url,body,&post_status)) {
        snprintf(reason,RR_MAX_LINE,"device rejected by group (HTTP %ld); two devices cannot claim the same group",post_status);
        return false;
    }
    snprintf(body,sizeof(body),"{\"device_id\":\"%.64s\",\"group_id\":\"%s\"}",dev,group);
    url_join(url,sizeof(url),server,"/api/devices/assignment");
    if(!http_get(url,"X-Device-ID",dev,&assign,256*1024)) {snprintf(reason,RR_MAX_LINE,"cannot fetch assignment");return false;}
    char assigned_pkg[65],idx_url[2048],release_id[128],assigned_group[128],pkg_url[RR_MAX_PATH];
    if(!json_string(assign.data,"package_id",assigned_pkg,sizeof(assigned_pkg)) ||
       !json_string(assign.data,"index_url",idx_url,sizeof(idx_url)) ||
       !json_string(assign.data,"release_id",release_id,sizeof(release_id)) ||
       !json_string(assign.data,"group_id",assigned_group,sizeof(assigned_group)) ||
       strcmp(assigned_group,group)!=0) {
        http_response_free(&assign);snprintf(reason,RR_MAX_LINE,"invalid assignment or wrong group");return false;
    }
    http_response_free(&assign);
    if(strncasecmp(idx_url,"http://",7)==0)snprintf(url,sizeof(url),"%s",idx_url);
    else url_join(url,sizeof(url),server,idx_url);
    {
        HttpResponse idx_resp={0};
        if(!http_get(url,"X-Device-ID",dev,&idx_resp,1024*1024)){snprintf(reason,RR_MAX_LINE,"cannot fetch package index");return false;}
        if(!rr_pkg_parse_index(idx_resp.data,idx_resp.size,&idx)) {
            http_response_free(&idx_resp);snprintf(reason,RR_MAX_LINE,"malformed package index");return false;
        }
        if(!rr_pkg_verify_index_bytes(idx_resp.data,idx_resp.size,idx.index_sha)) {
            http_response_free(&idx_resp);snprintf(reason,RR_MAX_LINE,"tampered package index fingerprint=%s",idx.index_sha);return false;
        }
        http_response_free(&idx_resp);
    }
    if(strcmp(idx.package_id,assigned_pkg)!=0){snprintf(reason,RR_MAX_LINE,"wrong package for device group");return false;}
    char old_id[65]=""; (void)state_package_id(roots->current,old_id);
    if(strcmp(old_id,idx.package_id)==0) {
        char m[RR_MAX_PATH],e[65];
        if(!rr_pkg_verify_installed(roots,old_id,m,e)){snprintf(reason,RR_MAX_LINE,"current package is damaged: %s",m);return false;}
        snprintf(package_id,RR_ID_SIZE,"%s",old_id);return true;
    }
    if(!count_missing(roots,&idx,&missing,&present)){snprintf(reason,RR_MAX_LINE,"cannot inspect cache");return false;}
    (void)present; need=idx.package_size+missing;
    freeb=rr_free_space(roots->tmp);
    if(freeb>=0 && freeb<need) {
        snprintf(reason,RR_MAX_LINE,"insufficient cache space: need %lld bytes (full download + missing unique files), free %lld; old version retained",need,freeb);
        return false;
    }
    package_url_from_index(pkg_url,sizeof(pkg_url),url);
    snprintf(pkg_path,sizeof(pkg_path),"%s/%s.rrpkg",roots->tmp,idx.package_id);
    if(!http_download(pkg_url,"X-Device-ID",dev,pkg_path,idx.package_size+1,false)) {
        snprintf(reason,RR_MAX_LINE,"package download failed; old version retained");return false;
    }
    if(rr_file_size(pkg_path)!=idx.package_size){rr_remove_file(pkg_path);snprintf(reason,RR_MAX_LINE,"downloaded package is truncated; old version retained");return false;}
    if(!rr_pkg_install_file(roots,pkg_path,false,package_id,reason)){rr_remove_file(pkg_path);return false;}
    rr_remove_file(pkg_path);
    snprintf(event,sizeof(event),"{\"device_id\":\"%.64s\",\"group_id\":\"%s\",\"release_id\":\"%s\",\"package_id\":\"%s\",\"status\":\"active\"}",
             dev,group,release_id,package_id);
    url_join(url,sizeof(url),server,"/api/devices/report");
    (void)http_post_json(url,event,NULL);
    return true;
}

bool rc_status(ResourceRoots *roots,char *out,size_t n) {
    char id[65];
    out[0]='\0';
    if(read_device_id(roots,id)) appendf(out,n,"device-id: %.64s\n",id);
    appendf(out,n,"root: %s\n",roots->root);
    const char *names[2]={"current","previous"}; const char *paths[2]={roots->current,roots->previous};
    for(int s=0;s<2;++s) {
        RrPackage pkg; char pid[65],missing[RR_MAX_PATH],expected[65];
        if(!load_state_package(roots,paths[s],&pkg,pid)){appendf(out,n,"%s: absent\n",names[s]);continue;}
        appendf(out,n,"%s: package=%s release=%s version=%s\n",names[s],pid,pkg.release_id,pkg.version);
        if(rr_pkg_verify_installed(roots,pid,missing,expected))appendf(out,n,"  complete: %d files\n",pkg.entry_count);
        else appendf(out,n,"  MISSING: %s expected-sha256=%s\n",missing[0]?missing:"(index)",expected);
    }
    return true;
}

static void add_ref(char refs[][65],int *count,const char *id) {
    for(int i=0;i<*count;++i)if(strcmp(refs[i],id)==0)return;
    snprintf(refs[(*count)++],65,"%s",id);
}

static bool package_referenced(char refs[][65],int count,const char *sha) {
    for(int r=0;r<count;++r)if(strcmp(refs[r],sha)==0)return true;
    return false;
}

bool rc_collect_garbage(ResourceRoots *roots,long long *removed_bytes,int *removed_files,char reason[RR_MAX_LINE]) {
    DIR *d1,*d2; struct dirent *a,*b;
    char package_refs[16][65]; char blob_refs[1024][65]; int pc=0,bc=0;
    (void)reason;
    if(removed_bytes){*removed_bytes=0;}
    if(removed_files){*removed_files=0;}
    const char *states[2]={roots->current,roots->previous};
    for(int s=0;s<2;++s) {
        RrPackage pkg; char pid[65];
        if(load_state_package(roots,states[s],&pkg,pid)) {
            add_ref(package_refs,&pc,pid);
            for(int i=0;i<pkg.entry_count;++i)add_ref(blob_refs,&bc,pkg.entries[i].sha256);
        }
    }
    d1=opendir(roots->blobs); if(!d1)return false;
    while((a=readdir(d1))!=NULL) {
        char sub[RR_MAX_PATH];
        if(a->d_name[0]=='.'||strlen(a->d_name)!=2)continue;
        if(!rr_join(sub,sizeof(sub),roots->blobs,a->d_name))continue;
        d2=opendir(sub);if(!d2)continue;
        while((b=readdir(d2))!=NULL) {
            char p[RR_MAX_PATH]; long long sz;
            if(strlen(b->d_name)!=64)continue;
            if(package_referenced(blob_refs,bc,b->d_name))continue;
            if(!rr_join(p,sizeof(p),sub,b->d_name))continue;
            sz=rr_file_size(p);
            if(rr_remove_file(p)&&sz>=0){if(removed_bytes)*removed_bytes+=sz;if(removed_files)*removed_files+=1;}
        }
        closedir(d2);
    }
    closedir(d1);
    DIR *td=opendir(roots->tmp);
    if(td){while((a=readdir(td))!=NULL){char p[RR_MAX_PATH];if(a->d_name[0]=='.')continue;if(rr_join(p,sizeof(p),roots->tmp,a->d_name))rr_remove_file(p);}closedir(td);}
    return true;
}
