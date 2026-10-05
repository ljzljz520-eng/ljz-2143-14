#define _GNU_SOURCE
#include "resource_pkg.h"

#include <inttypes.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sha256.h"

static char *trim(char *s) {
    char *end;
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') ++s;
    end = s + strlen(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n')) --end;
    *end = '\0';
    return s;
}

static bool copy_field(char *dst, size_t n, const char *src) {
    size_t l=strlen(src);
    if(l>=n) return false;
    memcpy(dst,src,l+1); return true;
}

static bool header_value(const char *line, const char *key, char *out, size_t n) {
    size_t klen = strlen(key);
    if (strncmp(line,key,klen) != 0 || line[klen] != ':') return false;
    copy_field(out,n,line+klen+1);
    return true;
}

static bool is_hex64(const char *s) {
    if (strlen(s) != 64) return false;
    for (int i=0;i<64;++i) {
        char c=s[i];
        if (!((c>='0'&&c<='9')||(c>='a'&&c<='f'))) return false;
    }
    return true;
}

typedef struct { size_t start,end; } Range;

static bool find_named_line(const char *data, size_t size, const char *name,
                            size_t *start, size_t *end) {
    for (size_t i=0;i<size;++i) {
        if ((i==0 || data[i-1]=='\n') && strncmp(data+i,name,strlen(name))==0) {
            const char *nl=memchr(data+i,'\n',size-i);
            if (nl==NULL) return false;
            *start=i;
            *end=(size_t)(nl-data)+1;
            return true;
        }
    }
    return false;
}

bool rr_pkg_verify_index_bytes(const char *data, size_t size, char expected[RR_ID_SIZE]) {
    Range ranges[2] = {{0,0},{0,0}}; unsigned int count=0;
    size_t ls,le; char actual[RR_ID_SIZE];
    if (!find_named_line(data,size,"index-sha256:",&ls,&le)) return false;
    ranges[count++]= (Range){ls,le};
    /* Package size is derived transport framing; the content fingerprint excludes
       both it and the fingerprint line so fixed-width values do not self-reference. */
    if (find_named_line(data,size,"package-size:",&ls,&le)) ranges[count++]=(Range){ls,le};
    for (unsigned int i=0;i<count;++i) for(unsigned int j=i+1;j<count;++j)
        if(ranges[j].start < ranges[i].start) { Range t=ranges[i];ranges[i]=ranges[j];ranges[j]=t; }
    Sha256Ctx ctx; unsigned char digest[32]; size_t pos=0;
    sha256_init(&ctx);
    for(unsigned int i=0;i<count;++i) {
        if(ranges[i].start<pos || ranges[i].end>size) return false;
        sha256_update(&ctx,(const unsigned char*)data+pos,ranges[i].start-pos);
        pos=ranges[i].end;
    }
    sha256_update(&ctx,(const unsigned char*)data+pos,size-pos);
    sha256_final(&ctx,digest);sha256_hex(digest,actual);
    return strcmp(actual,expected)==0;
}

bool rr_pkg_verify_file_index(FILE *f, long long header_size, char expected[RR_ID_SIZE]) {
    char *data;
    bool ok;
    if (fseek(f,0,SEEK_SET)!=0) return false;
    data=malloc((size_t)header_size);
    if (data==NULL) return false;
    if (fread(data,1,(size_t)header_size,f)!=(size_t)header_size) { free(data); return false; }
    ok=rr_pkg_verify_index_bytes(data,(size_t)header_size,expected);
    free(data);
    return ok;
}

bool rr_pkg_parse_index(const char *text, size_t size, RrPackage *pkg) {
    char copy[1024 * 1024];
    char *save=NULL;
    char *line;
    int phase=0, expected_entries=0;
    long long offset=0;
    if (size==0) size=strlen(text);
    if (size==0 || size>=sizeof(copy) || pkg==NULL) return false;
    memset(pkg,0,sizeof(*pkg));
    memcpy(copy,text,size); copy[size]='\0';
    line=strtok_r(copy,"\n",&save);
    while (line != NULL) {
        char *s=trim(line);
        if (phase==0) {
            char value[RR_MAX_LINE];
            if (strcmp(s,"RESOURCEPKG/1")==0) { }
            else if (header_value(s,"package-id",value,sizeof(value)) && is_hex64(trim(value))) copy_field(pkg->package_id,sizeof(pkg->package_id),trim(value));
            else if (header_value(s,"version",value,sizeof(value)) && *trim(value)) copy_field(pkg->version,sizeof(pkg->version),trim(value));
            else if (header_value(s,"release-id",value,sizeof(value)) && *trim(value)) copy_field(pkg->release_id,sizeof(pkg->release_id),trim(value));
            else if (header_value(s,"group-id",value,sizeof(value)) && *trim(value)) copy_field(pkg->group_id,sizeof(pkg->group_id),trim(value));
            else if (header_value(s,"created-at",value,sizeof(value)) && *trim(value)) copy_field(pkg->created_at,sizeof(pkg->created_at),trim(value));
            else if (header_value(s,"manifest-sha256",value,sizeof(value)) && is_hex64(trim(value))) copy_field(pkg->manifest_sha,sizeof(pkg->manifest_sha),trim(value));
            else if (header_value(s,"index-sha256",value,sizeof(value)) && is_hex64(trim(value))) copy_field(pkg->index_sha,sizeof(pkg->index_sha),trim(value));
            else if (header_value(s,"package-size",value,sizeof(value))) { pkg->package_size=strtoll(trim(value),NULL,10); }
            else if (header_value(s,"entry-count",value,sizeof(value))) { expected_entries=(int)strtol(trim(value),NULL,10); phase=1; }
            else if (*s != '\0') return false;
        } else if (phase==1) {
            if (strcmp(s,"BLOBS")==0) {
                phase=2;
            } else if (*s == '\0') {
            } else {
                char sha[RR_ID_SIZE], sizebuf[64], media[128], logical[RR_MAX_PATH];
                int consumed=0;
                if (sscanf(s,"%64s %63s %127s %n",sha,sizebuf,media,&consumed) < 3 || consumed==0) return false;
                if (expected_entries<0 || pkg->entry_count>=expected_entries || pkg->entry_count>=RR_MAX_ENTRIES) return false;
                if (!is_hex64(sha) || strtoll(sizebuf,NULL,10)<0) return false;
                {
                    char *log=trim(s+consumed);
                    if (!rr_is_safe_relative(log)) return false;
                    copy_field(logical,sizeof(logical),log);
                }
                for (int i=0;i<pkg->entry_count;++i)
                    if (strcmp(pkg->entries[i].logical,logical)==0) return false;
                RrPackageEntry *e=&pkg->entries[pkg->entry_count++];
                copy_field(e->sha256,sizeof(e->sha256),sha);
                copy_field(e->media,sizeof(e->media),media);
                copy_field(e->logical,sizeof(e->logical),logical);
                e->size=strtoll(sizebuf,NULL,10);
                e->offset=offset;
                offset += e->size;
            }
        } else if (*s != '\0') {
            return false;
        }
        line=strtok_r(NULL,"\n",&save);
    }
    if (phase!=2 || expected_entries != pkg->entry_count || pkg->package_size<1 ||
        !is_hex64(pkg->package_id) || !is_hex64(pkg->index_sha) || !is_hex64(pkg->manifest_sha)) return false;
    if (rr_pkg_find_manifest(pkg)==NULL) return false;
    return true;
}

bool rr_pkg_parse_file(FILE *f, RrPackage *pkg) {
    unsigned char header[1024*1024];
    size_t n=0;
    bool marker=false;
    if (fseek(f,0,SEEK_SET)!=0) return false;
    while (n<sizeof(header)) {
        int c=fgetc(f);
        if (c==EOF) return false;
        header[n++]=(unsigned char)c;
        if (n>=6 && memcmp(header+n-6,"\nBLOBS",6)==0) {
            int nl=fgetc(f);
            if (nl!='\n') return false;
            header[n++]=(unsigned char)nl;
            marker=true;
            break;
        }
    }
    if (!marker || !rr_pkg_parse_index((char*)header,n,pkg)) return false;
    pkg->data_start=(long long)n;
    if (!rr_pkg_verify_file_index(f,(long long)n,pkg->index_sha)) return false;
    for (int i=0;i<pkg->entry_count;++i) pkg->entries[i].offset += pkg->data_start;
    return true;
}

const RrPackageEntry *rr_pkg_find_logical(const RrPackage *pkg, const char *logical) {
    if (pkg==NULL||!rr_is_safe_relative(logical)) return NULL;
    for (int i=0;i<pkg->entry_count;++i)
        if (strcmp(pkg->entries[i].logical,logical)==0) return &pkg->entries[i];
    return NULL;
}

const RrPackageEntry *rr_pkg_find_manifest(const RrPackage *pkg) {
    return rr_pkg_find_logical(pkg,"manifest.json");
}

static bool extract_entry(FILE *src, const RrPackageEntry *e, const char *dest) {
    char tmp[RR_MAX_PATH + 16];
    FILE *out;
    unsigned char buf[65536];
    long long left;
    char actual[RR_ID_SIZE];
    snprintf(tmp,sizeof(tmp),"%s.part",dest);
    if (fseek(src,(long)e->offset,SEEK_SET)!=0) return false;
    out=fopen(tmp,"wb");
    if (out==NULL) { perror(tmp); return false; }
    left=e->size;
    while (left>0) {
        size_t want=sizeof(buf);
        size_t n;
        if ((long long)want>left) want=(size_t)left;
        n=fread(buf,1,want,src);
        if (n==0) { fclose(out); unlink(tmp); return false; }
        if (fwrite(buf,1,n,out)!=n) { fclose(out); unlink(tmp); return false; }
        left-=(long long)n;
    }
    if (fclose(out)!=0) { unlink(tmp); return false; }
    if (sha256_file(tmp,actual)!=0 || strcmp(actual,e->sha256)!=0) { unlink(tmp); return false; }
    if (rename(tmp,dest)!=0) { unlink(tmp); return false; }
    return true;
}

static bool state_read(const char *path, char id[RR_ID_SIZE], char release[128],
                       char version[128], char index_rel[RR_MAX_PATH]) {
    char data[RR_MAX_LINE * 4];
    char *save=NULL,*line;
    id[0]=release[0]=version[0]=index_rel[0]='\0';
    if (!rr_read_file(path,data,sizeof(data))) return false;
    line=strtok_r(data,"\n",&save);
    while(line){
        char *s=trim(line);
        if (strncmp(s,"package-id:",11)==0) copy_field(id,RR_ID_SIZE,s+11);
        else if (strncmp(s,"release-id:",11)==0) copy_field(release,128,s+11);
        else if (strncmp(s,"version:",8)==0) copy_field(version,128,s+8);
        else if (strncmp(s,"index:",6)==0) copy_field(index_rel,RR_MAX_PATH,s+6);
        line=strtok_r(NULL,"\n",&save);
    }
    char *id_end=id+strlen(id); while(id_end>id && (id_end[-1]=='\r'||id_end[-1]=='\n'))*--id_end='\0';
    char *idx_end=index_rel+strlen(index_rel); while(idx_end>index_rel && (idx_end[-1]=='\r'||idx_end[-1]=='\n'))*--idx_end='\0';
    return is_hex64(id) && rr_is_safe_relative(index_rel);
}

bool rr_pkg_verify_installed(ResourceRoots *roots, const char *package_id,
                             char missing[RR_MAX_PATH], char expected[RR_ID_SIZE]) {
    char idx_rel[RR_MAX_PATH], idx_abs[RR_MAX_PATH], data[1024*1024];
    RrPackage pkg;
    if (missing) missing[0]='\0';
    if (expected) expected[0]='\0';
    snprintf(idx_rel,sizeof(idx_rel),"releases/%s.idx",package_id);
    if (!rr_join(idx_abs,sizeof(idx_abs),roots->meta,idx_rel) || !rr_file_exists(idx_abs)) {
        if (missing) snprintf(missing,RR_MAX_PATH,"%s",idx_rel);
        return false;
    }
    if (!rr_read_file(idx_abs,data,sizeof(data)) || !rr_pkg_parse_index(data,0,&pkg)) return false;
    for (int i=0;i<pkg.entry_count;++i) {
        char blob[RR_MAX_PATH], hash[RR_ID_SIZE];
        if (!rr_blob_path(blob,sizeof(blob),roots->root,pkg.entries[i].sha256) || !rr_file_exists(blob)) {
            if (missing) snprintf(missing,RR_MAX_PATH,"%s",pkg.entries[i].logical);
            if (expected) snprintf(expected,RR_ID_SIZE,"%s",pkg.entries[i].sha256);
            return false;
        }
        if (rr_file_size(blob)!=pkg.entries[i].size || sha256_file(blob,hash)!=0 || strcmp(hash,pkg.entries[i].sha256)!=0) {
            if (missing) snprintf(missing,RR_MAX_PATH,"%s",pkg.entries[i].logical);
            if (expected) snprintf(expected,RR_ID_SIZE,"%s",pkg.entries[i].sha256);
            return false;
        }
    }
    return true;
}

static bool verify_loaded_package(ResourceRoots *roots,const RrPackage *pkg,
                                  char missing[RR_MAX_PATH],char expected[RR_ID_SIZE]) {
    for (int i=0;i<pkg->entry_count;++i) {
        char blob[RR_MAX_PATH], hash[RR_ID_SIZE];
        if (!rr_blob_path(blob,sizeof(blob),roots->root,pkg->entries[i].sha256)) return false;
        if (!rr_file_exists(blob) || rr_file_size(blob)!=pkg->entries[i].size ||
            sha256_file(blob,hash)!=0 || strcmp(hash,pkg->entries[i].sha256)!=0) {
            if(missing) snprintf(missing,RR_MAX_PATH,"%s",pkg->entries[i].logical);
            if(expected) snprintf(expected,RR_ID_SIZE,"%s",pkg->entries[i].sha256);
            return false;
        }
    }
    return true;
}

bool rr_pkg_activate_installed(ResourceRoots *roots, const RrPackage *pkg, const char *index_text,
                               size_t index_size, char reason[RR_MAX_LINE]) {
    char idx_rel[RR_MAX_PATH], idx_abs[RR_MAX_PATH], state_tmp[RR_MAX_PATH+64], state[RR_MAX_LINE*4];
    char missing[RR_MAX_PATH], expected[RR_ID_SIZE];
    int n;
    if (reason) reason[0]='\0';
    (void)missing; (void)expected;
    if (!verify_loaded_package(roots,pkg,missing,expected)) {
        if (reason) snprintf(reason,RR_MAX_LINE,"refusing activation: missing or corrupt blob for %s (%s)",missing,expected);
        return false;
    }
    snprintf(idx_rel,sizeof(idx_rel),"releases/%s.idx",pkg->package_id);
    if (!rr_join(idx_abs,sizeof(idx_abs),roots->meta,idx_rel)) return false;
    if (!rr_write_atomic(idx_abs,index_text,index_size)) {
        if (reason) snprintf(reason,RR_MAX_LINE,"cannot write release index");
        return false;
    }
    n=snprintf(state,sizeof(state),"package-id:%s\nrelease-id:%s\nversion:%s\nindex:%s\n",
               pkg->package_id,pkg->release_id,pkg->version,idx_rel);
    if (n<0 || (size_t)n>=sizeof(state)) return false;
    if (rr_file_exists(roots->current)) {
        char old[RR_MAX_PATH];
        if (!rr_join(old,sizeof(old),roots->root,"current.state.old") ||
            !rr_copy_file(roots->current,old)) return false;
    }
    snprintf(state_tmp,sizeof(state_tmp),"%s.activate.tmp",roots->current);
    if (!rr_write_atomic(state_tmp,state,strlen(state))) return false;
    if (rr_file_exists(roots->current)) {
        if (!rr_copy_file(roots->current,roots->previous)) return false;
    }
    return rr_rename_replace(state_tmp,roots->current);
}

bool rr_pkg_install_file(ResourceRoots *roots, const char *package_file, bool keep_package,
                         char installed_id[RR_ID_SIZE], char reason[RR_MAX_LINE]) {
    FILE *f=fopen(package_file,"rb");
    RrPackage pkg;
    char header[1024*1024];
    long long stored_size, actual_size;
    if (reason) reason[0]='\0';
    if (installed_id) installed_id[0]='\0';
    if (f==NULL) { if(reason) snprintf(reason,RR_MAX_LINE,"cannot open package"); return false; }
    actual_size=rr_file_size(package_file);
    if (!rr_pkg_parse_file(f,&pkg)) { fclose(f); if(reason) snprintf(reason,RR_MAX_LINE,"invalid package index or checksum"); return false; }
    stored_size=pkg.data_start;
    for(int i=0;i<pkg.entry_count;++i) stored_size+=pkg.entries[i].size;
    if (actual_size != pkg.package_size || stored_size != pkg.package_size) {
        fclose(f); if(reason) snprintf(reason,RR_MAX_LINE,"truncated package: expected %lld bytes, got %lld",pkg.package_size,actual_size); return false;
    }
    if (fseek(f,pkg.data_start,SEEK_SET)!=0 || fread(header,1,1,f)!=1) { fclose(f); return false; }
    if (pkg.data_start >= (long long)sizeof(header)) { fclose(f); return false; }
        long long need=0;
    for(int i=0;i<pkg.entry_count;++i) {
        char blob[RR_MAX_PATH];
        if (!rr_blob_path(blob,sizeof(blob),roots->root,pkg.entries[i].sha256)) { fclose(f); return false; }
        if (!rr_file_exists(blob)) need += pkg.entries[i].size;
    }
    {
        long long freeb=rr_free_space(roots->blobs);
        if (freeb>=0 && freeb < need) {
            fclose(f); if(reason) snprintf(reason,RR_MAX_LINE,"insufficient cache space: need %lld free %lld",need,freeb); return false;
        }
    }
    for(int i=0;i<pkg.entry_count;++i) {
        char blob[RR_MAX_PATH], dir[RR_MAX_PATH];
        char *slash;
        if (!rr_blob_path(blob,sizeof(blob),roots->root,pkg.entries[i].sha256)) { fclose(f); return false; }
        if (rr_file_exists(blob)) {
            char h[RR_ID_SIZE];
            if (rr_file_size(blob)!=pkg.entries[i].size || sha256_file(blob,h)!=0 || strcmp(h,pkg.entries[i].sha256)!=0) {
                fclose(f); if(reason) snprintf(reason,RR_MAX_LINE,"existing corrupt blob %s",pkg.entries[i].sha256); return false;
            }
            continue;
        }
        snprintf(dir,sizeof(dir),"%s",blob);
        slash=strrchr(dir,'/'); if(slash)*slash='\0';
        if (!rr_mkdir_p(dir) || !extract_entry(f,&pkg.entries[i],blob)) {
            fclose(f); if(reason) snprintf(reason,RR_MAX_LINE,"failed extracting %s",pkg.entries[i].logical); return false;
        }
    }
    fclose(f);
    {
        FILE *idx=fopen(package_file,"rb");
        size_t hs=(size_t)pkg.data_start;
        char *idxtext=malloc(hs);
        bool ok=false;
        if(idx && idxtext && fread(idxtext,1,hs,idx)==hs) {
            ok=rr_pkg_activate_installed(roots,&pkg,idxtext,hs,reason);
        } else if(reason) snprintf(reason,RR_MAX_LINE,"cannot stage activation");
        free(idxtext); if(idx)fclose(idx);
        if(!ok) { if(keep_package){} return false; }
    }
    snprintf(installed_id,RR_ID_SIZE,"%s",pkg.package_id);
    return true;
}

bool rr_pkg_resolve(ResourceRoots *roots, const char *logical, char path_out[RR_MAX_PATH],
                    char sha_out[RR_ID_SIZE], char package_out[RR_ID_SIZE]) {
    char id[RR_ID_SIZE], release[128], version[128], idx_rel[RR_MAX_PATH], idx_abs[RR_MAX_PATH];
    char data[1024*1024];
    RrPackage pkg;
    const RrPackageEntry *e;
    if (!rr_is_safe_relative(logical)) return false;
    if (!state_read(roots->current,id,release,version,idx_rel)) return false;
    if (!rr_join(idx_abs,sizeof(idx_abs),roots->meta,idx_rel) ||
        !rr_read_file(idx_abs,data,sizeof(data)) || !rr_pkg_parse_index(data,0,&pkg)) return false;
    e=rr_pkg_find_logical(&pkg,logical);
    if(e==NULL) return false;
    if (!rr_blob_path(path_out,RR_MAX_PATH,roots->root,e->sha256)) return false;
    if (!rr_file_exists(path_out)) return false;
    if (sha_out) snprintf(sha_out,RR_ID_SIZE,"%s",e->sha256);
    if (package_out) snprintf(package_out,RR_ID_SIZE,"%s",id);
    return true;
}

bool rr_pkg_rollback(ResourceRoots *roots, char activated_id[RR_ID_SIZE], char reason[RR_MAX_LINE]) {
    char id[RR_ID_SIZE], release[128], version[128], idx_rel[RR_MAX_PATH], missing[RR_MAX_PATH], expected[RR_ID_SIZE];
    char stable_id[RR_ID_SIZE];
    char new_current_tmp[RR_MAX_PATH + 32];
    if (activated_id) activated_id[0]='\0';
    if (!state_read(roots->previous,id,release,version,idx_rel)) {
        if(reason) snprintf(reason,RR_MAX_LINE,"no complete previous release");
        return false;
    }
    if (!rr_pkg_verify_installed(roots,id,missing,expected)) {
        if(reason) snprintf(reason,RR_MAX_LINE,"previous release incomplete: %s",missing);
        return false;
    }
    snprintf(stable_id,sizeof(stable_id),"%s",id);
    char new_previous_tmp[RR_MAX_PATH + 32];
    char aside[RR_MAX_PATH + 32];
    snprintf(new_current_tmp,sizeof(new_current_tmp),"%s.rollback.tmp",roots->current);
    snprintf(new_previous_tmp,sizeof(new_previous_tmp),"%s.previous.tmp",roots->current);
    snprintf(aside,sizeof(aside),"%s/rollback-aside.state",roots->root);
    if (rr_file_exists(new_current_tmp)) rr_remove_file(new_current_tmp);
    if (rr_file_exists(new_previous_tmp)) rr_remove_file(new_previous_tmp);
    if (rr_file_exists(aside)) rr_remove_file(aside);
    if (!rr_copy_file(roots->previous,new_current_tmp)) {
        if(reason)snprintf(reason,RR_MAX_LINE,"stage previous current pointer failed: %s",strerror(errno));
        return false;
    }
    if (link(roots->current,new_previous_tmp) != 0) {
        if(reason)snprintf(reason,RR_MAX_LINE,"snapshot old current failed: %s",strerror(errno));
        rr_remove_file(new_current_tmp); return false;
    }
    if (rename(roots->current, aside) != 0 || rename(new_current_tmp, roots->current) != 0) {
        if(reason)snprintf(reason,RR_MAX_LINE,"activate previous state failed: %s",strerror(errno));
        rr_remove_file(new_current_tmp); rr_remove_file(new_previous_tmp); rr_remove_file(aside); return false;
    }
    rr_remove_file(roots->previous);
    if (rename(new_previous_tmp, roots->previous) != 0) {
        if(reason)snprintf(reason,RR_MAX_LINE,"install new rollback pointer failed: %s",strerror(errno));
        rr_remove_file(new_previous_tmp); rr_remove_file(aside); return false;
    }
    rr_remove_file(aside);
    if (activated_id) snprintf(activated_id,RR_ID_SIZE,"%s",stable_id);
    return true;
}
