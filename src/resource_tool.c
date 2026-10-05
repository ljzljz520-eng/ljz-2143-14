#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "resource_client.h"

static int usage(void) {
    fprintf(stderr,"usage:\n"
        "  resource-tool init [--root DIR]\n"
        "  resource-tool install PACKAGE.rrpkg [--root DIR]\n"
        "  resource-tool update --server URL --group GROUP [--root DIR]\n"
        "  resource-tool rollback [--root DIR]\n"
        "  resource-tool resolve LOGICAL_PATH [--root DIR]\n"
        "  resource-tool status [--root DIR]\n"
        "  resource-tool gc [--root DIR]\n");
    return 2;
}

static const char *option_value(int argc,char **argv,const char *name) {
    for(int i=1;i<argc-1;++i)if(strcmp(argv[i],name)==0)return argv[i+1];
    return NULL;
}

int main(int argc,char **argv) {
    ResourceRoots roots; char reason[RR_MAX_LINE],id[RR_ID_SIZE],path[RR_MAX_PATH],sha[RR_ID_SIZE],pkg[RR_ID_SIZE];
    if(argc<2)return usage();
    const char *root=option_value(argc,argv,"--root");
    if(root)rr_set_cli_root(root);
    if(!rr_ensure_roots(&roots,root)){fprintf(stderr,"failed to resolve/create resource root (no build-machine path is embedded)\n");return 1;}
    if(!rc_init_device(&roots)){fprintf(stderr,"cannot initialize device identity\n");return 1;}
    if(strcmp(argv[1],"init")==0){printf("%s\n",roots.root);return 0;}
    if(strcmp(argv[1],"install")==0){
        if(argc<3){return usage();}
        if(!rr_pkg_install_file(&roots,argv[2],true,id,reason)){fprintf(stderr,"%s\n",reason[0]?reason:"install failed");return 1;}
        printf("activated %s\n",id);return 0;
    }
    if(strcmp(argv[1],"update")==0){
        const char *server=option_value(argc,argv,"--server"),*group=option_value(argc,argv,"--group");
        if(!server||!group)return usage();
        if(!rc_enroll_and_update(&roots,server,group,id,reason)){fprintf(stderr,"%s\n",reason[0]?reason:"update failed");return 1;}
        printf("activated %s\n",id);return 0;
    }
    if(strcmp(argv[1],"rollback")==0){
        if(!rr_pkg_rollback(&roots,id,reason)){fprintf(stderr,"%s\n",reason[0]?reason:"rollback failed");return 1;}
        printf("rolled back %s\n",id);return 0;
    }
    if(strcmp(argv[1],"resolve")==0){
        if(argc<3)return usage();
        if(!rr_pkg_resolve(&roots,argv[2],path,sha,pkg)){fprintf(stderr,"missing %s; it is absent from current complete release or its verified blob is missing\n",argv[2]);return 1;}
        printf("%s\nsha256=%s\npackage=%s\n",path,sha,pkg);return 0;
    }
    if(strcmp(argv[1],"status")==0){
        char out[8192]; rc_status(&roots,out,sizeof(out));fputs(out,stdout);return 0;
    }
    if(strcmp(argv[1],"gc")==0){
        long long bytes=0;int files=0;
        if(!rc_collect_garbage(&roots,&bytes,&files,reason)){fprintf(stderr,"gc failed\n");return 1;}
        printf("removed %d unreferenced files, %lld bytes; current/previous release refs retained\n",files,bytes);return 0;
    }
    return usage();
}
