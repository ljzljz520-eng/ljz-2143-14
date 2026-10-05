#ifndef RESOURCE_PKG_H
#define RESOURCE_PKG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "resource_paths.h"

#define RR_MAX_ENTRIES 128
#define RR_ID_SIZE 65

typedef struct {
    char sha256[RR_ID_SIZE];
    char logical[512];
    char media[128];
    long long size;
    long long offset;
} RrPackageEntry;

typedef struct {
    char package_id[RR_ID_SIZE];
    char version[128];
    char release_id[128];
    char group_id[128];
    char created_at[64];
    char manifest_sha[RR_ID_SIZE];
    char index_sha[RR_ID_SIZE];
    long long package_size;
    RrPackageEntry entries[RR_MAX_ENTRIES];
    int entry_count;
    long long data_start;
} RrPackage;

typedef bool (*RrBlobFetch)(void *userdata, const RrPackage *pkg, const RrPackageEntry *entry,
                            const char *dest_tmp, long long available_bytes);

bool rr_pkg_parse_index(const char *text, size_t size, RrPackage *pkg);
bool rr_pkg_verify_index_bytes(const char *data, size_t size, char expected[RR_ID_SIZE]);
bool rr_pkg_verify_file_index(FILE *f, long long header_size, char expected[RR_ID_SIZE]);
bool rr_pkg_parse_file(FILE *f, RrPackage *pkg);
const RrPackageEntry *rr_pkg_find_logical(const RrPackage *pkg, const char *logical);
const RrPackageEntry *rr_pkg_find_manifest(const RrPackage *pkg);
bool rr_pkg_install_file(ResourceRoots *roots, const char *package_file, bool keep_package,
                         char installed_id[RR_ID_SIZE], char reason[RR_MAX_LINE]);
bool rr_pkg_activate_installed(ResourceRoots *roots, const RrPackage *pkg, const char *index_text,
                               size_t index_size, char reason[RR_MAX_LINE]);
bool rr_pkg_verify_installed(ResourceRoots *roots, const char *package_id,
                             char missing[RR_MAX_PATH], char expected[RR_ID_SIZE]);
bool rr_pkg_resolve(ResourceRoots *roots, const char *logical, char path_out[RR_MAX_PATH],
                    char sha_out[RR_ID_SIZE], char package_out[RR_ID_SIZE]);
bool rr_pkg_rollback(ResourceRoots *roots, char activated_id[RR_ID_SIZE], char reason[RR_MAX_LINE]);

#endif
