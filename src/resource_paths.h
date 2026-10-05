#ifndef RESOURCE_PATHS_H
#define RESOURCE_PATHS_H

#include <stdbool.h>
#include <stddef.h>

#define RR_MAX_PATH 4096
#define RR_MAX_LINE 8192

typedef struct {
    char root[RR_MAX_PATH];
    char blobs[RR_MAX_PATH];
    char tmp[RR_MAX_PATH];
    char packages[RR_MAX_PATH];
    char meta[RR_MAX_PATH];
    char current[RR_MAX_PATH];
    char previous[RR_MAX_PATH];
    char device[RR_MAX_PATH];
} ResourceRoots;

bool rr_is_safe_relative(const char *path);
bool rr_mkdir_p(const char *path);
bool rr_file_exists(const char *path);
bool rr_read_file(const char *path, char *out, size_t out_size);
bool rr_write_atomic(const char *path, const char *data, size_t size);
bool rr_rename_replace(const char *from, const char *to);
bool rr_remove_file(const char *path);
bool rr_copy_file(const char *from, const char *to);
long long rr_file_size(const char *path);
long long rr_free_space(const char *path);
bool rr_join(char *out, size_t out_size, const char *base, const char *relative);
bool rr_blob_path(char *out, size_t out_size, const char *root, const char *sha256);
bool rr_ensure_roots(ResourceRoots *roots, const char *explicit_root);
void rr_set_cli_root(const char *root);

#endif
