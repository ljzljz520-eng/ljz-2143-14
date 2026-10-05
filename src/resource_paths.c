#define _GNU_SOURCE
#include "resource_paths.h"

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

static char g_cli_root[RR_MAX_PATH];
static bool rr_atomic_replace_unlink(const char *from, const char *to);

void rr_set_cli_root(const char *root) {
    if (root != NULL) {
        snprintf(g_cli_root, sizeof(g_cli_root), "%s", root);
    }
}

bool rr_is_safe_relative(const char *path) {
    const char *p = path;
    size_t len;
    if (path == NULL || *path == '\0' || *path == '/' || *path == '\\') {
        return false;
    }
    if (strstr(path, "://") != NULL) {
        return false;
    }
    while (*p != '\0') {
        unsigned char c = (unsigned char)*p;
        if (c < ' ' || c == '\\' || c == ':') {
            return false;
        }
        ++p;
    }
    p = path;
    while (p != NULL && *p != '\0') {
        const char *next = strchr(p, '/');
        size_t n = next == NULL ? strlen(p) : (size_t)(next - p);
        char component[RR_MAX_PATH];
        if (n == 0 || n >= sizeof(component)) {
            return false;
        }
        memcpy(component, p, n);
        component[n] = '\0';
        if (strcmp(component, ".") == 0 || strcmp(component, "..") == 0) {
            return false;
        }
        p = next == NULL ? NULL : next + 1;
    }
    len = strlen(path);
    if (len >= RR_MAX_PATH || path[len - 1] == '/') {
        return false;
    }
    return true;
}

bool rr_mkdir_p(const char *path) {
    char tmp[RR_MAX_PATH];
    size_t len;
    if (path == NULL) return false;
    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    if (len == 0 || len >= sizeof(tmp)) return false;
    if (tmp[len - 1] == '/') tmp[len - 1] = '\0';
    for (char *p = tmp + 1; *p != '\0'; ++p) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0777) != 0 && errno != EEXIST) return false;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0777) != 0 && errno != EEXIST) return false;
    return true;
}

bool rr_file_exists(const char *path) {
    struct stat st;
    return path != NULL && stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

bool rr_read_file(const char *path, char *out, size_t out_size) {
    FILE *f;
    size_t n;
    if (path == NULL || out == NULL || out_size == 0) return false;
    f = fopen(path, "rb");
    if (f == NULL) return false;
    n = fread(out, 1, out_size - 1, f);
    fclose(f);
    out[n] = '\0';
    return true;
}

bool rr_write_atomic(const char *path, const char *data, size_t size) {
    char tmp[RR_MAX_PATH];
    FILE *f;
    int fd;
    snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid());
    char parent[RR_MAX_PATH];
    snprintf(parent, sizeof(parent), "%s", path);
    char *slash=strrchr(parent, '/');
    if (slash != NULL) { *slash='\0'; rr_mkdir_p(parent); }
    fd = open(tmp, O_CREAT | O_WRONLY | O_TRUNC, 0666);
    if (fd < 0) return false;
    f = fdopen(fd, "wb");
    if (f == NULL) { close(fd); unlink(tmp); return false; }
    if (size > 0 && fwrite(data, 1, size, f) != size) {
        fclose(f); unlink(tmp); return false;
    }
    if (fclose(f) != 0) { unlink(tmp); return false; }
    if (rename(tmp, path) != 0) { unlink(tmp); return false; }
    return true;
}

bool rr_rename_replace(const char *from, const char *to) {
    return rr_atomic_replace_unlink(from, to);
}

bool rr_remove_file(const char *path) {
    return unlink(path) == 0 || errno == ENOENT;
}

static bool rr_atomic_replace_unlink(const char *from, const char *to) {
    if (rename(from, to) == 0) return true;
    if (errno != EEXIST && errno != ENOTEMPTY) return false;
    if (unlink(to) != 0) { fprintf(stderr,"unlink target failed %s %s\n",to,strerror(errno)); return false; }
    if (rename(from, to) == 0) return true;
    return false;
}

bool rr_copy_file(const char *from, const char *to) {
    FILE *in = fopen(from, "rb");
    FILE *out = NULL;
    char buf[65536];
    size_t n;
    bool ok = true;
    char tmp[RR_MAX_PATH];
    if (in == NULL) return false;
    snprintf(tmp, sizeof(tmp), "%s.copy.%ld", to, (long)getpid());
    out = fopen(tmp, "wb");
    if (out == NULL) { fclose(in); return false; }
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) { ok = false; break; }
    }
    if (ferror(in)) ok = false;
    fclose(in);
    fclose(out);
    if (ok && !rr_atomic_replace_unlink(tmp,to)) ok = false;
    if (!ok) unlink(tmp);
    return ok;
}

long long rr_file_size(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) return -1;
    return (long long)st.st_size;
}

long long rr_free_space(const char *path) {
    struct statvfs s;
    const char *p = path;
    char copy[RR_MAX_PATH];
    const char *force=getenv("RR_FORCE_FREE_BYTES");
    long long forced=force?strtoll(force,NULL,10):-1;
    long long real;
    if (statvfs(path, &s) == 0) real=(long long)s.f_bavail * (long long)s.f_frsize; else real=-1;
    if (forced >= 0) return real < 0 ? forced : (real < forced ? real : forced);
    snprintf(copy, sizeof(copy), "%s", path);
    while (strrchr(copy, '/') != NULL) {
        char *slash = strrchr(copy, '/');
        if (slash == copy) { copy[1] = '\0'; p = "/"; break; }
        *slash = '\0';
        if (statvfs(copy, &s) == 0) {
            real=(long long)s.f_bavail * (long long)s.f_frsize;
            if (forced >= 0) return real < forced ? real : forced;
            return real;
        }
    }
    (void)p;
    return -1;
}

bool rr_join(char *out, size_t out_size, const char *base, const char *relative) {
    int n;
    if (out == NULL || base == NULL || !rr_is_safe_relative(relative)) return false;
    n = snprintf(out, out_size, "%s/%s", base, relative);
    return n >= 0 && (size_t)n < out_size;
}

bool rr_blob_path(char *out, size_t out_size, const char *root, const char *sha256) {
    char rel[80];
    if (strlen(sha256) != 64) return false;
    for (int i = 0; i < 64; ++i) {
        char c = sha256[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    snprintf(rel, sizeof(rel), "blobs/%.2s/%s", sha256, sha256);
    return rr_join(out, out_size, root, rel);
}

static bool candidate_writable(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        return S_ISDIR(st.st_mode) && access(path, W_OK | X_OK) == 0;
    }
    return rr_mkdir_p(path) && access(path, W_OK | X_OK) == 0;
}

static bool executable_dir(char *out, size_t out_size) {
    char exe[RR_MAX_PATH];
    char *slash;
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n <= 0) return false;
    exe[n] = '\0';
    slash = strrchr(exe, '/');
    if (slash == NULL) return false;
    *slash = '\0';
    snprintf(out, out_size, "%s", exe);
    return true;
}

static bool add_candidate(char candidates[][RR_MAX_PATH], int *count, int max, const char *path) {
    if (*count >= max || path == NULL || *path == '\0') return false;
    for (int i = 0; i < *count; ++i) {
        if (strcmp(candidates[i], path) == 0) return true;
    }
    snprintf(candidates[*count], RR_MAX_PATH, "%s", path);
    ++(*count);
    return true;
}

bool rr_ensure_roots(ResourceRoots *roots, const char *explicit_root) {
    char candidates[8][RR_MAX_PATH];
    int count = 0;
    char exe[RR_MAX_PATH];
    const char *xdg = getenv("XDG_CACHE_HOME");
    const char *home = getenv("HOME");
    char buf[RR_MAX_PATH];

    if (roots == NULL) return false;
    memset(roots, 0, sizeof(*roots));
    if (explicit_root != NULL && *explicit_root != '\0') {
        if (!candidate_writable(explicit_root)) return false;
        if (snprintf(roots->root, sizeof(roots->root)-1, "%s", explicit_root) >= (int)sizeof(roots->root)) return false;
    } else if (g_cli_root[0] != '\0') {
        if (!candidate_writable(g_cli_root)) return false;
        if (snprintf(roots->root, sizeof(roots->root)-1, "%s", g_cli_root) >= (int)sizeof(roots->root)) return false;
    } else {
        const char *env = getenv("VISUAL_RESOURCE_ROOT");
        if (env != NULL && *env != '\0') add_candidate(candidates, &count, 8, env);
        if (executable_dir(exe, sizeof(exe))) {
            if (snprintf(buf, sizeof(buf), "%s/resources", exe) >= (int)sizeof(buf)) { return false; }
            add_candidate(candidates, &count, 8, buf);
            if (snprintf(buf, sizeof(buf), "%s/../resources", exe) >= (int)sizeof(buf)) { return false; }
            add_candidate(candidates, &count, 8, buf);
        }
        if (xdg != NULL && *xdg != '\0') {
            snprintf(buf, sizeof(buf), "%s/visual-window-app/resources", xdg);
            add_candidate(candidates, &count, 8, buf);
        } else if (home != NULL && *home != '\0') {
            snprintf(buf, sizeof(buf), "%s/.cache/visual-window-app/resources", home);
            add_candidate(candidates, &count, 8, buf);
        }
        add_candidate(candidates, &count, 8, ".visual-resources");
        bool chosen = false;
        for (int i = 0; i < count; ++i) {
            if (candidate_writable(candidates[i])) {
                if (snprintf(roots->root, sizeof(roots->root)-1, "%s", candidates[i]) >= (int)sizeof(roots->root)) return false;
                chosen = true;
                break;
            }
        }
        if (!chosen) return false;
    }

    if (!rr_mkdir_p(roots->root) ||
        !rr_join(roots->blobs, sizeof(roots->blobs), roots->root, "blobs") ||
        !rr_join(roots->tmp, sizeof(roots->tmp), roots->root, "tmp") ||
        !rr_join(roots->packages, sizeof(roots->packages), roots->root, "packages") ||
        !rr_join(roots->meta, sizeof(roots->meta), roots->root, "meta") ||
        !rr_join(roots->current, sizeof(roots->current), roots->root, "current.state") ||
        !rr_join(roots->previous, sizeof(roots->previous), roots->root, "previous.state") ||
        !rr_join(roots->device, sizeof(roots->device), roots->root, "device.state")) {
        return false;
    }
    return rr_mkdir_p(roots->blobs) && rr_mkdir_p(roots->tmp) &&
           rr_mkdir_p(roots->packages) && rr_mkdir_p(roots->meta);
}
