#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include <stdbool.h>
#include <stddef.h>

typedef struct {
    char *data;
    size_t size;
    long status;
} HttpResponse;

bool http_get(const char *url, const char *header_name, const char *header_value,
              HttpResponse *response, size_t max_size);
void http_response_free(HttpResponse *response);
bool http_download(const char *url, const char *header_name, const char *header_value,
                   const char *dest, long long max_bytes, bool truncate_last_byte);
#endif

bool http_post_json(const char *url, const char *json, long *status);
