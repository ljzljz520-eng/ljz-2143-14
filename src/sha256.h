#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define SHA256_HEX_SIZE 65

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    unsigned char buffer[64];
    size_t buflen;
} Sha256Ctx;

void sha256_init(Sha256Ctx *ctx);
void sha256_update(Sha256Ctx *ctx, const unsigned char *data, size_t len);
void sha256_final(Sha256Ctx *ctx, unsigned char out[32]);
void sha256_hex(const unsigned char digest[32], char out[SHA256_HEX_SIZE]);
int sha256_file(const char *path, char hex[SHA256_HEX_SIZE]);
int sha256_bytes(const unsigned char *data, size_t len, char hex[SHA256_HEX_SIZE]);
int sha256_stream_range(FILE *f, long long offset, long long length, char hex[SHA256_HEX_SIZE]);

#endif
