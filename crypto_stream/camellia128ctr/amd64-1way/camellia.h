#include <stdint.h>

#define CAMELLIA_TABLE_BYTE_LEN     272

struct camellia_ctx {
	uint64_t key_table[CAMELLIA_TABLE_BYTE_LEN / sizeof(uint64_t)];
	int key_length;
};

void camellia_init(struct camellia_ctx *ctx, const uint8_t *key, short keybytes);

void camellia_encrypt_asm(const struct camellia_ctx *ctx, void *dst, const void *src);
void camellia_decrypt_asm(const struct camellia_ctx *ctx, void *dst, const void *src);
