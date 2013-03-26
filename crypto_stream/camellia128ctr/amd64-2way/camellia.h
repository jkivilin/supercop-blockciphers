#include <stdint.h>

#define CAMELLIA_TABLE_BYTE_LEN     272

struct camellia_ctx {
	uint64_t key_table[CAMELLIA_TABLE_BYTE_LEN / sizeof(uint64_t)];
	int key_length;
};

void camellia_init(struct camellia_ctx *ctx, const uint8_t *key, short keybytes);

void camellia_enc_blk2(const struct camellia_ctx *ctx, uint8_t *dst, const uint8_t *src);
void camellia_dec_blk2(const struct camellia_ctx *ctx, uint8_t *dst, const uint8_t *src);
