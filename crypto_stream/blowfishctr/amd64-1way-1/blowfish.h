#include <stdint.h>

struct blowfish_ctx {
	uint32_t p[16 + 2];
	uint32_t s[4][256];
};

extern void blowfish_init(struct blowfish_ctx *ctx, const uint8_t *key, unsigned int keybytes);
extern void blowfish_enc_blk(const struct blowfish_ctx *ctx, void *out, const void *in);
extern void blowfish_dec_blk(const struct blowfish_ctx *ctx, void *out, const void *in);