#include <stdint.h>

struct blowfish_ctx {
	uint32_t P[18], S0[256], S1[256], S2[256], S3[256];
};

extern void blowfish_init(struct blowfish_ctx *ctx, const uint8_t *key, unsigned int keybytes);
