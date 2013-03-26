#include <stdint.h>

/* Structure for an expanded Twofish key.  s contains the key-dependent
 * S-boxes composed with the MDS matrix; w contains the eight "whitening"
 * subkeys, K[0] through K[7].	k holds the remaining, "round" subkeys.  Note
 * that k[i] corresponds to what the Twofish paper calls K[i+8]. */
struct twofish_ctx {
	uint32_t s[4][256], w[8], k[32];
};

void twofish_init(struct twofish_ctx *ctx, const uint8_t *key, uint32_t klen);

