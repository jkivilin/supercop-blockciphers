#include <stdint.h>

#define AES_MAX_NR 14		       /* max no of rounds */
#define AES_MAX_NK 8		       /* max no of words in input key */
#define AES_MAX_NB 4		       /* max no of words in cipher blk */

struct aes_block {
	uint32_t d[4];
};

struct aes_ctx {
	uint32_t keysched[(AES_MAX_NR + 1) * AES_MAX_NB];
	uint32_t invkeysched[(AES_MAX_NR + 1) * AES_MAX_NB];
	uint32_t Nr;
};

extern void aes_init(struct aes_ctx *ctx, const uint8_t *key, int keylen);
