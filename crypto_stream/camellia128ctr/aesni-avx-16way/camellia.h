#include <stdint.h>

#define CAMELLIA_TABLE_BYTE_LEN     272

struct camellia_ctx {
	uint64_t key_table[CAMELLIA_TABLE_BYTE_LEN / sizeof(uint64_t)];
	int key_length;
};

void camellia_init(struct camellia_ctx *ctx, const uint8_t *key, short keybytes);

/* input:
 *	%rdi: ctx, CTX
 *	%xmm0..%xmm15: 16 plaintext blocks
 * output:
 *	%xmm0..%xmm15: 16 encrypted blocks, order swapped:
 *       7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8
 */
void __camellia_enc_blk16(const struct camellia_ctx *ctx);


/* input:
 *	%rdi: ctx, CTX
 *	%xmm0..%xmm15: 16 encrypted blocks
 * output:
 *	%xmm0..%xmm15: 16 plaintext blocks, order swapped:
 *       7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8
 */
void __camellia_dec_blk16(const struct camellia_ctx *ctx);
