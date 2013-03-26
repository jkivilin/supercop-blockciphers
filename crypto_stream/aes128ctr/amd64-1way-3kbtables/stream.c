/*
 * SuperCop glue code for AES
 *
 * Public domain, 2013/03/06
 * Jussi Kivilinna
 */

#include <stdint.h>
#include <memory.h>
#include "crypto_stream.h"
#include "api.h"
#include "aes.h"

#define unlikely(x)	(!__builtin_expect(!(x),1))
#define likely(x)	(__builtin_expect(!!(x),1))

#define BLOCKSIZE 16

extern void aes_encrypt(struct aes_ctx *ctx, void *out, const void *in);

extern void aes_get_ctr_cache(struct aes_ctx *ctx, uint32_t ctr_cache[5], const void *iv);
extern void aes_ctr_match_encrypt(struct aes_ctx *ctx, void *out, const uint32_t ctr_cache[5], unsigned char counter);

extern void aes_enc_blk(struct aes_ctx *ctx, void *out, const void *in);

extern void aes_get_counter_cache(struct aes_ctx *ctx, uint32_t ctr_cache[5], const void *iv_be);
extern void aes_enc_blk_ctr_cached(struct aes_ctx *ctx, void *out, uint32_t ctr_cache[5], uint8_t ctr_byte);

typedef struct {
	uint64_t ll[2];
} uint128_t;

static inline void bswap128(uint128_t *dst, const uint128_t *src)
{
	uint64_t tmp;

	tmp = __builtin_bswap64(src->ll[1]);
	dst->ll[1] = __builtin_bswap64(src->ll[0]);
	dst->ll[0] = tmp;
}

static inline void inc128(uint128_t *u)
{
	__asm__ (
		"addq $1, %[ll0];\n"
		"adcq $0, %[ll1];\n"
		: [ll0] "=g" (u->ll[0]), [ll1] "=g" (u->ll[1])
		: "0" (u->ll[0]), "1" (u->ll[1])
		:
	);
}

static inline void add128(uint128_t *dst, const uint128_t *src, uint64_t add)
{
	__asm__ (
		"addq %[add], %[ll0];\n"
		"adcq $0, %[ll1];\n"
		: [ll0] "=g" (dst->ll[0]), [ll1] "=g" (dst->ll[1])
		: "0" (src->ll[0]), "1" (src->ll[1]), [add] "cg" (add)
		:
	);
}

static inline void xor128(uint128_t *dst, const uint128_t *src1, const uint128_t *src2)
{
	dst->ll[0] = src1->ll[0] ^ src2->ll[0];
	dst->ll[1] = src1->ll[1] ^ src2->ll[1];
}

int crypto_stream_xor(unsigned char *out, const unsigned char *in,
		      unsigned long long inlen, const unsigned char *n,
		      const unsigned char *k)
{
#define CTX_TYPE struct aes_ctx
#define PTR_ALIGN(ptr, mask) ((void *)((((long)(ptr)) + (mask)) & ~((long)(mask))))
	const unsigned long align = 16;
	char ctxbuf[sizeof(CTX_TYPE) + align];
	CTX_TYPE *ctx = PTR_ALIGN(ctxbuf, align - 1);
	uint128_t iv;
	uint128_t ivs[1];
	uint32_t ctr_cache[5];
	int need_new_ctr_cache = 1;

	aes_init(ctx, k, CRYPTO_KEYBYTES);
	bswap128(&iv, (const uint128_t *)n); /* be => le */

	while (likely(inlen >= BLOCKSIZE)) {
		uint8_t ctr_byte = ((uint8_t *)&iv)[0]; /* le */

		if (unlikely(ctr_byte == 0x00))
			need_new_ctr_cache = 1;

		if (unlikely(need_new_ctr_cache)) {
			bswap128(&ivs[0], &iv); /* le => be */

			/*
			 * ctr-cache has to be updated
			 */
			need_new_ctr_cache = 0;
			aes_get_counter_cache(ctx, ctr_cache, &ivs[0]);
		}

		add128(&iv, &iv, 1);

		aes_enc_blk_ctr_cached(ctx, out, ctr_cache, ctr_byte);

		if (unlikely(in)) {
			xor128(&((uint128_t *)out)[0], &((uint128_t *)out)[0], &((uint128_t *)in)[0]);
			in += BLOCKSIZE;
		}

		out += BLOCKSIZE;
		inlen -= BLOCKSIZE;
	}

	if (unlikely(inlen > 0)) {
		unsigned int j;

		bswap128(&ivs[0], &iv); /* le => be */

		aes_enc_blk(ctx, (uint8_t *)ivs, (uint8_t *)ivs);

		if (in) {
			for (j = 0; j < inlen; j++)
				out[j] = in[j] ^ ((uint8_t*)&ivs[0])[j];
		} else {
			for (j = 0; j < inlen; j++)
				out[j] = ((uint8_t*)&ivs[0])[j];
		}
	}

	return 0;
}

int crypto_stream(unsigned char *out, unsigned long long outlen,
		  const unsigned char *n,const unsigned char *k)
{
	return crypto_stream_xor(out, NULL, outlen, n, k);
}
