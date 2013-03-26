/*
 * SuperCop glue code for Blowfish
 *
 * Public domain, 2013/03/06
 * Jussi Kivilinna
 */

#include "crypto_stream.h"
#include <stdlib.h>
#include "api.h"
#include "blowfish.h"

#define unlikely(x)	(!__builtin_expect(!(x),1))
#define likely(x)	(__builtin_expect(!!(x),1))

#define BLOCKSIZE 8

extern void __blowfish_enc_blk_16way(struct blowfish_ctx *ctx, uint8_t *dst, const uint8_t *src, char xor);

static inline void bswap64(uint64_t *dst, const uint64_t *src)
{
	*dst = __builtin_bswap64(*src);
}

static inline void add64(uint64_t *dst, const uint64_t *src, uint64_t add)
{
	*dst = *src + add;
}

static inline void inc64(uint64_t *dst)
{
	add64(dst, dst, 1);
}

static inline void xor64(uint64_t *dst, const uint64_t *src1, const uint64_t *src2)
{
	*dst = *src1 ^ *src2;
}

static inline void xor128(uint64_t *dst, const uint64_t *src1, const uint64_t *src2)
{
	__asm__ (
		"vmovdqu %[s1], %%xmm0;\n"
		"vpxor %[s2], %%xmm0, %%xmm0;\n"
		"vmovdqu %%xmm0, %[d];\n"
		: [d] "=m" (*dst)
		: [s1] "m" (*src1), [s2] "m" (*src2)
		: "xmm0", "memory"
	);
}

static inline void mov128(uint64_t *dst, const uint64_t *src)
{
	__asm__ (
		"vmovdqu %[s], %%xmm0;\n"
		"vmovdqu %%xmm0, %[d];\n"
		: [d] "=m" (*dst)
		: [s] "m" (*src)
		: "xmm0", "memory"
	);
}

int crypto_stream_xor(unsigned char *out, const unsigned char *in,
		      unsigned long long inlen, const unsigned char *n,
		      const unsigned char *k)
{
#define PTR_ALIGN(ptr, mask) ((void *)((((long)(ptr)) + (mask)) & ~((long)(mask))))
	const unsigned long align = 16;
	char ctxbuf[sizeof(struct blowfish_ctx) + align];
	struct blowfish_ctx *ctx = PTR_ALIGN(ctxbuf, align - 1);
	uint64_t iv;
	uint64_t ivs[16];
	unsigned int i;

	blowfish_init(ctx, k, CRYPTO_KEYBYTES);
	bswap64(&iv, (const uint64_t *)n); /* be => le */

	while (likely(inlen >= BLOCKSIZE * 16)) {
		bswap64(&ivs[0], &iv); /* le => be */
		for (i = 1; i < 16; i++) {
			add64(&ivs[i], &iv, i);
			bswap64(&ivs[i], &ivs[i]); /* le => be */
		}
		add64(&iv, &iv, 16);

		__blowfish_enc_blk_16way(ctx, out, (uint8_t *)ivs, 0);

		if (unlikely(in)) {
			for (i = 0; i < 16; i+=2)
				xor128(&((uint64_t *)out)[i], &((uint64_t *)out)[i], &((uint64_t *)in)[i]);
			in += BLOCKSIZE * 16;
		}

		out += BLOCKSIZE * 16;
		inlen -= BLOCKSIZE * 16;
	}

	if (unlikely(inlen > 0)) {
		unsigned int nblock = inlen / BLOCKSIZE;
		unsigned int lastlen = inlen % BLOCKSIZE;
		unsigned int j;

		for (i = 0; i < nblock + !!lastlen; i++) {
			bswap64(&ivs[i], &iv); /* le => be */
			inc64(&iv);
		}
		for (; i < 16; i++) {
			ivs[i] = 0;
		}

		__blowfish_enc_blk_16way(ctx, (uint8_t *)ivs, (uint8_t *)ivs, 0);

		if (in) {
			for (i = 0; inlen >= 2*BLOCKSIZE; i+=2) {
				xor128((uint64_t *)out, (uint64_t *)in, (uint64_t *)&ivs[i]);

				inlen -= 2*BLOCKSIZE;
				in += 2*BLOCKSIZE;
				out += 2*BLOCKSIZE;
			}

			for (j = 0; j < inlen; j++)
				out[j] = in[j] ^ ((uint8_t*)&ivs[i])[j];
		} else {
			for (i = 0; inlen >= 2*BLOCKSIZE; i+=2) {
				mov128((uint64_t *)out, (uint64_t *)&ivs[i]);

				inlen -= 2*BLOCKSIZE;
				out += 2*BLOCKSIZE;
			}

			for (j = 0; j < inlen; j++)
				out[j] = ((uint8_t*)&ivs[i])[j];
		}
	}

	return 0;
}

int crypto_stream(unsigned char *out, unsigned long long outlen,
		  const unsigned char *n,const unsigned char *k)
{
	return crypto_stream_xor(out, NULL, outlen, n, k);
}
