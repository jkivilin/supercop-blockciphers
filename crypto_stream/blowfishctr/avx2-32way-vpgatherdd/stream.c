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

#define PARALLEL_BLOCKS 32
#define BLOCKSIZE 8

extern void __blowfish_enc_blk_avx2_32way(struct blowfish_ctx *ctx, uint8_t *dst, const uint8_t *src, char xor);

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

#define move256(dst, src) ({ \
	__asm__ ("vmovdqu %[s], %%ymm0;\n" \
		 "vmovdqu %%ymm0, %[d];\n" \
		 : [d] "=m" (*(dst)) \
		 : [s] "m" (*(src)) \
		 : "xmm0", "memory" \
	);})

__attribute__((optimize("unroll-loops")))
int crypto_stream_xor(unsigned char *out, const unsigned char *in,
		      unsigned long long inlen, const unsigned char *n,
		      const unsigned char *k)
{
#define PTR_ALIGN(ptr, mask) ((void *)((((long)(ptr)) + (mask)) & ~((long)(mask))))
	const unsigned long align = 32;
	char ctxbuf[sizeof(struct blowfish_ctx) + align];
	struct blowfish_ctx *ctx = PTR_ALIGN(ctxbuf, align - 1);
	uint64_t iv;
	uint64_t ivs[PARALLEL_BLOCKS];
	unsigned int i;

	blowfish_init(ctx, k, CRYPTO_KEYBYTES);
	bswap64(&iv, (const uint64_t *)n); /* be => le */

	__asm__ volatile ("vzeroupper; \n" :::);

	while (likely(inlen >= BLOCKSIZE * PARALLEL_BLOCKS)) {
		bswap64(&ivs[0], &iv); /* le => be */
		for (i = 1; i < PARALLEL_BLOCKS; i++) {
			add64(&ivs[i], &iv, i);
			bswap64(&ivs[i], &ivs[i]); /* le => be */
		}
		add64(&iv, &iv, PARALLEL_BLOCKS);

		if (unlikely(in) && unlikely(in != out)) {
			move256(out + BLOCKSIZE * 0, in + BLOCKSIZE * 0);
			move256(out + BLOCKSIZE * 4, in + BLOCKSIZE * 4);
			move256(out + BLOCKSIZE * 8, in + BLOCKSIZE * 8);
			move256(out + BLOCKSIZE * 12, in + BLOCKSIZE * 12);
			move256(out + BLOCKSIZE * 16, in + BLOCKSIZE * 16);
			move256(out + BLOCKSIZE * 20, in + BLOCKSIZE * 20);
			move256(out + BLOCKSIZE * 24, in + BLOCKSIZE * 24);
			move256(out + BLOCKSIZE * 28, in + BLOCKSIZE * 28);
		}

		__blowfish_enc_blk_avx2_32way(ctx, out, (uint8_t *)ivs, in != NULL);

		if (unlikely(in))
			in += BLOCKSIZE * PARALLEL_BLOCKS;

		out += BLOCKSIZE * PARALLEL_BLOCKS;
		inlen -= BLOCKSIZE * PARALLEL_BLOCKS;
	}

	if (unlikely(inlen > 0)) {
		unsigned int nblock = inlen / BLOCKSIZE;
		unsigned int lastlen = inlen % BLOCKSIZE;
		unsigned int j;

		for (i = 0; i < nblock + !!lastlen; i++) {
			bswap64(&ivs[i], &iv); /* le => be */
			inc64(&iv);
		}
		for (; i < PARALLEL_BLOCKS; i++) {
			ivs[i] = 0;
		}

		__blowfish_enc_blk_avx2_32way(ctx, (uint8_t *)ivs, (uint8_t *)ivs, 0);

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

	__asm__ volatile ("vzeroupper; \n" :::);

	return 0;
}

int crypto_stream(unsigned char *out, unsigned long long outlen,
		  const unsigned char *n,const unsigned char *k)
{
	return crypto_stream_xor(out, NULL, outlen, n, k);
}
