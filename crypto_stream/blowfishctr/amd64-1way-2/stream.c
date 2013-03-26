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

#define BLOCKSIZE 8

#define unlikely(x)	(!__builtin_expect(!(x),1))
#define likely(x)	(__builtin_expect(!!(x),1))

int crypto_stream_xor(unsigned char *out, const unsigned char *in,
		      unsigned long long inlen, const unsigned char *n,
		      const unsigned char *k)
{
#define PTR_ALIGN(ptr, mask) ((void *)((((long)(ptr)) + (mask)) & ~((long)(mask))))
	const unsigned long align = 4096;
	char ctxbuf[sizeof(struct blowfish_ctx) + align];
	struct blowfish_ctx *ctx = PTR_ALIGN(ctxbuf, align - 1);
	uint64_t iv;
	uint64_t block;

	blowfish_init(ctx, k, CRYPTO_KEYBYTES);
	iv = __builtin_bswap64(*(uint64_t *)n); /* be => le */

	while (likely(inlen >= BLOCKSIZE)) {
		block = __builtin_bswap64(iv++); /* le => be */

		blowfish_enc_blk(ctx, out, &block);

		if (unlikely(in)) {
			*(uint64_t *)out ^= *(uint64_t *)in;
			in += BLOCKSIZE;
		}

		out += BLOCKSIZE;
		inlen -= BLOCKSIZE;
	}

	if (unlikely(inlen > 0)) {
		/* handle remaining bytes */
		unsigned int i;

		block = __builtin_bswap64(iv); /* le => be */

		blowfish_enc_blk(ctx, &block, &block);

		if (in) {
			for (i = 0; i < inlen; i++)
				out[i] = in[i] ^ ((uint8_t*)&block)[i];
		} else {
			for (i = 0; i < inlen; i++)
				out[i] = ((uint8_t*)&block)[i];
		}
	}

	return 0;
}

int crypto_stream(unsigned char *out, unsigned long long outlen,
		  const unsigned char *n,const unsigned char *k)
{
	return crypto_stream_xor(out, NULL, outlen, n, k);
}
