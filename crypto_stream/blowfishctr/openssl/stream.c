#include <openssl/blowfish.h>
#include <stdint.h>
#include <memory.h>
#include <assert.h>
#include "crypto_stream.h"
#include "api.h"

#define BLOCKSIZE 8

#define unlikely(x)	(!__builtin_expect(!(x),1))
#define likely(x)	(__builtin_expect(!!(x),1))

int crypto_stream_xor(unsigned char *out, const unsigned char *in,
		      unsigned long long inlen, const unsigned char *n,
		      const unsigned char *k)
{
	BF_KEY ctx;
	uint64_t iv;

	BF_set_key(&ctx, CRYPTO_KEYBYTES, k);
	iv = __builtin_bswap64(*(uint64_t *)n); /* be => le */

	while (likely(inlen >= BLOCKSIZE)) {
		*(uint64_t *)out = __builtin_bswap64(iv++); /* le => be */

		BF_ecb_encrypt((void *)out, (void *)out, &ctx, BF_ENCRYPT);

		if (unlikely(in)) {
			((uint64_t *)out)[0] ^= ((uint64_t *)in)[0];
			in += BLOCKSIZE;
		}

		out += BLOCKSIZE;
		inlen -= BLOCKSIZE;
	}

	if (unlikely(inlen > 0)) {
		unsigned int j;

		iv = __builtin_bswap64(iv); /* le => be */

		BF_ecb_encrypt((void *)&iv, (void *)&iv, &ctx, BF_ENCRYPT);

		if (in) {
			for (j = 0; j < inlen; j++)
				out[j] = in[j] ^ ((uint8_t *)&iv)[j];
		} else {
			for (j = 0; j < inlen; j++)
				out[j] = ((uint8_t *)&iv)[j];
		}
	}

	return 0;
}

int crypto_stream(unsigned char *out, unsigned long long outlen,
		  const unsigned char *n,const unsigned char *k)
{
	return crypto_stream_xor(out, NULL, outlen, n, k);
}
