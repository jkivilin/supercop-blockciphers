#include <openssl/camellia.h>
#include <stdint.h>
#include <memory.h>
#include <assert.h>
#include "crypto_stream.h"
#include "api.h"

int crypto_stream(unsigned char *out, unsigned long long outlen,
		  const unsigned char *n, const unsigned char *k)
{
	static const uint64_t zero[(1024 * 1024) / sizeof(uint64_t)];
	unsigned char tmp[CAMELLIA_BLOCK_SIZE] = {0, };
	unsigned char iv[CAMELLIA_BLOCK_SIZE];
	CAMELLIA_KEY ctx;
	unsigned int num = 0;

	assert(outlen <= sizeof(zero));

	Camellia_set_key(k, CRYPTO_KEYBYTES * 8, &ctx);
	memcpy(iv, n, sizeof(iv));

	Camellia_ctr128_encrypt((void *)zero, out, outlen, &ctx, iv, tmp, &num);

	return 0;
}

int crypto_stream_xor(unsigned char *out, const unsigned char *in,
		      unsigned long long inlen, const unsigned char *n,
		      const unsigned char *k)
{
	unsigned char tmp[CAMELLIA_BLOCK_SIZE] = {0, };
	unsigned char iv[CAMELLIA_BLOCK_SIZE];
	CAMELLIA_KEY ctx;
	unsigned int num = 0;

	Camellia_set_key(k, CRYPTO_KEYBYTES * 8, &ctx);
	memcpy(iv, n, sizeof(iv));

	Camellia_ctr128_encrypt(in, out, inlen, &ctx, iv, tmp, &num);

	return 0;
}
