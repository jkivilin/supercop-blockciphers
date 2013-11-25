/* camellia.c ver 1.2.0-aesni1.2
 *
 * Copyright (c) 2006,2007
 * NTT (Nippon Telegraph and Telephone Corporation) . All rights reserved.
 *
 * AES-NI implementation, ECB mode:
 * Copyright © 2012 Jussi Kivilinna <jussi.kivilinna@iki.fi>
 *
 * SuperCop integration:
 * Copyright © 2013 Jussi Kivilinna <jussi.kivilinna@iki.fi>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer as
 *   the first lines of this file unmodified.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NTT ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL NTT BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Algorithm Specification
 *  http://info.isl.ntt.co.jp/crypt/eng/camellia/specifications.html
 */


#include <string.h>
#include <stdlib.h>

#include "camellia.h"

#define CAMELLIA_BLOCK_SIZE 16
#define CAMELLIA_TABLE_WORD_LEN (CAMELLIA_TABLE_BYTE_LEN / 4)

typedef unsigned int KEY_TABLE_TYPE[CAMELLIA_TABLE_WORD_LEN];

/* u32 must be 32bit word */
typedef unsigned int u32;
typedef unsigned char u8;

extern void camellia_setup128(void *subkeys, const void *key128);

#if 0
extern void camellia_setup256(void *subkeys, const void *key256);

void camellia_setup192(u32 *subkey, const unsigned char *key)
{
    unsigned char kk[32];
    u32 krll, krlr, krrl,krrr;

    memcpy(kk, key, 24);
    memcpy((unsigned char *)&krll, key+16,4);
    memcpy((unsigned char *)&krlr, key+20,4);
    krrl = ~krll;
    krrr = ~krlr;
    memcpy(kk+24, (unsigned char *)&krrl, 4);
    memcpy(kk+28, (unsigned char *)&krrr, 4);
    camellia_setup256(subkey, kk);
    return;
}
#endif

/***
 *
 * API for compatibility
 */

static void Camellia_Ekeygen(const int keyBitLength,
		      const unsigned char *rawKey,
		      KEY_TABLE_TYPE keyTable)
{
    switch(keyBitLength) {
    case 128:
	camellia_setup128(keyTable, rawKey);
	break;
#if 0
    case 192:
	camellia_setup192(keyTable, rawKey);
	break;
    case 256:
	camellia_setup256(keyTable, rawKey);
	break;
#endif
    default:
	break;
    }
}


void camellia_init(struct camellia_ctx *ctx, const uint8_t *key, short keybytes)
{
	if (keybytes != 128 / 8)
		exit(keybytes * -8);

	Camellia_Ekeygen(128, (const unsigned char*)key,
			 (unsigned int *)ctx->key_table);

	ctx->key_length = 128 / 8;
}
