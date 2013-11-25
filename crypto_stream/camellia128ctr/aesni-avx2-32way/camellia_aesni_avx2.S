/* camellia_aesni_avx2.S v1.1
 *
 * Copyright © 2013 Jussi Kivilinna <jussi.kivilinna@iki.fi>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#define CAMELLIA_TABLE_BYTE_LEN 272

/* struct camellia_ctx: */
#define key_table 0
#define key_length CAMELLIA_TABLE_BYTE_LEN

/* register macros */
#define CTX %rdi
#define RIO %r8

/**********************************************************************
  helper macros
 **********************************************************************/
#define filter_8bit(x, lo_t, hi_t, mask4bit, tmp0) \
	vpand x, mask4bit, tmp0; \
	vpandn x, mask4bit, x; \
	vpsrld $4, x, x; \
	\
	vpshufb tmp0, lo_t, tmp0; \
	vpshufb x, hi_t, x; \
	vpxor tmp0, x, x;

#define ymm0_x xmm0
#define ymm1_x xmm1
#define ymm2_x xmm2
#define ymm3_x xmm3
#define ymm4_x xmm4
#define ymm5_x xmm5
#define ymm6_x xmm6
#define ymm7_x xmm7
#define ymm8_x xmm8
#define ymm9_x xmm9
#define ymm10_x xmm10
#define ymm11_x xmm11
#define ymm12_x xmm12
#define ymm13_x xmm13
#define ymm14_x xmm14
#define ymm15_x xmm15

/**********************************************************************
  32-way camellia
 **********************************************************************/

/*
 * IN:
 *   x0..x7: byte-sliced AB state
 *   mem_cd: register pointer storing CD state
 *   key: index for key material
 * OUT:
 *   x0..x7: new byte-sliced CD state
 */
#define roundsm32(x0, x1, x2, x3, x4, x5, x6, x7, t0, t1, t2, t3, t4, t5, t6, \
		  t7, mem_cd, key) \
	/* \
	 * S-function with AES subbytes \
	 */ \
	vbroadcasti128 .Linv_shift_row, t4; \
	vpbroadcastd .L0f0f0f0f, t7; \
	vbroadcasti128 .Lpre_tf_lo_s1, t5; \
	vbroadcasti128 .Lpre_tf_hi_s1, t6; \
	vbroadcasti128 .Lpre_tf_lo_s4, t2; \
	vbroadcasti128 .Lpre_tf_hi_s4, t3; \
	\
	/* AES inverse shift rows */ \
	vpshufb t4, x0, x0; \
	vpshufb t4, x7, x7; \
	vpshufb t4, x3, x3; \
	vpshufb t4, x6, x6; \
	vpshufb t4, x2, x2; \
	vpshufb t4, x5, x5; \
	vpshufb t4, x1, x1; \
	vpshufb t4, x4, x4; \
	\
	/* prefilter sboxes 1, 2 and 3 */ \
	/* prefilter sbox 4 */ \
	filter_8bit(x0, t5, t6, t7, t4); \
	filter_8bit(x7, t5, t6, t7, t4); \
	vextracti128 $1, x0, t0##_x; \
	vextracti128 $1, x7, t1##_x; \
	filter_8bit(x3, t2, t3, t7, t4); \
	filter_8bit(x6, t2, t3, t7, t4); \
	vextracti128 $1, x3, t3##_x; \
	vextracti128 $1, x6, t2##_x; \
	filter_8bit(x2, t5, t6, t7, t4); \
	filter_8bit(x5, t5, t6, t7, t4); \
	filter_8bit(x1, t5, t6, t7, t4); \
	filter_8bit(x4, t5, t6, t7, t4); \
	\
	vpxor t4##_x, t4##_x, t4##_x; \
	\
	/* AES subbytes + AES shift rows */ \
	vextracti128 $1, x2, t6##_x; \
	vextracti128 $1, x5, t5##_x; \
	vaesenclast t4##_x, x0##_x, x0##_x; \
	vaesenclast t4##_x, t0##_x, t0##_x; \
	vaesenclast t4##_x, x7##_x, x7##_x; \
	vaesenclast t4##_x, t1##_x, t1##_x; \
	vaesenclast t4##_x, x3##_x, x3##_x; \
	vaesenclast t4##_x, t3##_x, t3##_x; \
	vaesenclast t4##_x, x6##_x, x6##_x; \
	vaesenclast t4##_x, t2##_x, t2##_x; \
	vinserti128 $1, t0##_x, x0, x0; \
	vinserti128 $1, t1##_x, x7, x7; \
	vinserti128 $1, t3##_x, x3, x3; \
	vinserti128 $1, t2##_x, x6, x6; \
	vextracti128 $1, x1, t3##_x; \
	vextracti128 $1, x4, t2##_x; \
	vbroadcasti128 .Lpost_tf_lo_s1, t0; \
	vbroadcasti128 .Lpost_tf_hi_s1, t1; \
	vaesenclast t4##_x, x2##_x, x2##_x; \
	vaesenclast t4##_x, t6##_x, t6##_x; \
	vaesenclast t4##_x, x5##_x, x5##_x; \
	vaesenclast t4##_x, t5##_x, t5##_x; \
	vaesenclast t4##_x, x1##_x, x1##_x; \
	vaesenclast t4##_x, t3##_x, t3##_x; \
	vaesenclast t4##_x, x4##_x, x4##_x; \
	vaesenclast t4##_x, t2##_x, t2##_x; \
	vinserti128 $1, t6##_x, x2, x2; \
	vinserti128 $1, t5##_x, x5, x5; \
	vinserti128 $1, t3##_x, x1, x1; \
	vinserti128 $1, t2##_x, x4, x4; \
	\
	/* postfilter sboxes 1 and 4 */ \
	vbroadcasti128 .Lpost_tf_lo_s3, t2; \
	vbroadcasti128 .Lpost_tf_hi_s3, t3; \
	filter_8bit(x0, t0, t1, t7, t4); \
	filter_8bit(x7, t0, t1, t7, t4); \
	filter_8bit(x3, t0, t1, t7, t6); \
	filter_8bit(x6, t0, t1, t7, t6); \
	\
	/* postfilter sbox 3 */ \
	vbroadcasti128 .Lpost_tf_lo_s2, t4; \
	vbroadcasti128 .Lpost_tf_hi_s2, t5; \
	filter_8bit(x2, t2, t3, t7, t6); \
	filter_8bit(x5, t2, t3, t7, t6); \
	\
	vpbroadcastq key, t0; /* higher 64-bit duplicate ignored */ \
	\
	/* postfilter sbox 2 */ \
	filter_8bit(x1, t4, t5, t7, t2); \
	filter_8bit(x4, t4, t5, t7, t2); \
	vpxor t7, t7, t7; \
	\
	vpsrldq $1, t0, t1; \
	vpsrldq $2, t0, t2; \
	vpshufb t7, t1, t1; \
	vpsrldq $3, t0, t3; \
	\
	/* P-function */ \
	vpxor x5, x0, x0; \
	vpxor x6, x1, x1; \
	vpxor x7, x2, x2; \
	vpxor x4, x3, x3; \
	\
	vpshufb t7, t2, t2; \
	vpsrldq $4, t0, t4; \
	vpshufb t7, t3, t3; \
	vpsrldq $5, t0, t5; \
	vpshufb t7, t4, t4; \
	\
	vpxor x2, x4, x4; \
	vpxor x3, x5, x5; \
	vpxor x0, x6, x6; \
	vpxor x1, x7, x7; \
	\
	vpsrldq $6, t0, t6; \
	vpshufb t7, t5, t5; \
	vpshufb t7, t6, t6; \
	\
	vpxor x7, x0, x0; \
	vpxor x4, x1, x1; \
	vpxor x5, x2, x2; \
	vpxor x6, x3, x3; \
	\
	vpxor x3, x4, x4; \
	vpxor x0, x5, x5; \
	vpxor x1, x6, x6; \
	vpxor x2, x7, x7; /* note: high and low parts swapped */ \
	\
	/* Add key material and result to CD (x becomes new CD) */ \
	\
	vpxor t6, x1, x1; \
	vpxor 5 * 32(mem_cd), x1, x1; \
	\
	vpsrldq $7, t0, t6; \
	vpshufb t7, t0, t0; \
	vpshufb t7, t6, t7; \
	\
	vpxor t7, x0, x0; \
	vpxor 4 * 32(mem_cd), x0, x0; \
	\
	vpxor t5, x2, x2; \
	vpxor 6 * 32(mem_cd), x2, x2; \
	\
	vpxor t4, x3, x3; \
	vpxor 7 * 32(mem_cd), x3, x3; \
	\
	vpxor t3, x4, x4; \
	vpxor 0 * 32(mem_cd), x4, x4; \
	\
	vpxor t2, x5, x5; \
	vpxor 1 * 32(mem_cd), x5, x5; \
	\
	vpxor t1, x6, x6; \
	vpxor 2 * 32(mem_cd), x6, x6; \
	\
	vpxor t0, x7, x7; \
	vpxor 3 * 32(mem_cd), x7, x7;

/*
 * IN/OUT:
 *  x0..x7: byte-sliced AB state preloaded
 *  mem_ab: byte-sliced AB state in memory
 *  mem_cb: byte-sliced CD state in memory
 */
#define two_roundsm32(x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3, y4, y5, \
		      y6, y7, mem_ab, mem_cd, i, dir, store_ab) \
	roundsm32(x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3, y4, y5, \
		  y6, y7, mem_cd, (key_table + (i) * 8)(CTX)); \
	\
	vmovdqu x0, 4 * 32(mem_cd); \
	vmovdqu x1, 5 * 32(mem_cd); \
	vmovdqu x2, 6 * 32(mem_cd); \
	vmovdqu x3, 7 * 32(mem_cd); \
	vmovdqu x4, 0 * 32(mem_cd); \
	vmovdqu x5, 1 * 32(mem_cd); \
	vmovdqu x6, 2 * 32(mem_cd); \
	vmovdqu x7, 3 * 32(mem_cd); \
	\
	roundsm32(x4, x5, x6, x7, x0, x1, x2, x3, y0, y1, y2, y3, y4, y5, \
		  y6, y7, mem_ab, (key_table + ((i) + (dir)) * 8)(CTX)); \
	\
	store_ab(x0, x1, x2, x3, x4, x5, x6, x7, mem_ab);

#define dummy_store(x0, x1, x2, x3, x4, x5, x6, x7, mem_ab) /* do nothing */

#define store_ab_state(x0, x1, x2, x3, x4, x5, x6, x7, mem_ab) \
	/* Store new AB state */ \
	vmovdqu x4, 4 * 32(mem_ab); \
	vmovdqu x5, 5 * 32(mem_ab); \
	vmovdqu x6, 6 * 32(mem_ab); \
	vmovdqu x7, 7 * 32(mem_ab); \
	vmovdqu x0, 0 * 32(mem_ab); \
	vmovdqu x1, 1 * 32(mem_ab); \
	vmovdqu x2, 2 * 32(mem_ab); \
	vmovdqu x3, 3 * 32(mem_ab);

#define enc_rounds32(x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3, y4, y5, \
		      y6, y7, mem_ab, mem_cd, i) \
	two_roundsm32(x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3, y4, y5, \
		      y6, y7, mem_ab, mem_cd, (i) + 2, 1, store_ab_state); \
	two_roundsm32(x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3, y4, y5, \
		      y6, y7, mem_ab, mem_cd, (i) + 4, 1, store_ab_state); \
	two_roundsm32(x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3, y4, y5, \
		      y6, y7, mem_ab, mem_cd, (i) + 6, 1, dummy_store);

#define dec_rounds32(x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3, y4, y5, \
		      y6, y7, mem_ab, mem_cd, i) \
	two_roundsm32(x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3, y4, y5, \
		      y6, y7, mem_ab, mem_cd, (i) + 7, -1, store_ab_state); \
	two_roundsm32(x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3, y4, y5, \
		      y6, y7, mem_ab, mem_cd, (i) + 5, -1, store_ab_state); \
	two_roundsm32(x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3, y4, y5, \
		      y6, y7, mem_ab, mem_cd, (i) + 3, -1, dummy_store);

/*
 * IN:
 *  v0..3: byte-sliced 32-bit integers
 * OUT:
 *  v0..3: (IN <<< 1)
 */
#define rol32_1_32(v0, v1, v2, v3, t0, t1, t2, zero) \
	vpcmpgtb v0, zero, t0; \
	vpaddb v0, v0, v0; \
	vpabsb t0, t0; \
	\
	vpcmpgtb v1, zero, t1; \
	vpaddb v1, v1, v1; \
	vpabsb t1, t1; \
	\
	vpcmpgtb v2, zero, t2; \
	vpaddb v2, v2, v2; \
	vpabsb t2, t2; \
	\
	vpor t0, v1, v1; \
	\
	vpcmpgtb v3, zero, t0; \
	vpaddb v3, v3, v3; \
	vpabsb t0, t0; \
	\
	vpor t1, v2, v2; \
	vpor t2, v3, v3; \
	vpor t0, v0, v0;

/*
 * IN:
 *   r: byte-sliced AB state in memory
 *   l: byte-sliced CD state in memory
 * OUT:
 *   x0..x7: new byte-sliced CD state
 */
#define fls32(l, l0, l1, l2, l3, l4, l5, l6, l7, r, t0, t1, t2, t3, tt0, \
	      tt1, tt2, tt3, kll, klr, krl, krr) \
	/* \
	 * t0 = kll; \
	 * t0 &= ll; \
	 * lr ^= rol32(t0, 1); \
	 */ \
	vpbroadcastd kll, t0; /* only lowest 32-bit used */ \
	vpxor tt0, tt0, tt0; \
	vpshufb tt0, t0, t3; \
	vpsrldq $1, t0, t0; \
	vpshufb tt0, t0, t2; \
	vpsrldq $1, t0, t0; \
	vpshufb tt0, t0, t1; \
	vpsrldq $1, t0, t0; \
	vpshufb tt0, t0, t0; \
	\
	vpand l0, t0, t0; \
	vpand l1, t1, t1; \
	vpand l2, t2, t2; \
	vpand l3, t3, t3; \
	\
	rol32_1_32(t3, t2, t1, t0, tt1, tt2, tt3, tt0); \
	\
	vpxor l4, t0, l4; \
	vpbroadcastd krr, t0; /* only lowest 32-bit used */ \
	vmovdqu l4, 4 * 32(l); \
	vpxor l5, t1, l5; \
	vmovdqu l5, 5 * 32(l); \
	vpxor l6, t2, l6; \
	vmovdqu l6, 6 * 32(l); \
	vpxor l7, t3, l7; \
	vmovdqu l7, 7 * 32(l); \
	\
	/* \
	 * t2 = krr; \
	 * t2 |= rr; \
	 * rl ^= t2; \
	 */ \
	\
	vpshufb tt0, t0, t3; \
	vpsrldq $1, t0, t0; \
	vpshufb tt0, t0, t2; \
	vpsrldq $1, t0, t0; \
	vpshufb tt0, t0, t1; \
	vpsrldq $1, t0, t0; \
	vpshufb tt0, t0, t0; \
	\
	vpor 4 * 32(r), t0, t0; \
	vpor 5 * 32(r), t1, t1; \
	vpor 6 * 32(r), t2, t2; \
	vpor 7 * 32(r), t3, t3; \
	\
	vpxor 0 * 32(r), t0, t0; \
	vpxor 1 * 32(r), t1, t1; \
	vpxor 2 * 32(r), t2, t2; \
	vpxor 3 * 32(r), t3, t3; \
	vmovdqu t0, 0 * 32(r); \
	vpbroadcastd krl, t0; /* only lowest 32-bit used */ \
	vmovdqu t1, 1 * 32(r); \
	vmovdqu t2, 2 * 32(r); \
	vmovdqu t3, 3 * 32(r); \
	\
	/* \
	 * t2 = krl; \
	 * t2 &= rl; \
	 * rr ^= rol32(t2, 1); \
	 */ \
	vpshufb tt0, t0, t3; \
	vpsrldq $1, t0, t0; \
	vpshufb tt0, t0, t2; \
	vpsrldq $1, t0, t0; \
	vpshufb tt0, t0, t1; \
	vpsrldq $1, t0, t0; \
	vpshufb tt0, t0, t0; \
	\
	vpand 0 * 32(r), t0, t0; \
	vpand 1 * 32(r), t1, t1; \
	vpand 2 * 32(r), t2, t2; \
	vpand 3 * 32(r), t3, t3; \
	\
	rol32_1_32(t3, t2, t1, t0, tt1, tt2, tt3, tt0); \
	\
	vpxor 4 * 32(r), t0, t0; \
	vpxor 5 * 32(r), t1, t1; \
	vpxor 6 * 32(r), t2, t2; \
	vpxor 7 * 32(r), t3, t3; \
	vmovdqu t0, 4 * 32(r); \
	vpbroadcastd klr, t0; /* only lowest 32-bit used */ \
	vmovdqu t1, 5 * 32(r); \
	vmovdqu t2, 6 * 32(r); \
	vmovdqu t3, 7 * 32(r); \
	\
	/* \
	 * t0 = klr; \
	 * t0 |= lr; \
	 * ll ^= t0; \
	 */ \
	\
	vpshufb tt0, t0, t3; \
	vpsrldq $1, t0, t0; \
	vpshufb tt0, t0, t2; \
	vpsrldq $1, t0, t0; \
	vpshufb tt0, t0, t1; \
	vpsrldq $1, t0, t0; \
	vpshufb tt0, t0, t0; \
	\
	vpor l4, t0, t0; \
	vpor l5, t1, t1; \
	vpor l6, t2, t2; \
	vpor l7, t3, t3; \
	\
	vpxor l0, t0, l0; \
	vmovdqu l0, 0 * 32(l); \
	vpxor l1, t1, l1; \
	vmovdqu l1, 1 * 32(l); \
	vpxor l2, t2, l2; \
	vmovdqu l2, 2 * 32(l); \
	vpxor l3, t3, l3; \
	vmovdqu l3, 3 * 32(l);

#define transpose_4x4(x0, x1, x2, x3, t1, t2) \
	vpunpckhdq x1, x0, t2; \
	vpunpckldq x1, x0, x0; \
	\
	vpunpckldq x3, x2, t1; \
	vpunpckhdq x3, x2, x2; \
	\
	vpunpckhqdq t1, x0, x1; \
	vpunpcklqdq t1, x0, x0; \
	\
	vpunpckhqdq x2, t2, x3; \
	vpunpcklqdq x2, t2, x2;

#define byteslice_16x16b_fast(a0, b0, c0, d0, a1, b1, c1, d1, a2, b2, c2, d2, \
			      a3, b3, c3, d3, st0, st1) \
	vmovdqu d2, st0; \
	vmovdqu d3, st1; \
	transpose_4x4(a0, a1, a2, a3, d2, d3); \
	transpose_4x4(b0, b1, b2, b3, d2, d3); \
	vmovdqu st0, d2; \
	vmovdqu st1, d3; \
	\
	vmovdqu a0, st0; \
	vmovdqu a1, st1; \
	transpose_4x4(c0, c1, c2, c3, a0, a1); \
	transpose_4x4(d0, d1, d2, d3, a0, a1); \
	\
	vbroadcasti128 .Lshufb_16x16b, a0; \
	vmovdqu st1, a1; \
	vpshufb a0, a2, a2; \
	vpshufb a0, a3, a3; \
	vpshufb a0, b0, b0; \
	vpshufb a0, b1, b1; \
	vpshufb a0, b2, b2; \
	vpshufb a0, b3, b3; \
	vpshufb a0, a1, a1; \
	vpshufb a0, c0, c0; \
	vpshufb a0, c1, c1; \
	vpshufb a0, c2, c2; \
	vpshufb a0, c3, c3; \
	vpshufb a0, d0, d0; \
	vpshufb a0, d1, d1; \
	vpshufb a0, d2, d2; \
	vpshufb a0, d3, d3; \
	vmovdqu d3, st1; \
	vmovdqu st0, d3; \
	vpshufb a0, d3, a0; \
	vmovdqu d2, st0; \
	\
	transpose_4x4(a0, b0, c0, d0, d2, d3); \
	transpose_4x4(a1, b1, c1, d1, d2, d3); \
	vmovdqu st0, d2; \
	vmovdqu st1, d3; \
	\
	vmovdqu b0, st0; \
	vmovdqu b1, st1; \
	transpose_4x4(a2, b2, c2, d2, b0, b1); \
	transpose_4x4(a3, b3, c3, d3, b0, b1); \
	vmovdqu st0, b0; \
	vmovdqu st1, b1; \
	/* does not adjust output bytes inside vectors */

/* load blocks to registers and apply pre-whitening */
#define inpack32_pre(x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3, y4, y5, \
		     y6, y7, rio, key) \
	vpbroadcastq key, x0; \
	vpshufb .Lpack_bswap, x0, x0; \
	\
	vpxor 0 * 32(rio), x0, y7; \
	vpxor 1 * 32(rio), x0, y6; \
	vpxor 2 * 32(rio), x0, y5; \
	vpxor 3 * 32(rio), x0, y4; \
	vpxor 4 * 32(rio), x0, y3; \
	vpxor 5 * 32(rio), x0, y2; \
	vpxor 6 * 32(rio), x0, y1; \
	vpxor 7 * 32(rio), x0, y0; \
	vpxor 8 * 32(rio), x0, x7; \
	vpxor 9 * 32(rio), x0, x6; \
	vpxor 10 * 32(rio), x0, x5; \
	vpxor 11 * 32(rio), x0, x4; \
	vpxor 12 * 32(rio), x0, x3; \
	vpxor 13 * 32(rio), x0, x2; \
	vpxor 14 * 32(rio), x0, x1; \
	vpxor 15 * 32(rio), x0, x0;

/* byteslice pre-whitened blocks and store to temporary memory */
#define inpack32_post(x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3, y4, y5, \
		      y6, y7, mem_ab, mem_cd) \
	byteslice_16x16b_fast(x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3, \
			      y4, y5, y6, y7, (mem_ab), (mem_cd)); \
	\
	vmovdqu x0, 0 * 32(mem_ab); \
	vmovdqu x1, 1 * 32(mem_ab); \
	vmovdqu x2, 2 * 32(mem_ab); \
	vmovdqu x3, 3 * 32(mem_ab); \
	vmovdqu x4, 4 * 32(mem_ab); \
	vmovdqu x5, 5 * 32(mem_ab); \
	vmovdqu x6, 6 * 32(mem_ab); \
	vmovdqu x7, 7 * 32(mem_ab); \
	vmovdqu y0, 0 * 32(mem_cd); \
	vmovdqu y1, 1 * 32(mem_cd); \
	vmovdqu y2, 2 * 32(mem_cd); \
	vmovdqu y3, 3 * 32(mem_cd); \
	vmovdqu y4, 4 * 32(mem_cd); \
	vmovdqu y5, 5 * 32(mem_cd); \
	vmovdqu y6, 6 * 32(mem_cd); \
	vmovdqu y7, 7 * 32(mem_cd);

/* de-byteslice, apply post-whitening and store blocks */
#define outunpack32(x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3, y4, \
		    y5, y6, y7, key, stack_tmp0, stack_tmp1) \
	byteslice_16x16b_fast(y0, y4, x0, x4, y1, y5, x1, x5, y2, y6, x2, x6, \
			      y3, y7, x3, x7, stack_tmp0, stack_tmp1); \
	\
	vmovdqu x0, stack_tmp0; \
	\
	vpbroadcastq key, x0; \
	vpshufb .Lpack_bswap, x0, x0; \
	\
	vpxor x0, y7, y7; \
	vpxor x0, y6, y6; \
	vpxor x0, y5, y5; \
	vpxor x0, y4, y4; \
	vpxor x0, y3, y3; \
	vpxor x0, y2, y2; \
	vpxor x0, y1, y1; \
	vpxor x0, y0, y0; \
	vpxor x0, x7, x7; \
	vpxor x0, x6, x6; \
	vpxor x0, x5, x5; \
	vpxor x0, x4, x4; \
	vpxor x0, x3, x3; \
	vpxor x0, x2, x2; \
	vpxor x0, x1, x1; \
	vpxor stack_tmp0, x0, x0;

#define write_output(x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3, y4, y5, \
		     y6, y7, rio) \
	vmovdqu x0, 0 * 32(rio); \
	vmovdqu x1, 1 * 32(rio); \
	vmovdqu x2, 2 * 32(rio); \
	vmovdqu x3, 3 * 32(rio); \
	vmovdqu x4, 4 * 32(rio); \
	vmovdqu x5, 5 * 32(rio); \
	vmovdqu x6, 6 * 32(rio); \
	vmovdqu x7, 7 * 32(rio); \
	vmovdqu y0, 8 * 32(rio); \
	vmovdqu y1, 9 * 32(rio); \
	vmovdqu y2, 10 * 32(rio); \
	vmovdqu y3, 11 * 32(rio); \
	vmovdqu y4, 12 * 32(rio); \
	vmovdqu y5, 13 * 32(rio); \
	vmovdqu y6, 14 * 32(rio); \
	vmovdqu y7, 15 * 32(rio);

.data
.align 32

#define SHUFB_BYTES(idx) \
	0 + (idx), 4 + (idx), 8 + (idx), 12 + (idx)

.Lshufb_16x16b:
	.byte SHUFB_BYTES(0), SHUFB_BYTES(1), SHUFB_BYTES(2), SHUFB_BYTES(3)
	.byte SHUFB_BYTES(0), SHUFB_BYTES(1), SHUFB_BYTES(2), SHUFB_BYTES(3)

.Lpack_bswap:
	.long 0x00010203, 0x04050607, 0x80808080, 0x80808080
	.long 0x00010203, 0x04050607, 0x80808080, 0x80808080

/* For CTR-mode IV byteswap */
.Lbswap128_mask:
	.byte 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0

/*
 * pre-SubByte transform
 *
 * pre-lookup for sbox1, sbox2, sbox3:
 *   swap_bitendianness(
 *       isom_map_camellia_to_aes(
 *           camellia_f(
 *               swap_bitendianess(in)
 *           )
 *       )
 *   )
 *
 * (note: '⊕ 0xc5' inside camellia_f())
 */
.Lpre_tf_lo_s1:
	.byte 0x45, 0xe8, 0x40, 0xed, 0x2e, 0x83, 0x2b, 0x86
	.byte 0x4b, 0xe6, 0x4e, 0xe3, 0x20, 0x8d, 0x25, 0x88
.Lpre_tf_hi_s1:
	.byte 0x00, 0x51, 0xf1, 0xa0, 0x8a, 0xdb, 0x7b, 0x2a
	.byte 0x09, 0x58, 0xf8, 0xa9, 0x83, 0xd2, 0x72, 0x23

/*
 * pre-SubByte transform
 *
 * pre-lookup for sbox4:
 *   swap_bitendianness(
 *       isom_map_camellia_to_aes(
 *           camellia_f(
 *               swap_bitendianess(in <<< 1)
 *           )
 *       )
 *   )
 *
 * (note: '⊕ 0xc5' inside camellia_f())
 */
.Lpre_tf_lo_s4:
	.byte 0x45, 0x40, 0x2e, 0x2b, 0x4b, 0x4e, 0x20, 0x25
	.byte 0x14, 0x11, 0x7f, 0x7a, 0x1a, 0x1f, 0x71, 0x74
.Lpre_tf_hi_s4:
	.byte 0x00, 0xf1, 0x8a, 0x7b, 0x09, 0xf8, 0x83, 0x72
	.byte 0xad, 0x5c, 0x27, 0xd6, 0xa4, 0x55, 0x2e, 0xdf

/*
 * post-SubByte transform
 * 
 * post-lookup for sbox1, sbox4:
 *  swap_bitendianness(
 *      camellia_h(
 *          isom_map_aes_to_camellia(
 *              swap_bitendianness(
 *                  aes_inverse_affine_transform(in)
 *              )
 *          )
 *      )
 *  )
 *
 * (note: '⊕ 0x6e' inside camellia_h())
 */
.Lpost_tf_lo_s1:
	.byte 0x3c, 0xcc, 0xcf, 0x3f, 0x32, 0xc2, 0xc1, 0x31
	.byte 0xdc, 0x2c, 0x2f, 0xdf, 0xd2, 0x22, 0x21, 0xd1
.Lpost_tf_hi_s1:
	.byte 0x00, 0xf9, 0x86, 0x7f, 0xd7, 0x2e, 0x51, 0xa8
	.byte 0xa4, 0x5d, 0x22, 0xdb, 0x73, 0x8a, 0xf5, 0x0c

/*
 * post-SubByte transform
 *
 * post-lookup for sbox2:
 *  swap_bitendianness(
 *      camellia_h(
 *          isom_map_aes_to_camellia(
 *              swap_bitendianness(
 *                  aes_inverse_affine_transform(in)
 *              )
 *          )
 *      )
 *  ) <<< 1
 *
 * (note: '⊕ 0x6e' inside camellia_h())
 */
.Lpost_tf_lo_s2:
	.byte 0x78, 0x99, 0x9f, 0x7e, 0x64, 0x85, 0x83, 0x62
	.byte 0xb9, 0x58, 0x5e, 0xbf, 0xa5, 0x44, 0x42, 0xa3
.Lpost_tf_hi_s2:
	.byte 0x00, 0xf3, 0x0d, 0xfe, 0xaf, 0x5c, 0xa2, 0x51
	.byte 0x49, 0xba, 0x44, 0xb7, 0xe6, 0x15, 0xeb, 0x18

/*
 * post-SubByte transform
 *
 * post-lookup for sbox3:
 *  swap_bitendianness(
 *      camellia_h(
 *          isom_map_aes_to_camellia(
 *              swap_bitendianness(
 *                  aes_inverse_affine_transform(in)
 *              )
 *          )
 *      )
 *  ) >>> 1
 *
 * (note: '⊕ 0x6e' inside camellia_h())
 */
.Lpost_tf_lo_s3:
	.byte 0x1e, 0x66, 0xe7, 0x9f, 0x19, 0x61, 0xe0, 0x98
	.byte 0x6e, 0x16, 0x97, 0xef, 0x69, 0x11, 0x90, 0xe8
.Lpost_tf_hi_s3:
	.byte 0x00, 0xfc, 0x43, 0xbf, 0xeb, 0x17, 0xa8, 0x54
	.byte 0x52, 0xae, 0x11, 0xed, 0xb9, 0x45, 0xfa, 0x06

/* For isolating SubBytes from AESENCLAST, inverse shift row */
.Linv_shift_row:
	.byte 0x00, 0x0d, 0x0a, 0x07, 0x04, 0x01, 0x0e, 0x0b
	.byte 0x08, 0x05, 0x02, 0x0f, 0x0c, 0x09, 0x06, 0x03

.align 4
/* 4-bit mask */
.L0f0f0f0f:
	.long 0x0f0f0f0f

.text

.align 8
.type   __camellia_enc_blk32,@function;

__camellia_enc_blk32:
	/* input:
	 *	%rdi: ctx, CTX
	 *	%rax: temporary storage, 512 bytes
	 *	%ymm0..%ymm15: 32 plaintext blocks
	 * output:
	 *	%ymm0..%ymm15: 32 encrypted blocks, order swapped:
	 *       7, 8, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8
	 */

	leaq 8 * 32(%rax), %rcx;

	inpack32_post(%ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
		      %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
		      %ymm15, %rax, %rcx);

	enc_rounds32(%ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
		     %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
		     %ymm15, %rax, %rcx, 0);

	fls32(%rax, %ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
	      %rcx, %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
	      %ymm15,
	      ((key_table + (8) * 8) + 0)(CTX),
	      ((key_table + (8) * 8) + 4)(CTX),
	      ((key_table + (8) * 8) + 8)(CTX),
	      ((key_table + (8) * 8) + 12)(CTX));

	enc_rounds32(%ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
		     %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
		     %ymm15, %rax, %rcx, 8);

	fls32(%rax, %ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
	      %rcx, %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
	      %ymm15,
	      ((key_table + (16) * 8) + 0)(CTX),
	      ((key_table + (16) * 8) + 4)(CTX),
	      ((key_table + (16) * 8) + 8)(CTX),
	      ((key_table + (16) * 8) + 12)(CTX));

	enc_rounds32(%ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
		     %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
		     %ymm15, %rax, %rcx, 16);

	movl $24, %r8d;
	cmpl $16, key_length(CTX);
	jne .Lenc_max32;

.Lenc_done:
	/* load CD for output */
	vmovdqu 0 * 32(%rcx), %ymm8;
	vmovdqu 1 * 32(%rcx), %ymm9;
	vmovdqu 2 * 32(%rcx), %ymm10;
	vmovdqu 3 * 32(%rcx), %ymm11;
	vmovdqu 4 * 32(%rcx), %ymm12;
	vmovdqu 5 * 32(%rcx), %ymm13;
	vmovdqu 6 * 32(%rcx), %ymm14;
	vmovdqu 7 * 32(%rcx), %ymm15;

	outunpack32(%ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
		    %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
		    %ymm15, (key_table)(CTX, %r8, 8), (%rax), 1 * 32(%rax));

	ret;

.align 8
.Lenc_max32:
	movl $32, %r8d;

	fls32(%rax, %ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
	      %rcx, %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
	      %ymm15,
	      ((key_table + (24) * 8) + 0)(CTX),
	      ((key_table + (24) * 8) + 4)(CTX),
	      ((key_table + (24) * 8) + 8)(CTX),
	      ((key_table + (24) * 8) + 12)(CTX));

	enc_rounds32(%ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
		     %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
		     %ymm15, %rax, %rcx, 24);

	jmp .Lenc_done;

.align 8
.type   __camellia_dec_blk32,@function;

__camellia_dec_blk32:
	/* input:
	 *	%rdi: ctx, CTX
	 *	%rax: temporary storage, 512 bytes
	 *	%r8d: 24 for 16 byte key, 32 for larger
	 *	%ymm0..%ymm15: 16 encrypted blocks
	 * output:
	 *	%ymm0..%ymm15: 16 plaintext blocks, order swapped:
	 *       7, 8, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8
	 */

	leaq 8 * 32(%rax), %rcx;

	inpack32_post(%ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
		      %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
		      %ymm15, %rax, %rcx);

	cmpl $32, %r8d;
	je .Ldec_max32;

.Ldec_max24:
	dec_rounds32(%ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
		     %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
		     %ymm15, %rax, %rcx, 16);

	fls32(%rax, %ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
	      %rcx, %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
	      %ymm15,
	      ((key_table + (16) * 8) + 8)(CTX),
	      ((key_table + (16) * 8) + 12)(CTX),
	      ((key_table + (16) * 8) + 0)(CTX),
	      ((key_table + (16) * 8) + 4)(CTX));

	dec_rounds32(%ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
		     %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
		     %ymm15, %rax, %rcx, 8);

	fls32(%rax, %ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
	      %rcx, %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
	      %ymm15,
	      ((key_table + (8) * 8) + 8)(CTX),
	      ((key_table + (8) * 8) + 12)(CTX),
	      ((key_table + (8) * 8) + 0)(CTX),
	      ((key_table + (8) * 8) + 4)(CTX));

	dec_rounds32(%ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
		     %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
		     %ymm15, %rax, %rcx, 0);

	/* load CD for output */
	vmovdqu 0 * 32(%rcx), %ymm8;
	vmovdqu 1 * 32(%rcx), %ymm9;
	vmovdqu 2 * 32(%rcx), %ymm10;
	vmovdqu 3 * 32(%rcx), %ymm11;
	vmovdqu 4 * 32(%rcx), %ymm12;
	vmovdqu 5 * 32(%rcx), %ymm13;
	vmovdqu 6 * 32(%rcx), %ymm14;
	vmovdqu 7 * 32(%rcx), %ymm15;

	outunpack32(%ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
		    %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
		    %ymm15, (key_table)(CTX), (%rax), 1 * 32(%rax));

	ret;

.align 8
.Ldec_max32:
	dec_rounds32(%ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
		     %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
		     %ymm15, %rax, %rcx, 24);

	fls32(%rax, %ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
	      %rcx, %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
	      %ymm15,
	      ((key_table + (24) * 8) + 8)(CTX),
	      ((key_table + (24) * 8) + 12)(CTX),
	      ((key_table + (24) * 8) + 0)(CTX),
	      ((key_table + (24) * 8) + 4)(CTX));

	jmp .Ldec_max24;

#define inc_le128(x, minus_one, tmp) \
	vpcmpeqq minus_one, x, tmp; \
	vpsubq minus_one, x, x; \
	vpslldq $8, tmp, tmp; \
	vpsubq tmp, x, x;

.align 8
.global camellia_ctr_32way
.type   camellia_ctr_32way,@function;

camellia_ctr_32way:
	/* input:
	 *	%rdi: ctx, CTX
	 *	%rsi: dst (32 blocks)
	 *	%rdx: src (32 blocks)
	 *	%rcx: iv (little endian, 128bit)
	 *	%r8: count, number of 32*16 byte chunks
	 */

	pushq %rbp;
	movq %rsp, %rbp;

	vzeroupper;

	movq %r8, %r11;
	movq %rcx, %r9;

	subq $(16 * 32), %rsp;
	andq $~31, %rsp;
	movq %rsp, %rax;

.align 8
.Lctr_loop:
	vpcmpeqd %ymm15, %ymm15, %ymm15;
	vpsrldq $8, %ymm15, %ymm15; /* ab: -1:0 ; cd: -1:0 */

	cmpq $(0xffffffffffffffff - 32), (%r9);

	/* load IV and byteswap */
	vmovdqu (%r9), %xmm0;
	vmovdqa %xmm0, %xmm1;
	inc_le128(%xmm0, %xmm15, %xmm14);
	vbroadcasti128 .Lbswap128_mask, %ymm14;
	vinserti128 $1, %xmm0, %ymm1, %ymm0;
	vpshufb %ymm14, %ymm0, %ymm13;
	vmovdqu %ymm13, 15 * 32(%rax);

	ja .Lload_ctr_carry;

	/* construct IVs */
	vpaddq %ymm15, %ymm15, %ymm15; /* ab: -2:0 ; cd: -2:0 */
	vpsubq %ymm15, %ymm0, %ymm0;
	vpshufb %ymm14, %ymm0, %ymm13;
	vmovdqu %ymm13, 14 * 32(%rax);
	vpsubq %ymm15, %ymm0, %ymm0;
	vpshufb %ymm14, %ymm0, %ymm13;
	vmovdqu %ymm13, 13 * 32(%rax);
	vpsubq %ymm15, %ymm0, %ymm0;
	vpshufb %ymm14, %ymm0, %ymm12;
	vpsubq %ymm15, %ymm0, %ymm0;
	vpshufb %ymm14, %ymm0, %ymm11;
	vpsubq %ymm15, %ymm0, %ymm0;
	vpshufb %ymm14, %ymm0, %ymm10;
	vpsubq %ymm15, %ymm0, %ymm0;
	vpshufb %ymm14, %ymm0, %ymm9;
	vpsubq %ymm15, %ymm0, %ymm0;
	vpshufb %ymm14, %ymm0, %ymm8;
	vpsubq %ymm15, %ymm0, %ymm0;
	vpshufb %ymm14, %ymm0, %ymm7;
	vpsubq %ymm15, %ymm0, %ymm0;
	vpshufb %ymm14, %ymm0, %ymm6;
	vpsubq %ymm15, %ymm0, %ymm0;
	vpshufb %ymm14, %ymm0, %ymm5;
	vpsubq %ymm15, %ymm0, %ymm0;
	vpshufb %ymm14, %ymm0, %ymm4;
	vpsubq %ymm15, %ymm0, %ymm0;
	vpshufb %ymm14, %ymm0, %ymm3;
	vpsubq %ymm15, %ymm0, %ymm0;
	vpshufb %ymm14, %ymm0, %ymm2;
	vpsubq %ymm15, %ymm0, %ymm0;
	vpshufb %ymm14, %ymm0, %ymm1;
	vpsubq %ymm15, %ymm0, %ymm0;
	vpsubq %xmm15, %xmm0, %xmm13;
	vpshufb %ymm14, %ymm0, %ymm0;
	vmovdqu %xmm13, (%r9);

	jmp .Lload_ctr_done;

.align 4
.Lload_ctr_carry:
	/* construct IVs */
	inc_le128(%ymm0, %ymm15, %ymm13); /* ab: le1 ; cd: le2 */
	inc_le128(%ymm0, %ymm15, %ymm13); /* ab: le2 ; cd: le3 */
	vpshufb %ymm14, %ymm0, %ymm13;
	vmovdqu %ymm13, 14 * 32(%rax);
	inc_le128(%ymm0, %ymm15, %ymm13);
	inc_le128(%ymm0, %ymm15, %ymm13);
	vpshufb %ymm14, %ymm0, %ymm13;
	vmovdqu %ymm13, 13 * 32(%rax);
	inc_le128(%ymm0, %ymm15, %ymm13);
	inc_le128(%ymm0, %ymm15, %ymm13);
	vpshufb %ymm14, %ymm0, %ymm12;
	inc_le128(%ymm0, %ymm15, %ymm13);
	inc_le128(%ymm0, %ymm15, %ymm13);
	vpshufb %ymm14, %ymm0, %ymm11;
	inc_le128(%ymm0, %ymm15, %ymm13);
	inc_le128(%ymm0, %ymm15, %ymm13);
	vpshufb %ymm14, %ymm0, %ymm10;
	inc_le128(%ymm0, %ymm15, %ymm13);
	inc_le128(%ymm0, %ymm15, %ymm13);
	vpshufb %ymm14, %ymm0, %ymm9;
	inc_le128(%ymm0, %ymm15, %ymm13);
	inc_le128(%ymm0, %ymm15, %ymm13);
	vpshufb %ymm14, %ymm0, %ymm8;
	inc_le128(%ymm0, %ymm15, %ymm13);
	inc_le128(%ymm0, %ymm15, %ymm13);
	vpshufb %ymm14, %ymm0, %ymm7;
	inc_le128(%ymm0, %ymm15, %ymm13);
	inc_le128(%ymm0, %ymm15, %ymm13);
	vpshufb %ymm14, %ymm0, %ymm6;
	inc_le128(%ymm0, %ymm15, %ymm13);
	inc_le128(%ymm0, %ymm15, %ymm13);
	vpshufb %ymm14, %ymm0, %ymm5;
	inc_le128(%ymm0, %ymm15, %ymm13);
	inc_le128(%ymm0, %ymm15, %ymm13);
	vpshufb %ymm14, %ymm0, %ymm4;
	inc_le128(%ymm0, %ymm15, %ymm13);
	inc_le128(%ymm0, %ymm15, %ymm13);
	vpshufb %ymm14, %ymm0, %ymm3;
	inc_le128(%ymm0, %ymm15, %ymm13);
	inc_le128(%ymm0, %ymm15, %ymm13);
	vpshufb %ymm14, %ymm0, %ymm2;
	inc_le128(%ymm0, %ymm15, %ymm13);
	inc_le128(%ymm0, %ymm15, %ymm13);
	vpshufb %ymm14, %ymm0, %ymm1;
	inc_le128(%ymm0, %ymm15, %ymm13);
	inc_le128(%ymm0, %ymm15, %ymm13);
	vextracti128 $1, %ymm0, %xmm13;
	vpshufb %ymm14, %ymm0, %ymm0;
	inc_le128(%xmm13, %xmm15, %xmm14);
	vmovdqu %xmm13, (%r9);

.align 4
.Lload_ctr_done:
	/* inpack16_pre: */
	vpbroadcastq (key_table)(CTX), %ymm15;
	vpshufb .Lpack_bswap, %ymm15, %ymm15;
	vpxor %ymm0, %ymm15, %ymm0;
	vpxor %ymm1, %ymm15, %ymm1;
	vpxor %ymm2, %ymm15, %ymm2;
	vpxor %ymm3, %ymm15, %ymm3;
	vpxor %ymm4, %ymm15, %ymm4;
	vpxor %ymm5, %ymm15, %ymm5;
	vpxor %ymm6, %ymm15, %ymm6;
	vpxor %ymm7, %ymm15, %ymm7;
	vpxor %ymm8, %ymm15, %ymm8;
	vpxor %ymm9, %ymm15, %ymm9;
	vpxor %ymm10, %ymm15, %ymm10;
	vpxor %ymm11, %ymm15, %ymm11;
	vpxor %ymm12, %ymm15, %ymm12;
	vpxor 13 * 32(%rax), %ymm15, %ymm13;
	vpxor 14 * 32(%rax), %ymm15, %ymm14;
	vpxor 15 * 32(%rax), %ymm15, %ymm15;

	call __camellia_enc_blk32;

	cmpq $0, %rdx;
	je .Lctr_no_xor;

	vpxor 0 * 32(%rdx), %ymm7, %ymm7;
	vpxor 1 * 32(%rdx), %ymm6, %ymm6;
	vpxor 2 * 32(%rdx), %ymm5, %ymm5;
	vpxor 3 * 32(%rdx), %ymm4, %ymm4;
	vpxor 4 * 32(%rdx), %ymm3, %ymm3;
	vpxor 5 * 32(%rdx), %ymm2, %ymm2;
	vpxor 6 * 32(%rdx), %ymm1, %ymm1;
	vpxor 7 * 32(%rdx), %ymm0, %ymm0;
	vpxor 8 * 32(%rdx), %ymm15, %ymm15;
	vpxor 9 * 32(%rdx), %ymm14, %ymm14;
	vpxor 10 * 32(%rdx), %ymm13, %ymm13;
	vpxor 11 * 32(%rdx), %ymm12, %ymm12;
	vpxor 12 * 32(%rdx), %ymm11, %ymm11;
	vpxor 13 * 32(%rdx), %ymm10, %ymm10;
	vpxor 14 * 32(%rdx), %ymm9, %ymm9;
	vpxor 15 * 32(%rdx), %ymm8, %ymm8;
	leaq 32 * 16(%rdx), %rdx;
.align 4
.Lctr_no_xor:
	write_output(%ymm7, %ymm6, %ymm5, %ymm4, %ymm3, %ymm2, %ymm1, %ymm0,
		     %ymm15, %ymm14, %ymm13, %ymm12, %ymm11, %ymm10, %ymm9,
		     %ymm8, %rsi);

	decq %r11;
	leaq 32 * 16(%rsi), %rsi;
	jnz .Lctr_loop;

	vzeroupper;

	leave;
	ret;

/********* Key setup **********************************************************/

/*
 * Camellia F-function, 1-way AES-NI/AVX. Approx. ~0.5x speed of reference table
 * look-up implementation.
 *
 * IN:
 *  ab: 64-bit AB state
 *  cd: 64-bit CD state
 */
#define camellia_f(ab, x, t0, t1, t2, t3, t4, inv_shift_row, sbox4mask, \
		   _0f0f0f0fmask, pre_s1lo_mask, pre_s1hi_mask, key) \
	vmovq key, t0; \
	vpxor x, x, t3; \
	\
	vpxor ab, t0, x; \
	\
	/* \
	 * S-function with AES subbytes \
	 */ \
	\
	/* input rotation for sbox4 (<<< 1) */ \
	vpand x, sbox4mask, t0; \
	vpandn x, sbox4mask, x; \
	vpaddw t0, t0, t1; \
	vpsrlw $7, t0, t0; \
	vpor t0, t1, t0; \
	vpand sbox4mask, t0, t0; \
	vpor t0, x, x; \
	\
	vmovdqa .Lpost_tf_lo_s1, t0; \
	vmovdqa .Lpost_tf_hi_s1, t1; \
	\
	/* prefilter sboxes */ \
	filter_8bit(x, pre_s1lo_mask, pre_s1hi_mask, _0f0f0f0fmask, t2); \
	\
	/* AES subbytes + AES shift rows + AES inv shift rows */ \
	vaesenclast t3, x, x; \
	\
	/* postfilter sboxes */ \
	filter_8bit(x, t0, t1, _0f0f0f0fmask, t2); \
	\
	/* output rotation for sbox2 (<<< 1) */ \
	/* output rotation for sbox3 (>>> 1) */ \
	vpshufb inv_shift_row, x, t1; \
	vpshufb .Lsp0044440444044404mask, x, t4; \
	vpshufb .Lsp1110111010011110mask, x, x; \
	vpaddb t1, t1, t2; \
	vpsrlw $7, t1, t0; \
	vpsllw $7, t1, t3; \
	vpor t0, t2, t0; \
	vpsrlw $1, t1, t1; \
	vpshufb .Lsp0222022222000222mask, t0, t0; \
	vpor t1, t3, t1; \
	\
	vpxor x, t4, t4; \
	vpshufb .Lsp3033303303303033mask, t1, t1; \
	vpxor t4, t0, t0; \
	vpxor t1, t0, t0; \
	vpsrldq $8, t0, x; \
	vpxor t0, x, x;

#define vec_rol128(in, out, nrol, t0) \
	vpshufd $0x4e, in, out; \
	vpsllq $(nrol), in, t0; \
	vpsrlq $(64-(nrol)), out, out; \
	vpaddd t0, out, out;

#define vec_ror128(in, out, nror, t0) \
	vpshufd $0x4e, in, out; \
	vpsrlq $(nror), in, t0; \
	vpsllq $(64-(nror)), out, out; \
	vpaddd t0, out, out;

.data

.align 16
.Linv_shift_row_and_unpcklbw:
	.byte 0x00, 0xff, 0x0d, 0xff, 0x0a, 0xff, 0x07, 0xff
	.byte 0x04, 0xff, 0x01, 0xff, 0x0e, 0xff, 0x0b, 0xff
.Lsp0044440444044404mask:
	.long 0xffff0404, 0x0404ff04;
	.long 0x0d0dff0d, 0x0d0dff0d;
.Lsp1110111010011110mask:
	.long 0x000000ff, 0x000000ff;
	.long 0x0bffff0b, 0x0b0b0bff;
.Lsp0222022222000222mask:
	.long 0xff060606, 0xff060606;
	.long 0x0c0cffff, 0xff0c0c0c;
.Lsp3033303303303033mask:
	.long 0x04ff0404, 0x04ff0404;
	.long 0xff0a0aff, 0x0aff0a0a;
.Lsbox4_input_mask:
	.byte 0x00, 0xff, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00;
.Lsigma1:
	.long 0x3BCC908B, 0xA09E667F;
.Lsigma2:
	.long 0x4CAA73B2, 0xB67AE858;
.Lsigma3:
	.long 0xE94F82BE, 0xC6EF372F;
.Lsigma4:
	.long 0xF1D36F1C, 0x54FF53A5;
.Lsigma5:
	.long 0xDE682D1D, 0x10E527FA;
.Lsigma6:
	.long 0xB3E6C1FD, 0xB05688C2;

.text

.align 8
.type  camellia_setup128,@function;
.globl camellia_setup128
camellia_setup128:
	/* input:
	 *	%rdi: subkey storage
	 *	%rsi: key
	 */
#define cmll_sub(n, subkeys) (((n)*8))(subkeys)
#define KL128 %xmm0
#define KA128 %xmm2
	vzeroupper;

	vmovdqu (%rsi), %xmm0;

	vpshufb .Lbswap128_mask, KL128, KL128;

	vmovdqa .Linv_shift_row_and_unpcklbw, %xmm11;
	vmovq .Lsbox4_input_mask, %xmm12;
	vbroadcastss .L0f0f0f0f, %xmm13;
	vmovdqa .Lpre_tf_lo_s1, %xmm14;
	vmovdqa .Lpre_tf_hi_s1, %xmm15;

	/*
	 * Generate KA
	 */
	vpsrldq $8, KL128, %xmm2;
	vmovdqa KL128, %xmm3;
	vpslldq $8, %xmm3, %xmm3;
	vpsrldq $8, %xmm3, %xmm3;

	camellia_f(%xmm2, %xmm4, %xmm1,
		   %xmm5, %xmm6, %xmm7, %xmm8,
		   %xmm11, %xmm12, %xmm13, %xmm14, %xmm15, .Lsigma1);
	vpxor %xmm4, %xmm3, %xmm3;
	camellia_f(%xmm3, %xmm2, %xmm1,
		   %xmm5, %xmm6, %xmm7, %xmm8,
		   %xmm11, %xmm12, %xmm13, %xmm14, %xmm15, .Lsigma2);
	camellia_f(%xmm2, %xmm3, %xmm1,
		   %xmm5, %xmm6, %xmm7, %xmm8,
		   %xmm11, %xmm12, %xmm13, %xmm14, %xmm15, .Lsigma3);
	vpxor %xmm4, %xmm3, %xmm3;
	camellia_f(%xmm3, %xmm4, %xmm1,
		   %xmm5, %xmm6, %xmm7, %xmm8,
		   %xmm11, %xmm12, %xmm13, %xmm14, %xmm15, .Lsigma4);

	vpslldq $8, %xmm3, %xmm3;
	vpxor %xmm4, %xmm2, %xmm2;
	vpsrldq $8, %xmm3, %xmm3;
	vpslldq $8, %xmm2, KA128;
	vpor %xmm3, KA128, KA128;

        /*
         * Generate subkeys
         */
	vmovdqu KA128, cmll_sub(24, CTX);
	vec_rol128(KL128, %xmm3, 15, %xmm15);
	vec_rol128(KA128, %xmm4, 15, %xmm15);
	vec_rol128(KA128, %xmm5, 30, %xmm15);
	vec_rol128(KL128, %xmm6, 45, %xmm15);
	vec_rol128(KA128, %xmm7, 45, %xmm15);
	vec_rol128(KL128, %xmm8, 60, %xmm15);
	vec_rol128(KA128, %xmm9, 60, %xmm15);
	vec_ror128(KL128, %xmm10, 128-77, %xmm15);

	/* absorb kw2 to other subkeys */
	vpslldq $8, KL128, %xmm15;
	vpsrldq $8, %xmm15, %xmm15;
	vpxor %xmm15, KA128, KA128;
	vpxor %xmm15, %xmm3, %xmm3;
	vpxor %xmm15, %xmm4, %xmm4;

	/* subl(1) ^= subr(1) & ~subr(9); */
	vpandn %xmm15, %xmm5, %xmm13;
	vpslldq $12, %xmm13, %xmm13;
	vpsrldq $8, %xmm13, %xmm13;
	vpxor %xmm13, %xmm15, %xmm15;
	/* dw = subl(1) & subl(9), subr(1) ^= CAMELLIA_RL1(dw); */
	vpand %xmm15, %xmm5, %xmm14;
	vpslld $1, %xmm14, %xmm11;
	vpsrld $31, %xmm14, %xmm14;
	vpaddd %xmm11, %xmm14, %xmm14;
	vpslldq $8, %xmm14, %xmm14;
	vpsrldq $12, %xmm14, %xmm14;
	vpxor %xmm14, %xmm15, %xmm15;

	vpxor %xmm15, %xmm6, %xmm6;
	vpxor %xmm15, %xmm8, %xmm8;
	vpxor %xmm15, %xmm9, %xmm9;

	/* subl(1) ^= subr(1) & ~subr(17); */
	vpandn %xmm15, %xmm10, %xmm13;
	vpslldq $12, %xmm13, %xmm13;
	vpsrldq $8, %xmm13, %xmm13;
	vpxor %xmm13, %xmm15, %xmm15;
	/* dw = subl(1) & subl(17), subr(1) ^= CAMELLIA_RL1(dw); */
	vpand %xmm15, %xmm10, %xmm14;
	vpslld $1, %xmm14, %xmm11;
	vpsrld $31, %xmm14, %xmm14;
	vpaddd %xmm11, %xmm14, %xmm14;
	vpslldq $8, %xmm14, %xmm14;
	vpsrldq $12, %xmm14, %xmm14;
	vpxor %xmm14, %xmm15, %xmm15;

	vpshufd $0x1b, KL128, KL128;
	vpshufd $0x1b, KA128, KA128;
	vpshufd $0x1b, %xmm3, %xmm3;
	vpshufd $0x1b, %xmm4, %xmm4;
	vpshufd $0x1b, %xmm5, %xmm5;
	vpshufd $0x1b, %xmm6, %xmm6;
	vpshufd $0x1b, %xmm7, %xmm7;
	vpshufd $0x1b, %xmm8, %xmm8;
	vpshufd $0x1b, %xmm9, %xmm9;
	vpshufd $0x1b, %xmm10, %xmm10;

	vmovdqu KL128, cmll_sub(0, CTX);
	vpshufd $0x1b, KL128, KL128;
	vmovdqu KA128, cmll_sub(2, CTX);
	vmovdqu %xmm3, cmll_sub(4, CTX);
	vmovdqu %xmm4, cmll_sub(6, CTX);
	vmovdqu %xmm5, cmll_sub(8, CTX);
	vmovdqu %xmm6, cmll_sub(10, CTX);
	vpsrldq $8, %xmm8, %xmm8;
	vmovq %xmm7, cmll_sub(12, CTX);
	vmovq %xmm8, cmll_sub(13, CTX);
	vmovdqu %xmm9, cmll_sub(14, CTX);
	vmovdqu %xmm10, cmll_sub(16, CTX);

	vmovdqu cmll_sub(24, CTX), KA128;

	vec_ror128(KL128, %xmm3, 128 - 94, %xmm7);
	vec_ror128(KA128, %xmm4, 128 - 94, %xmm7);
	vec_ror128(KL128, %xmm5, 128 - 111, %xmm7);
	vec_ror128(KA128, %xmm6, 128 - 111, %xmm7);

	vpxor %xmm15, %xmm3, %xmm3;
	vpxor %xmm15, %xmm4, %xmm4;
	vpxor %xmm15, %xmm5, %xmm5;
	vpslldq $8, %xmm15, %xmm15;
	vpxor %xmm15, %xmm6, %xmm6;

	/* absorb kw4 to other subkeys */
	vpslldq $8, %xmm6, %xmm15;
	vpxor %xmm15, %xmm5, %xmm5;
	vpxor %xmm15, %xmm4, %xmm4;
	vpxor %xmm15, %xmm3, %xmm3;

	/* subl(25) ^= subr(25) & ~subr(16); */
	vpshufd $0x1b, cmll_sub(16, CTX), %xmm10;
	vpandn %xmm15, %xmm10, %xmm13;
	vpslldq $4, %xmm13, %xmm13;
	vpxor %xmm13, %xmm15, %xmm15;
	/* dw = subl(25) & subl(16), subr(25) ^= CAMELLIA_RL1(dw); */
	vpand %xmm15, %xmm10, %xmm14;
	vpslld $1, %xmm14, %xmm11;
	vpsrld $31, %xmm14, %xmm14;
	vpaddd %xmm11, %xmm14, %xmm14;
	vpsrldq $12, %xmm14, %xmm14;
	vpslldq $8, %xmm14, %xmm14;
	vpxor %xmm14, %xmm15, %xmm15;

	vpshufd $0x1b, %xmm3, %xmm3;
	vpshufd $0x1b, %xmm4, %xmm4;
	vpshufd $0x1b, %xmm5, %xmm5;
	vpshufd $0x1b, %xmm6, %xmm6;

	vmovdqu %xmm3, cmll_sub(18, CTX);
	vmovdqu %xmm4, cmll_sub(20, CTX);
	vmovdqu %xmm5, cmll_sub(22, CTX);
	vmovdqu %xmm6, cmll_sub(24, CTX);

	vpshufd $0x1b, cmll_sub(14, CTX), %xmm3;
	vpshufd $0x1b, cmll_sub(12, CTX), %xmm4;
	vpshufd $0x1b, cmll_sub(10, CTX), %xmm5;
	vpshufd $0x1b, cmll_sub(8, CTX), %xmm6;

	vpxor %xmm15, %xmm3, %xmm3;
	vpxor %xmm15, %xmm4, %xmm4;
	vpxor %xmm15, %xmm5, %xmm5;

	/* subl(25) ^= subr(25) & ~subr(8); */
	vpandn %xmm15, %xmm6, %xmm13;
	vpslldq $4, %xmm13, %xmm13;
	vpxor %xmm13, %xmm15, %xmm15;
	/* dw = subl(25) & subl(8), subr(25) ^= CAMELLIA_RL1(dw); */
	vpand %xmm15, %xmm6, %xmm14;
	vpslld $1, %xmm14, %xmm11;
	vpsrld $31, %xmm14, %xmm14;
	vpaddd %xmm11, %xmm14, %xmm14;
	vpsrldq $12, %xmm14, %xmm14;
	vpslldq $8, %xmm14, %xmm14;
	vpxor %xmm14, %xmm15, %xmm15;

	vpshufd $0x1b, %xmm3, %xmm3;
	vpshufd $0x1b, %xmm4, %xmm4;
	vpshufd $0x1b, %xmm5, %xmm5;

	vmovdqu %xmm3, cmll_sub(14, CTX);
	vmovdqu %xmm4, cmll_sub(12, CTX);
	vmovdqu %xmm5, cmll_sub(10, CTX);

	vpshufd $0x1b, cmll_sub(6, CTX), %xmm6;
	vpshufd $0x1b, cmll_sub(4, CTX), %xmm4;
	vpshufd $0x1b, cmll_sub(2, CTX), %xmm2;
	vpshufd $0x1b, cmll_sub(0, CTX), %xmm0;

	vpxor %xmm15, %xmm6, %xmm6;
	vpxor %xmm15, %xmm4, %xmm4;
	vpxor %xmm15, %xmm2, %xmm2;
	vpxor %xmm15, %xmm0, %xmm0;

	vpshufd $0x1b, %xmm6, %xmm6;
	vpshufd $0x1b, %xmm4, %xmm4;
	vpshufd $0x1b, %xmm2, %xmm2;
	vpshufd $0x1b, %xmm0, %xmm0;

	vpsrldq $8, %xmm2, %xmm3;
	vpsrldq $8, %xmm4, %xmm5;
	vpsrldq $8, %xmm6, %xmm7;

        /*
	 * key XOR is end of F-function.
	 */
	vpxor %xmm2, %xmm0, %xmm0;
	vpxor %xmm4, %xmm2, %xmm2;

	vmovq %xmm0, cmll_sub(0, CTX);
	vmovq %xmm3, cmll_sub(2, CTX);
	vpxor %xmm5, %xmm3, %xmm3;
	vpxor %xmm6, %xmm4, %xmm4;
	vpxor %xmm7, %xmm5, %xmm5;
	vmovq %xmm2, cmll_sub(3, CTX);
	vmovq %xmm3, cmll_sub(4, CTX);
	vmovq %xmm4, cmll_sub(5, CTX);
	vmovq %xmm5, cmll_sub(6, CTX);

	vmovq cmll_sub(7, CTX), %xmm7;
	vmovq cmll_sub(8, CTX), %xmm8;
	vmovq cmll_sub(9, CTX), %xmm9;
	vmovq cmll_sub(10, CTX), %xmm10;
	/* tl = subl(10) ^ (subr(10) & ~subr(8)); */
	vpandn %xmm10, %xmm8, %xmm15;
	vpsrldq $4, %xmm15, %xmm15;
	vpxor %xmm15, %xmm10, %xmm0;
	/* dw = tl & subl(8), tr = subr(10) ^ CAMELLIA_RL1(dw); */
	vpand %xmm8, %xmm0, %xmm15;
	vpslld $1, %xmm15, %xmm14;
	vpsrld $31, %xmm15, %xmm15;
	vpaddd %xmm14, %xmm15, %xmm15;
	vpslldq $12, %xmm15, %xmm15;
	vpsrldq $8, %xmm15, %xmm15;
	vpxor %xmm15, %xmm0, %xmm0;

	vpxor %xmm0, %xmm6, %xmm6;
	vmovq %xmm6, cmll_sub(7, CTX);

	vmovq cmll_sub(11, CTX), %xmm11;
	vmovq cmll_sub(12, CTX), %xmm12;
	vmovq cmll_sub(13, CTX), %xmm13;
	vmovq cmll_sub(14, CTX), %xmm14;
	vmovq cmll_sub(15, CTX), %xmm15;
	/* tl = subl(7) ^ (subr(7) & ~subr(9)); */
	vpandn %xmm7, %xmm9, %xmm1;
	vpsrldq $4, %xmm1, %xmm1;
	vpxor %xmm1, %xmm7, %xmm0;
	/* dw = tl & subl(9), tr = subr(7) ^ CAMELLIA_RL1(dw); */
	vpand %xmm9, %xmm0, %xmm1;
	vpslld $1, %xmm1, %xmm2;
	vpsrld $31, %xmm1, %xmm1;
	vpaddd %xmm2, %xmm1, %xmm1;
	vpslldq $12, %xmm1, %xmm1;
	vpsrldq $8, %xmm1, %xmm1;
	vpxor %xmm1, %xmm0, %xmm0;

	vpxor %xmm11, %xmm0, %xmm0;
	vpxor %xmm12, %xmm10, %xmm10;
	vpxor %xmm13, %xmm11, %xmm11;
	vpxor %xmm14, %xmm12, %xmm12;
	vpxor %xmm15, %xmm13, %xmm13;
	vmovq %xmm0, cmll_sub(10, CTX);
	vmovq %xmm10, cmll_sub(11, CTX);
	vmovq %xmm11, cmll_sub(12, CTX);
	vmovq %xmm12, cmll_sub(13, CTX);
	vmovq %xmm13, cmll_sub(14, CTX);

	vmovq cmll_sub(16, CTX), %xmm6;
	vmovq cmll_sub(17, CTX), %xmm7;
	vmovq cmll_sub(18, CTX), %xmm8;
	vmovq cmll_sub(19, CTX), %xmm9;
	vmovq cmll_sub(20, CTX), %xmm10;
	/* tl = subl(18) ^ (subr(18) & ~subr(16)); */
	vpandn %xmm8, %xmm6, %xmm1;
	vpsrldq $4, %xmm1, %xmm1;
	vpxor %xmm1, %xmm8, %xmm0;
	/* dw = tl & subl(16), tr = subr(18) ^ CAMELLIA_RL1(dw); */
	vpand %xmm6, %xmm0, %xmm1;
	vpslld $1, %xmm1, %xmm2;
	vpsrld $31, %xmm1, %xmm1;
	vpaddd %xmm2, %xmm1, %xmm1;
	vpslldq $12, %xmm1, %xmm1;
	vpsrldq $8, %xmm1, %xmm1;
	vpxor %xmm1, %xmm0, %xmm0;

	vpxor %xmm14, %xmm0, %xmm0;
	vmovq %xmm0, cmll_sub(15, CTX);

	/* tl = subl(15) ^ (subr(15) & ~subr(17)); */
	vpandn %xmm15, %xmm7, %xmm1;
	vpsrldq $4, %xmm1, %xmm1;
	vpxor %xmm1, %xmm15, %xmm0;
	/* dw = tl & subl(17), tr = subr(15) ^ CAMELLIA_RL1(dw); */
	vpand %xmm7, %xmm0, %xmm1;
	vpslld $1, %xmm1, %xmm2;
	vpsrld $31, %xmm1, %xmm1;
	vpaddd %xmm2, %xmm1, %xmm1;
	vpslldq $12, %xmm1, %xmm1;
	vpsrldq $8, %xmm1, %xmm1;
	vpxor %xmm1, %xmm0, %xmm0;

	vmovq cmll_sub(21, CTX), %xmm1;
	vmovq cmll_sub(22, CTX), %xmm2;
	vmovq cmll_sub(23, CTX), %xmm3;
	vmovq cmll_sub(24, CTX), %xmm4;

	vpxor %xmm9, %xmm0, %xmm0;
	vpxor %xmm10, %xmm8, %xmm8;
	vpxor %xmm1, %xmm9, %xmm9;
	vpxor %xmm2, %xmm10, %xmm10;
	vpxor %xmm3, %xmm1, %xmm1;
	vpxor %xmm4, %xmm3, %xmm3;

	vmovq %xmm0, cmll_sub(18, CTX);
	vmovq %xmm8, cmll_sub(19, CTX);
	vmovq %xmm9, cmll_sub(20, CTX);
	vmovq %xmm10, cmll_sub(21, CTX);
	vmovq %xmm1, cmll_sub(22, CTX);
	vmovq %xmm2, cmll_sub(23, CTX);
	vmovq %xmm3, cmll_sub(24, CTX);

	/* kw2 and kw4 are unused now. */
	movq $0, cmll_sub(1, CTX);
	movq $0, cmll_sub(25, CTX);

	vzeroupper;

	ret;


.align 8
.type  camellia_setup256,@function;
.globl camellia_setup256
camellia_setup256:
	/* input:
	 *	%rdi: subkey storage
	 *	%rsi: key
	 */
#define KL128 %xmm0
#define KR128 %xmm1
#define KA128 %xmm2
#define KB128 %xmm3
	vzeroupper;

	vmovdqu (%rsi), %xmm0;
	vmovdqu 16(%rsi), %xmm1;

	vpshufb .Lbswap128_mask, KL128, KL128;
	vpshufb .Lbswap128_mask, KR128, KR128;

	vmovdqa .Linv_shift_row_and_unpcklbw, %xmm11;
	vmovq .Lsbox4_input_mask, %xmm12;
	vbroadcastss .L0f0f0f0f, %xmm13;
	vmovdqa .Lpre_tf_lo_s1, %xmm14;
	vmovdqa .Lpre_tf_hi_s1, %xmm15;

	/*
	 * Generate KA
	 */
	vpxor KL128, KR128, %xmm3;
	vpsrldq $8, KR128, %xmm6;
	vpsrldq $8, %xmm3, %xmm2;
	vpslldq $8, %xmm3, %xmm3;
	vpsrldq $8, %xmm3, %xmm3;

	camellia_f(%xmm2, %xmm4, %xmm5,
		   %xmm7, %xmm8, %xmm9, %xmm10,
		   %xmm11, %xmm12, %xmm13, %xmm14, %xmm15, .Lsigma1);
	vpxor %xmm4, %xmm3, %xmm3;
	camellia_f(%xmm3, %xmm2, %xmm5,
		   %xmm7, %xmm8, %xmm9, %xmm10,
		   %xmm11, %xmm12, %xmm13, %xmm14, %xmm15, .Lsigma2);
	vpxor %xmm6, %xmm2, %xmm2;
	camellia_f(%xmm2, %xmm3, %xmm5,
		   %xmm7, %xmm8, %xmm9, %xmm10,
		   %xmm11, %xmm12, %xmm13, %xmm14, %xmm15, .Lsigma3);
	vpxor %xmm4, %xmm3, %xmm3;
	vpxor KR128, %xmm3, %xmm3;
	camellia_f(%xmm3, %xmm4, %xmm5,
		   %xmm7, %xmm8, %xmm9, %xmm10,
		   %xmm11, %xmm12, %xmm13, %xmm14, %xmm15, .Lsigma4);

	vpslldq $8, %xmm3, %xmm3;
	vpxor %xmm4, %xmm2, %xmm2;
	vpsrldq $8, %xmm3, %xmm3;
	vpslldq $8, %xmm2, KA128;
	vpor %xmm3, KA128, KA128;

	/*
	 * Generate KB
	 */
	vpxor KA128, KR128, %xmm3;
	vpsrldq $8, %xmm3, %xmm4;
	vpslldq $8, %xmm3, %xmm3;
	vpsrldq $8, %xmm3, %xmm3;

	camellia_f(%xmm4, %xmm5, %xmm6,
		   %xmm7, %xmm8, %xmm9, %xmm10,
		   %xmm11, %xmm12, %xmm13, %xmm14, %xmm15, .Lsigma5);
	vpxor %xmm5, %xmm3, %xmm3;

	camellia_f(%xmm3, %xmm5, %xmm6,
		   %xmm7, %xmm8, %xmm9, %xmm10,
		   %xmm11, %xmm12, %xmm13, %xmm14, %xmm15, .Lsigma6);
	vpslldq $8, %xmm3, %xmm3;
	vpxor %xmm5, %xmm4, %xmm4;
	vpsrldq $8, %xmm3, %xmm3;
	vpslldq $8, %xmm4, %xmm4;
	vpor %xmm3, %xmm4, KB128;

        /*
         * Generate subkeys
         */
	vmovdqu KB128, cmll_sub(32, CTX);
	vec_rol128(KR128, %xmm4, 15, %xmm15);
	vec_rol128(KA128, %xmm5, 15, %xmm15);
	vec_rol128(KR128, %xmm6, 30, %xmm15);
	vec_rol128(KB128, %xmm7, 30, %xmm15);
	vec_rol128(KL128, %xmm8, 45, %xmm15);
	vec_rol128(KA128, %xmm9, 45, %xmm15);
	vec_rol128(KL128, %xmm10, 60, %xmm15);
	vec_rol128(KR128, %xmm11, 60, %xmm15);
	vec_rol128(KB128, %xmm12, 60, %xmm15);

	/* absorb kw2 to other subkeys */
	vpslldq $8, KL128, %xmm15;
	vpsrldq $8, %xmm15, %xmm15;
	vpxor %xmm15, KB128, KB128;
	vpxor %xmm15, %xmm4, %xmm4;
	vpxor %xmm15, %xmm5, %xmm5;

	/* subl(1) ^= subr(1) & ~subr(9); */
	vpandn %xmm15, %xmm6, %xmm13;
	vpslldq $12, %xmm13, %xmm13;
	vpsrldq $8, %xmm13, %xmm13;
	vpxor %xmm13, %xmm15, %xmm15;
	/* dw = subl(1) & subl(9), subr(1) ^= CAMELLIA_RL1(dw); */
	vpand %xmm15, %xmm6, %xmm14;
	vpslld $1, %xmm14, %xmm13;
	vpsrld $31, %xmm14, %xmm14;
	vpaddd %xmm13, %xmm14, %xmm14;
	vpslldq $8, %xmm14, %xmm14;
	vpsrldq $12, %xmm14, %xmm14;
	vpxor %xmm14, %xmm15, %xmm15;

	vpxor %xmm15, %xmm7, %xmm7;
	vpxor %xmm15, %xmm8, %xmm8;
	vpxor %xmm15, %xmm9, %xmm9;

	vpshufd $0x1b, KL128, KL128;
	vpshufd $0x1b, KB128, KB128;
	vpshufd $0x1b, %xmm4, %xmm4;
	vpshufd $0x1b, %xmm5, %xmm5;
	vpshufd $0x1b, %xmm6, %xmm6;
	vpshufd $0x1b, %xmm7, %xmm7;
	vpshufd $0x1b, %xmm8, %xmm8;
	vpshufd $0x1b, %xmm9, %xmm9;

	vmovdqu KL128, cmll_sub(0, CTX);
	vpshufd $0x1b, KL128, KL128;
	vmovdqu KB128, cmll_sub(2, CTX);
	vmovdqu %xmm4, cmll_sub(4, CTX);
	vmovdqu %xmm5, cmll_sub(6, CTX);
	vmovdqu %xmm6, cmll_sub(8, CTX);
	vmovdqu %xmm7, cmll_sub(10, CTX);
	vmovdqu %xmm8, cmll_sub(12, CTX);
	vmovdqu %xmm9, cmll_sub(14, CTX);

	vmovdqu cmll_sub(32, CTX), KB128;

	/* subl(1) ^= subr(1) & ~subr(17); */
	vpandn %xmm15, %xmm10, %xmm13;
	vpslldq $12, %xmm13, %xmm13;
	vpsrldq $8, %xmm13, %xmm13;
	vpxor %xmm13, %xmm15, %xmm15;
	/* dw = subl(1) & subl(17), subr(1) ^= CAMELLIA_RL1(dw); */
	vpand %xmm15, %xmm10, %xmm14;
	vpslld $1, %xmm14, %xmm13;
	vpsrld $31, %xmm14, %xmm14;
	vpaddd %xmm13, %xmm14, %xmm14;
	vpslldq $8, %xmm14, %xmm14;
	vpsrldq $12, %xmm14, %xmm14;
	vpxor %xmm14, %xmm15, %xmm15;

	vpxor %xmm15, %xmm11, %xmm11;
	vpxor %xmm15, %xmm12, %xmm12;

	vec_ror128(KL128, %xmm4, 128-77, %xmm14);
	vec_ror128(KA128, %xmm5, 128-77, %xmm14);
	vec_ror128(KR128, %xmm6, 128-94, %xmm14);
	vec_ror128(KA128, %xmm7, 128-94, %xmm14);
	vec_ror128(KL128, %xmm8, 128-111, %xmm14);
	vec_ror128(KB128, %xmm9, 128-111, %xmm14);

	vpxor %xmm15, %xmm4, %xmm4;

	vpshufd $0x1b, %xmm10, %xmm10;
	vpshufd $0x1b, %xmm11, %xmm11;
	vpshufd $0x1b, %xmm12, %xmm12;
	vpshufd $0x1b, %xmm4, %xmm4;

	vmovdqu %xmm10, cmll_sub(16, CTX);
	vmovdqu %xmm11, cmll_sub(18, CTX);
	vmovdqu %xmm12, cmll_sub(20, CTX);
	vmovdqu %xmm4, cmll_sub(22, CTX);

	/* subl(1) ^= subr(1) & ~subr(25); */
	vpandn %xmm15, %xmm5, %xmm13;
	vpslldq $12, %xmm13, %xmm13;
	vpsrldq $8, %xmm13, %xmm13;
	vpxor %xmm13, %xmm15, %xmm15;
	/* dw = subl(1) & subl(25), subr(1) ^= CAMELLIA_RL1(dw); */
	vpand %xmm15, %xmm5, %xmm14;
	vpslld $1, %xmm14, %xmm13;
	vpsrld $31, %xmm14, %xmm14;
	vpaddd %xmm13, %xmm14, %xmm14;
	vpslldq $8, %xmm14, %xmm14;
	vpsrldq $12, %xmm14, %xmm14;
	vpxor %xmm14, %xmm15, %xmm15;

	vpxor %xmm15, %xmm6, %xmm6;
	vpxor %xmm15, %xmm7, %xmm7;
	vpxor %xmm15, %xmm8, %xmm8;
	vpslldq $8, %xmm15, %xmm15;
	vpxor %xmm15, %xmm9, %xmm9;

	/* absorb kw4 to other subkeys */
	vpslldq $8, %xmm9, %xmm15;
	vpxor %xmm15, %xmm8, %xmm8;
	vpxor %xmm15, %xmm7, %xmm7;
	vpxor %xmm15, %xmm6, %xmm6;

	/* subl(33) ^= subr(33) & ~subr(24); */
	vpandn %xmm15, %xmm5, %xmm14;
	vpslldq $4, %xmm14, %xmm14;
	vpxor %xmm14, %xmm15, %xmm15;
	/* dw = subl(33) & subl(24), subr(33) ^= CAMELLIA_RL1(dw); */
	vpand %xmm15, %xmm5, %xmm14;
	vpslld $1, %xmm14, %xmm13;
	vpsrld $31, %xmm14, %xmm14;
	vpaddd %xmm13, %xmm14, %xmm14;
	vpsrldq $12, %xmm14, %xmm14;
	vpslldq $8, %xmm14, %xmm14;
	vpxor %xmm14, %xmm15, %xmm15;

	vpshufd $0x1b, %xmm5, %xmm5;
	vpshufd $0x1b, %xmm6, %xmm6;
	vpshufd $0x1b, %xmm7, %xmm7;
	vpshufd $0x1b, %xmm8, %xmm8;
	vpshufd $0x1b, %xmm9, %xmm9;

	vmovdqu %xmm5, cmll_sub(24, CTX);
	vmovdqu %xmm6, cmll_sub(26, CTX);
	vmovdqu %xmm7, cmll_sub(28, CTX);
	vmovdqu %xmm8, cmll_sub(30, CTX);
	vmovdqu %xmm9, cmll_sub(32, CTX);

	vpshufd $0x1b, cmll_sub(22, CTX), %xmm0;
	vpshufd $0x1b, cmll_sub(20, CTX), %xmm1;
	vpshufd $0x1b, cmll_sub(18, CTX), %xmm2;
	vpshufd $0x1b, cmll_sub(16, CTX), %xmm3;
	vpshufd $0x1b, cmll_sub(14, CTX), %xmm4;
	vpshufd $0x1b, cmll_sub(12, CTX), %xmm5;
	vpshufd $0x1b, cmll_sub(10, CTX), %xmm6;
	vpshufd $0x1b, cmll_sub(8, CTX), %xmm7;

	vpxor %xmm15, %xmm0, %xmm0;
	vpxor %xmm15, %xmm1, %xmm1;
	vpxor %xmm15, %xmm2, %xmm2;

	/* subl(33) ^= subr(33) & ~subr(24); */
	vpandn %xmm15, %xmm3, %xmm14;
	vpslldq $4, %xmm14, %xmm14;
	vpxor %xmm14, %xmm15, %xmm15;
	/* dw = subl(33) & subl(24), subr(33) ^= CAMELLIA_RL1(dw); */
	vpand %xmm15, %xmm3, %xmm14;
	vpslld $1, %xmm14, %xmm13;
	vpsrld $31, %xmm14, %xmm14;
	vpaddd %xmm13, %xmm14, %xmm14;
	vpsrldq $12, %xmm14, %xmm14;
	vpslldq $8, %xmm14, %xmm14;
	vpxor %xmm14, %xmm15, %xmm15;

	vpxor %xmm15, %xmm4, %xmm4;
	vpxor %xmm15, %xmm5, %xmm5;
	vpxor %xmm15, %xmm6, %xmm6;

	vpshufd $0x1b, %xmm0, %xmm0;
	vpshufd $0x1b, %xmm1, %xmm1;
	vpshufd $0x1b, %xmm2, %xmm2;
	vpshufd $0x1b, %xmm4, %xmm4;
	vpshufd $0x1b, %xmm5, %xmm5;
	vpshufd $0x1b, %xmm6, %xmm6;

	vmovdqu %xmm0, cmll_sub(22, CTX);
	vmovdqu %xmm1, cmll_sub(20, CTX);
	vmovdqu %xmm2, cmll_sub(18, CTX);
	vmovdqu %xmm4, cmll_sub(14, CTX);
	vmovdqu %xmm5, cmll_sub(12, CTX);
	vmovdqu %xmm6, cmll_sub(10, CTX);

	vpshufd $0x1b, cmll_sub(6, CTX), %xmm6;
	vpshufd $0x1b, cmll_sub(4, CTX), %xmm4;
	vpshufd $0x1b, cmll_sub(2, CTX), %xmm2;
	vpshufd $0x1b, cmll_sub(0, CTX), %xmm0;

	/* subl(33) ^= subr(33) & ~subr(24); */
	vpandn %xmm15, %xmm7, %xmm14;
	vpslldq $4, %xmm14, %xmm14;
	vpxor %xmm14, %xmm15, %xmm15;
	/* dw = subl(33) & subl(24), subr(33) ^= CAMELLIA_RL1(dw); */
	vpand %xmm15, %xmm7, %xmm14;
	vpslld $1, %xmm14, %xmm13;
	vpsrld $31, %xmm14, %xmm14;
	vpaddd %xmm13, %xmm14, %xmm14;
	vpsrldq $12, %xmm14, %xmm14;
	vpslldq $8, %xmm14, %xmm14;
	vpxor %xmm14, %xmm15, %xmm15;

	vpxor %xmm15, %xmm6, %xmm6;
	vpxor %xmm15, %xmm4, %xmm4;
	vpxor %xmm15, %xmm2, %xmm2;
	vpxor %xmm15, %xmm0, %xmm0;

	vpshufd $0x1b, %xmm6, %xmm6;
	vpshufd $0x1b, %xmm4, %xmm4;
	vpshufd $0x1b, %xmm2, %xmm2;
	vpshufd $0x1b, %xmm0, %xmm0;

	vpsrldq $8, %xmm2, %xmm3;
	vpsrldq $8, %xmm4, %xmm5;
	vpsrldq $8, %xmm6, %xmm7;

        /*
	 * key XOR is end of F-function.
	 */
	vpxor %xmm2, %xmm0, %xmm0;
	vpxor %xmm4, %xmm2, %xmm2;

	vmovq %xmm0, cmll_sub(0, CTX);
	vmovq %xmm3, cmll_sub(2, CTX);
	vpxor %xmm5, %xmm3, %xmm3;
	vpxor %xmm6, %xmm4, %xmm4;
	vpxor %xmm7, %xmm5, %xmm5;
	vmovq %xmm2, cmll_sub(3, CTX);
	vmovq %xmm3, cmll_sub(4, CTX);
	vmovq %xmm4, cmll_sub(5, CTX);
	vmovq %xmm5, cmll_sub(6, CTX);

	vmovq cmll_sub(7, CTX), %xmm7;
	vmovq cmll_sub(8, CTX), %xmm8;
	vmovq cmll_sub(9, CTX), %xmm9;
	vmovq cmll_sub(10, CTX), %xmm10;
	/* tl = subl(10) ^ (subr(10) & ~subr(8)); */
	vpandn %xmm10, %xmm8, %xmm15;
	vpsrldq $4, %xmm15, %xmm15;
	vpxor %xmm15, %xmm10, %xmm0;
	/* dw = tl & subl(8), tr = subr(10) ^ CAMELLIA_RL1(dw); */
	vpand %xmm8, %xmm0, %xmm15;
	vpslld $1, %xmm15, %xmm14;
	vpsrld $31, %xmm15, %xmm15;
	vpaddd %xmm14, %xmm15, %xmm15;
	vpslldq $12, %xmm15, %xmm15;
	vpsrldq $8, %xmm15, %xmm15;
	vpxor %xmm15, %xmm0, %xmm0;

	vpxor %xmm0, %xmm6, %xmm6;
	vmovq %xmm6, cmll_sub(7, CTX);

	vmovq cmll_sub(11, CTX), %xmm11;
	vmovq cmll_sub(12, CTX), %xmm12;
	vmovq cmll_sub(13, CTX), %xmm13;
	vmovq cmll_sub(14, CTX), %xmm14;
	vmovq cmll_sub(15, CTX), %xmm15;
	/* tl = subl(7) ^ (subr(7) & ~subr(9)); */
	vpandn %xmm7, %xmm9, %xmm1;
	vpsrldq $4, %xmm1, %xmm1;
	vpxor %xmm1, %xmm7, %xmm0;
	/* dw = tl & subl(9), tr = subr(7) ^ CAMELLIA_RL1(dw); */
	vpand %xmm9, %xmm0, %xmm1;
	vpslld $1, %xmm1, %xmm2;
	vpsrld $31, %xmm1, %xmm1;
	vpaddd %xmm2, %xmm1, %xmm1;
	vpslldq $12, %xmm1, %xmm1;
	vpsrldq $8, %xmm1, %xmm1;
	vpxor %xmm1, %xmm0, %xmm0;

	vpxor %xmm11, %xmm0, %xmm0;
	vpxor %xmm12, %xmm10, %xmm10;
	vpxor %xmm13, %xmm11, %xmm11;
	vpxor %xmm14, %xmm12, %xmm12;
	vpxor %xmm15, %xmm13, %xmm13;
	vmovq %xmm0, cmll_sub(10, CTX);
	vmovq %xmm10, cmll_sub(11, CTX);
	vmovq %xmm11, cmll_sub(12, CTX);
	vmovq %xmm12, cmll_sub(13, CTX);
	vmovq %xmm13, cmll_sub(14, CTX);

	vmovq cmll_sub(16, CTX), %xmm6;
	vmovq cmll_sub(17, CTX), %xmm7;
	vmovq cmll_sub(18, CTX), %xmm8;
	vmovq cmll_sub(19, CTX), %xmm9;
	vmovq cmll_sub(20, CTX), %xmm10;
	/* tl = subl(18) ^ (subr(18) & ~subr(16)); */
	vpandn %xmm8, %xmm6, %xmm1;
	vpsrldq $4, %xmm1, %xmm1;
	vpxor %xmm1, %xmm8, %xmm0;
	/* dw = tl & subl(16), tr = subr(18) ^ CAMELLIA_RL1(dw); */
	vpand %xmm6, %xmm0, %xmm1;
	vpslld $1, %xmm1, %xmm2;
	vpsrld $31, %xmm1, %xmm1;
	vpaddd %xmm2, %xmm1, %xmm1;
	vpslldq $12, %xmm1, %xmm1;
	vpsrldq $8, %xmm1, %xmm1;
	vpxor %xmm1, %xmm0, %xmm0;

	vpxor %xmm14, %xmm0, %xmm0;
	vmovq %xmm0, cmll_sub(15, CTX);

	/* tl = subl(15) ^ (subr(15) & ~subr(17)); */
	vpandn %xmm15, %xmm7, %xmm1;
	vpsrldq $4, %xmm1, %xmm1;
	vpxor %xmm1, %xmm15, %xmm0;
	/* dw = tl & subl(17), tr = subr(15) ^ CAMELLIA_RL1(dw); */
	vpand %xmm7, %xmm0, %xmm1;
	vpslld $1, %xmm1, %xmm2;
	vpsrld $31, %xmm1, %xmm1;
	vpaddd %xmm2, %xmm1, %xmm1;
	vpslldq $12, %xmm1, %xmm1;
	vpsrldq $8, %xmm1, %xmm1;
	vpxor %xmm1, %xmm0, %xmm0;

	vmovq cmll_sub(21, CTX), %xmm1;
	vmovq cmll_sub(22, CTX), %xmm2;
	vmovq cmll_sub(23, CTX), %xmm3;
	vmovq cmll_sub(24, CTX), %xmm4;

	vpxor %xmm9, %xmm0, %xmm0;
	vpxor %xmm10, %xmm8, %xmm8;
	vpxor %xmm1, %xmm9, %xmm9;
	vpxor %xmm2, %xmm10, %xmm10;
	vpxor %xmm3, %xmm1, %xmm1;

	vmovq %xmm0, cmll_sub(18, CTX);
	vmovq %xmm8, cmll_sub(19, CTX);
	vmovq %xmm9, cmll_sub(20, CTX);
	vmovq %xmm10, cmll_sub(21, CTX);
	vmovq %xmm1, cmll_sub(22, CTX);

	vmovq cmll_sub(25, CTX), %xmm5;
	vmovq cmll_sub(26, CTX), %xmm6;
	vmovq cmll_sub(27, CTX), %xmm7;
	vmovq cmll_sub(28, CTX), %xmm8;
	vmovq cmll_sub(29, CTX), %xmm9;
	vmovq cmll_sub(30, CTX), %xmm10;
	vmovq cmll_sub(31, CTX), %xmm11;
	vmovq cmll_sub(32, CTX), %xmm12;

	/* tl = subl(26) ^ (subr(26) & ~subr(24)); */
	vpandn %xmm6, %xmm4, %xmm15;
	vpsrldq $4, %xmm15, %xmm15;
	vpxor %xmm15, %xmm6, %xmm0;
	/* dw = tl & subl(26), tr = subr(24) ^ CAMELLIA_RL1(dw); */
	vpand %xmm4, %xmm0, %xmm15;
	vpslld $1, %xmm15, %xmm14;
	vpsrld $31, %xmm15, %xmm15;
	vpaddd %xmm14, %xmm15, %xmm15;
	vpslldq $12, %xmm15, %xmm15;
	vpsrldq $8, %xmm15, %xmm15;
	vpxor %xmm15, %xmm0, %xmm0;

	vpxor %xmm0, %xmm2, %xmm2;
	vmovq %xmm2, cmll_sub(23, CTX);

	/* tl = subl(23) ^ (subr(23) &  ~subr(25)); */
	vpandn %xmm3, %xmm5, %xmm15;
	vpsrldq $4, %xmm15, %xmm15;
	vpxor %xmm15, %xmm3, %xmm0;
	/* dw = tl & subl(26), tr = subr(24) ^ CAMELLIA_RL1(dw); */
	vpand %xmm5, %xmm0, %xmm15;
	vpslld $1, %xmm15, %xmm14;
	vpsrld $31, %xmm15, %xmm15;
	vpaddd %xmm14, %xmm15, %xmm15;
	vpslldq $12, %xmm15, %xmm15;
	vpsrldq $8, %xmm15, %xmm15;
	vpxor %xmm15, %xmm0, %xmm0;

	vpxor %xmm7, %xmm0, %xmm0;
	vpxor %xmm8, %xmm6, %xmm6;
	vpxor %xmm9, %xmm7, %xmm7;
	vpxor %xmm10, %xmm8, %xmm8;
	vpxor %xmm11, %xmm9, %xmm9;
	vpxor %xmm12, %xmm11, %xmm11;

	vmovq %xmm0, cmll_sub(26, CTX);
	vmovq %xmm6, cmll_sub(27, CTX);
	vmovq %xmm7, cmll_sub(28, CTX);
	vmovq %xmm8, cmll_sub(29, CTX);
	vmovq %xmm9, cmll_sub(30, CTX);
	vmovq %xmm10, cmll_sub(31, CTX);
	vmovq %xmm11, cmll_sub(32, CTX);

	/* kw2 and kw4 are unused now. */
	movq $0, cmll_sub(1, CTX);
	movq $0, cmll_sub(33, CTX);

	vzeroupper;

	ret;
