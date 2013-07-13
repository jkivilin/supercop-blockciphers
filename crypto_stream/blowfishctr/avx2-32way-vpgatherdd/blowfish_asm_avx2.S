/* blowfish_asm_avx2.S
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

#ifdef __x86_64

.file "blowfish_asm_avx2.S"

.data
.align 32

bswap32_mask:
.long 0x00010203
.long 0x04050607
.long 0x08090a0b
.long 0x0c0d0e0f

.text
/* structure of crypto context */
#define p	0
#define s0	((16 + 2) * 4)
#define s1	((16 + 2 + (1 * 256)) * 4)
#define s2	((16 + 2 + (2 * 256)) * 4)
#define s3	((16 + 2 + (3 * 256)) * 4)

/* register macros */
#define CTX	%rdi
#define RIO	 %rdx

#define RS0	%rax
#define RS1	%r8
#define RS2	%r9
#define RS3	%r10

#define RLOOP	%r11
#define RLOOPd	%r11d

#define RXr0	%ymm8
#define RXr1	%ymm9
#define RXr2	%ymm10
#define RXr3	%ymm11
#define RXl0	%ymm12
#define RXl1	%ymm13
#define RXl2	%ymm14
#define RXl3	%ymm15

/* temp regs */
#define RT0	%ymm0
#define RT1	%ymm1
#define RIDX0	%ymm2
#define RIDX1	%ymm3
#define RIDX2	%ymm4
#define RIDX3	%ymm5

#define RT1x	%xmm1

/* vpgatherdd mask and '-1' */
#define RNOT	%ymm6

/* byte mask, (-1 >> 24) */
#define RBYTE	%ymm7

/***********************************************************************
 * 32-way AVX2 blowfish
 ***********************************************************************/
#define F(xl, xr) \
	vpsrld $24, xl, RIDX0; \
	vpsrld $16, xl, RIDX1; \
	vpsrld $8, xl, RIDX2; \
	vpand RBYTE, RIDX1, RIDX1; \
	vpand RBYTE, RIDX2, RIDX2; \
	vpand RBYTE, xl, RIDX3; \
	\
	vpgatherdd RNOT, (RS0, RIDX0, 4), RT0; \
	vpcmpeqd RNOT, RNOT, RNOT; \
	vpcmpeqd RIDX0, RIDX0, RIDX0; \
	\
	vpgatherdd RNOT, (RS1, RIDX1, 4), RT1; \
	vpcmpeqd RIDX1, RIDX1, RIDX1; \
	vpaddd RT0, RT1, RT0; \
	\
	vpgatherdd RIDX0, (RS2, RIDX2, 4), RT1; \
	vpxor RT0, RT1, RT0; \
	\
	vpgatherdd RIDX1, (RS3, RIDX3, 4), RT1; \
	vpcmpeqd RNOT, RNOT, RNOT; \
	vpaddd RT0, RT1, RT0; \
	\
	vpxor RT0, xr, xr;

#define add_roundkey(xl, nmem) \
	vpbroadcastd nmem, RT0; \
	vpxor RT0, xl ## 0, xl ## 0; \
	vpxor RT0, xl ## 1, xl ## 1; \
	vpxor RT0, xl ## 2, xl ## 2; \
	vpxor RT0, xl ## 3, xl ## 3;

#define round_enc() \
	add_roundkey(RXr, p(CTX,RLOOP,4)); \
	F(RXl0, RXr0); \
	F(RXl1, RXr1); \
	F(RXl2, RXr2); \
	F(RXl3, RXr3); \
	\
	add_roundkey(RXl, p+4(CTX,RLOOP,4)); \
	F(RXr0, RXl0); \
	F(RXr1, RXl1); \
	F(RXr2, RXl2); \
	F(RXr3, RXl3);

#define round_dec() \
	add_roundkey(RXr, p+4*2(CTX,RLOOP,4)); \
	F(RXl0, RXr0); \
	F(RXl1, RXr1); \
	F(RXl2, RXr2); \
	F(RXl3, RXr3); \
	\
	add_roundkey(RXl, p+4(CTX,RLOOP,4)); \
	F(RXr0, RXl0); \
	F(RXr1, RXl1); \
	F(RXr2, RXl2); \
	F(RXr3, RXl3);

#define init_round_constants() \
	vpcmpeqd RNOT, RNOT, RNOT; \
	leaq s0(CTX), RS0; \
	leaq s1(CTX), RS1; \
	vpsrld $24, RNOT, RBYTE; \
	leaq s2(CTX), RS2; \
	leaq s3(CTX), RS3;

#define transpose_2x2(x0, x1, t0) \
	vpunpckldq x0, x1, t0; \
	vpunpckhdq x0, x1, x1; \
	\
	vpunpcklqdq t0, x1, x0; \
	vpunpckhqdq t0, x1, x1;

#define read_block(xl, xr) \
	vbroadcasti128 bswap32_mask, RT1; \
	\
	vmovdqu 0*32(RIO), xl ## 0; \
	vmovdqu 1*32(RIO), xr ## 0; \
	vmovdqu 2*32(RIO), xl ## 1; \
	vmovdqu 3*32(RIO), xr ## 1; \
	vmovdqu 4*32(RIO), xl ## 2; \
	vmovdqu 5*32(RIO), xr ## 2; \
	vmovdqu 6*32(RIO), xl ## 3; \
	vmovdqu 7*32(RIO), xr ## 3; \
	\
	vpshufb RT1, xl ## 0, xl ## 0; \
	vpshufb RT1, xr ## 0, xr ## 0; \
	vpshufb RT1, xl ## 1, xl ## 1; \
	vpshufb RT1, xr ## 1, xr ## 1; \
	vpshufb RT1, xl ## 2, xl ## 2; \
	vpshufb RT1, xr ## 2, xr ## 2; \
	vpshufb RT1, xl ## 3, xl ## 3; \
	vpshufb RT1, xr ## 3, xr ## 3; \
	\
	transpose_2x2(xl ## 0, xr ## 0, RT0); \
	transpose_2x2(xl ## 1, xr ## 1, RT0); \
	transpose_2x2(xl ## 2, xr ## 2, RT0); \
	transpose_2x2(xl ## 3, xr ## 3, RT0);

#define write_block(xl, xr) \
	vbroadcasti128 bswap32_mask, RT1; \
	\
	transpose_2x2(xl ## 0, xr ## 0, RT0); \
	transpose_2x2(xl ## 1, xr ## 1, RT0); \
	transpose_2x2(xl ## 2, xr ## 2, RT0); \
	transpose_2x2(xl ## 3, xr ## 3, RT0); \
	\
	vpshufb RT1, xl ## 0, xl ## 0; \
	vpshufb RT1, xr ## 0, xr ## 0; \
	vpshufb RT1, xl ## 1, xl ## 1; \
	vpshufb RT1, xr ## 1, xr ## 1; \
	vpshufb RT1, xl ## 2, xl ## 2; \
	vpshufb RT1, xr ## 2, xr ## 2; \
	vpshufb RT1, xl ## 3, xl ## 3; \
	vpshufb RT1, xr ## 3, xr ## 3; \
	\
	vmovdqu xr ## 0, 0*32(RIO); \
	vmovdqu xl ## 0, 1*32(RIO); \
	vmovdqu xr ## 1, 2*32(RIO); \
	vmovdqu xl ## 1, 3*32(RIO); \
	vmovdqu xr ## 2, 4*32(RIO); \
	vmovdqu xl ## 2, 5*32(RIO); \
	vmovdqu xr ## 3, 6*32(RIO); \
	vmovdqu xl ## 3, 7*32(RIO);

#define vpxor_unaligned(r, mem) \
	vmovdqu mem, RT0; \
	vpxor RT0, r, r; \
	vmovdqu r, mem; \

#define xor_block(xl, xr) \
	vbroadcasti128 bswap32_mask, RT1; \
	\
	transpose_2x2(xl ## 0, xr ## 0, RT0); \
	transpose_2x2(xl ## 1, xr ## 1, RT0); \
	transpose_2x2(xl ## 2, xr ## 2, RT0); \
	transpose_2x2(xl ## 3, xr ## 3, RT0); \
	\
	vpshufb RT1, xl ## 0, xl ## 0; \
	vpshufb RT1, xr ## 0, xr ## 0; \
	vpshufb RT1, xl ## 1, xl ## 1; \
	vpshufb RT1, xr ## 1, xr ## 1; \
	vpshufb RT1, xl ## 2, xl ## 2; \
	vpshufb RT1, xr ## 2, xr ## 2; \
	vpshufb RT1, xl ## 3, xl ## 3; \
	vpshufb RT1, xr ## 3, xr ## 3; \
	\
	vpxor_unaligned(xr ## 0, 0*32(RIO)); \
	vpxor_unaligned(xl ## 0, 1*32(RIO)); \
	vpxor_unaligned(xr ## 1, 2*32(RIO)); \
	vpxor_unaligned(xl ## 1, 3*32(RIO)); \
	vpxor_unaligned(xr ## 2, 4*32(RIO)); \
	vpxor_unaligned(xl ## 2, 5*32(RIO)); \
	vpxor_unaligned(xr ## 3, 6*32(RIO)); \
	vpxor_unaligned(xl ## 3, 7*32(RIO));

.align 8
.global __blowfish_enc_blk_avx2_32way
.type   __blowfish_enc_blk_avx2_32way,@function;

__blowfish_enc_blk_avx2_32way:
	/* input:
	 *	%rdi: ctx, CTX
	 *	%rsi: dst (32 blocks)
	 *	%rdx: src (32 blocks), RIO
	 *	%rcx: bool, if true: xor output
	 */
	vzeroupper;
	init_round_constants();

	read_block(RXl, RXr);
	movq %rsi, RIO;

	movl $1, RLOOPd;
	add_roundkey(RXl, p+4*(0)(CTX));

.align 4
.L__enc_loop:
		round_enc();
		leal 2(RLOOPd), RLOOPd;
		cmpl $17, RLOOPd;
		jne .L__enc_loop;

	add_roundkey(RXr, p+4*(17)(CTX));

	test %cl, %cl;
	jnz .L__enc_xor16;

	write_block(RXl, RXr);

	vzeroupper;
	ret;
.L__enc_xor16:
	xor_block(RXl, RXr);

	vzeroupper;
	ret;

.align 8
.global blowfish_dec_blk_avx2_32way
.type   blowfish_dec_blk_avx2_32way,@function;

blowfish_dec_blk_avx2_32way:
	/* input:
	 *	%rdi: ctx, CTX
	 *	%rsi: dst
	 *	%rdx: src
	 */
	vzeroupper;
	init_round_constants();

	read_block(RXl, RXr);
	movq %rsi, RIO;

	movl $14, RLOOPd;
	add_roundkey(RXl, p+4*(17)(CTX));

.align 4
.L__dec_loop:
		round_dec();
		addl $-2, RLOOPd;
		jns .L__dec_loop;

	add_roundkey(RXr, p+4*(0)(CTX));

	write_block(RXl, RXr);

	vzeroupper;
	ret;

#endif
