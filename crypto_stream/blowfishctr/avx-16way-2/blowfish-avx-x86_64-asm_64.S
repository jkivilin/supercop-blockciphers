/*
 * Blowfish Cipher 16-way parallel algorithm (AVX/x86_64)
 *
 * Copyright (C) 2012 Johannes Goetzfried
 *     <Johannes.Goetzfried@informatik.stud.uni-erlangen.de>
 * Copyright (C) 2013 Jussi Kivilinna <jussi.kivilinna@iki.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 * USA
 *
 */

.file "blowfish-avx-x86_64-asm_64.S"
.text

/* structure of crypto context */
#define p	0
#define s0	(18*4)
#define s1	((18*4)+1024)
#define s2	((18*4)+2048)
#define s3	((18*4)+3072)

/**********************************************************************
  16-way AVX blowfish
 **********************************************************************/
#define CTX %rdi

#define RL1 %xmm0
#define RR1 %xmm1
#define RL2 %xmm2
#define RR2 %xmm3
#define RL3 %xmm4
#define RR3 %xmm5
#define RL4 %xmm6
#define RR4 %xmm7

#define RX %xmm8
#define RY %xmm9
#define RK %xmm10

#define RMASK %xmm11

#define RID1   %rbp
#define RID1d  %ebp
#define RID2   %rsi
#define RID2d  %esi
#define RID3   %rcx
#define RID3d  %ecx

#define RGI1   %rax
#define RGI1bl %al
#define RGI1bh %ah
#define RGI2   %rdx
#define RGI2bl %dl
#define RGI2bh %dh

#define RFS1   %r8
#define RFS1d  %r8d
#define RFS2   %r9
#define RFS2d  %r9d
#define RFS3   %r10
#define RFS3d  %r10d


#define lookup_32bit(src, dst, interleave_op, il_reg) \
	movzbl		src ## bh, RID2d;             \
	movzbl		src ## bl, RID3d;             \
	shrq $16,	src;                          \
	movzbl		src ## bh, RID1d;             \
	movl		s0(CTX, RID1, 4), dst ## d;   \
	movzbl		src ## bl, RID1d;             \
	interleave_op(il_reg);                        \
	addl		s1(CTX, RID1, 4), dst ## d;   \
	xorl		s2(CTX, RID2, 4), dst ## d;   \
	addl		s3(CTX, RID3, 4), dst ## d;

#define dummy(d) /* do nothing */

#define shr_next(reg) \
	shrq $16,	reg;

#define F(gi1, gi2) \
	lookup_32bit(##gi1, RFS1, shr_next, ##gi1);   \
	lookup_32bit(##gi2, RFS3, shr_next, ##gi2);   \
	\
	lookup_32bit(##gi1, RFS2, dummy, none);       \
	shlq $32,	RFS2;                         \
	orq		RFS1, RFS2;                   \
	lookup_32bit(##gi2, RFS1, dummy, none);       \
	shlq $32,	RFS1;                         \
	orq		RFS3, RFS1;

#define subround2(a1, b1, a2, b2) \
	vmovq		b1, RGI1;                     \
	vpextrq $1,	b1, RGI2;                     \
	F(RGI1, RGI2);                                \
	vmovq		b2, RGI1;                     \
	vpextrq $1,	b2, RGI2;                     \
	vmovq		RFS2, RX;                     \
	vpinsrq $1,	RFS1, RX, RX;                 \
	F(RGI1, RGI2);                                \
	vmovq		RFS2, RY;                     \
	vpinsrq $1,	RFS1, RY, RY;                 \
	vpxor		a1, RX, a1;                   \
	vpxor		a2, RY, a2;

#define first(i) \
	vbroadcastss	(p + 4*(i))(CTX), RK;

#define round(r, l, n) \
	vpxor		l ## 1, RK, l ## 1;           \
	vpxor		l ## 2, RK, l ## 2;           \
	vpxor		l ## 3, RK, l ## 3;           \
	vpxor		l ## 4, RK, l ## 4;           \
	vbroadcastss	(p + 4*(n))(CTX), RK;         \
	subround2(r ## 1, l ## 1, r ## 2, l ## 2);    \
	subround2(r ## 3, l ## 3, r ## 4, l ## 4);

#define last(j) \
	vbroadcastss (p + 4*(j))(CTX), RX;            \
	vpxor		RK, RL1, RL1;                 \
	vpxor		RK, RL2, RL2;                 \
	vpxor		RK, RL3, RL3;                 \
	vpxor		RK, RL4, RL4;                 \
	vpxor		RX, RR1, RR1;                 \
	vpxor		RX, RR2, RR2;                 \
	vpxor		RX, RR3, RR3;                 \
	vpxor		RX, RR4, RR4;

#define transpose_2x4(x0, x1, t0, t1) \
	vpunpckldq	x1, x0, t0;                   \
	vpunpckhdq	x1, x0, t1;                   \
	\
	vpunpcklqdq	t1, t0, x0;                   \
	vpunpckhqdq	t1, t0, x1;

#define inpack_blocks(in, x0, x1, t0, t1) \
	vmovdqu		(0*4*4)(in), x0;              \
	vmovdqu		(1*4*4)(in), x1;              \
	vpshufb		RMASK, x0, x0;                \
	vpshufb		RMASK, x1, x1;                \
	\
	transpose_2x4(x0, x1, t0, t1)

#define outunpack_blocks(out, x0, x1, t0, t1) \
	transpose_2x4(x0, x1, t0, t1)                 \
	\
	vpshufb		RMASK, x0, x0;                \
	vpshufb		RMASK, x1, x1;                \
	vmovdqu 	x0, (0*4*4)(out);             \
	vmovdqu		x1, (1*4*4)(out);

#define outunpack_xor_blocks(out, x0, x1, t0, t1) \
	transpose_2x4(x0, x1, t0, t1)                 \
	\
	vpshufb		RMASK, x0, x0;                \
	vpshufb		RMASK, x1, x1;                \
	vpxor		(0*4*4)(out), x0, x0;         \
	vmovdqu 	x0, (0*4*4)(out);             \
	vpxor		(1*4*4)(out), x1, x1;         \
	vmovdqu	        x1, (1*4*4)(out);

.align 16
.Lbswap_mask:
	.byte 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12

.align 16
.global blowfish_enc_blk_16way
.type   blowfish_enc_blk_16way,@function;

blowfish_enc_blk_16way:
	/* input:
	 *	%rdi: ctx, CTX
	 *	%rsi: dst
	 *	%rdx: src
	 */

	pushq %rbp;
	movq %rsi, %r11;

	vmovdqa .Lbswap_mask, RMASK;

	leaq (2*4*4)(%rdx), %rax;
	leaq (4*4*4)(%rdx), %r8;
	leaq (6*4*4)(%rdx), %r9;
	inpack_blocks(%rdx, RL1, RR1, RK, RX);
	inpack_blocks(%rax, RL2, RR2, RK, RX);
	inpack_blocks(%r8, RL3, RR3, RK, RX);
	inpack_blocks(%r9, RL4, RR4, RK, RX);

	first(0);
	round(RR, RL, 1);
	round(RL, RR, 2);
	round(RR, RL, 3);
	round(RL, RR, 4);
	round(RR, RL, 5);
	round(RL, RR, 6);
	round(RR, RL, 7);
	round(RL, RR, 8);
	round(RR, RL, 9);
	round(RL, RR, 10);
	round(RR, RL, 11);
	round(RL, RR, 12);
	round(RR, RL, 13);
	round(RL, RR, 14);
	round(RR, RL, 15);
	round(RL, RR, 16);
	last(17);

	leaq (2*4*4)(%r11), %rax;
	leaq (4*4*4)(%r11), %r8;
	leaq (6*4*4)(%r11), %r9;
	outunpack_blocks(%r11, RR1, RL1, RK, RX);
	outunpack_blocks(%rax, RR2, RL2, RK, RX);
	outunpack_blocks(%r8, RR3, RL3, RK, RX);
	outunpack_blocks(%r9, RR4, RL4, RK, RX);

	popq %rbp;

	ret;

.align 16
.global blowfish_dec_blk_16way
.type   blowfish_dec_blk_16way,@function;

blowfish_dec_blk_16way:
	/* input:
	 *	%rdi: ctx, CTX
	 *	%rsi: dst
	 *	%rdx: src
	 */

	pushq %rbp;
	movq %rsi, %r11;

	vmovdqa .Lbswap_mask, RMASK;

	leaq (2*4*4)(%rdx), %rax;
	leaq (4*4*4)(%rdx), %r8;
	leaq (6*4*4)(%rdx), %r9;
	inpack_blocks(%rdx, RL1, RR1, RK, RX);
	inpack_blocks(%rax, RL2, RR2, RK, RX);
	inpack_blocks(%r8, RL3, RR3, RK, RX);
	inpack_blocks(%r9, RL4, RR4, RK, RX);

	first(17);
	round(RR, RL, 16);
	round(RL, RR, 15);
	round(RR, RL, 14);
	round(RL, RR, 13);
	round(RR, RL, 12);
	round(RL, RR, 11);
	round(RR, RL, 10);
	round(RL, RR, 9);
	round(RR, RL, 8);
	round(RL, RR, 7);
	round(RR, RL, 6);
	round(RL, RR, 5);
	round(RR, RL, 4);
	round(RL, RR, 3);
	round(RR, RL, 2);
	round(RL, RR, 1);
	last(0);

	leaq (2*4*4)(%r11), %rax;
	leaq (4*4*4)(%r11), %r8;
	leaq (6*4*4)(%r11), %r9;
	outunpack_blocks(%r11, RR1, RL1, RK, RX);
	outunpack_blocks(%rax, RR2, RL2, RK, RX);
	outunpack_blocks(%r8, RR3, RL3, RK, RX);
	outunpack_blocks(%r9, RR4, RL4, RK, RX);

	popq %rbp;

	ret;
