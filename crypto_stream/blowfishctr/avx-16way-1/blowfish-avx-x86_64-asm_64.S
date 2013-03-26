/*
 * Blowfish Cipher 16-way parallel algorithm (AVX/x86_64)
 *
 * Copyright (C) 2012 Johannes Goetzfried
 *     <Johannes.Goetzfried@informatik.stud.uni-erlangen.de>
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
#define RK %xmm9

#define RMASK %xmm10

#define RID1  %rax
#define RID1b %al
#define RID2  %rbx
#define RID2b %bl

#define RGI1   %rdx
#define RGI1bl %dl
#define RGI1bh %dh
#define RGI2   %rcx
#define RGI2bl %cl
#define RGI2bh %ch

#define RFS1  %r8
#define RFS1d %r8d
#define RFS2  %r9
#define RFS2d %r9d
#define RFS3  %r10
#define RFS3d %r10d


#define lookup_32bit(src, dst) \
	movb		src ## bl,        RID1b;     \
	movb		src ## bh,        RID2b;     \
	movl		s0(CTX, RID1, 4), dst ## d;  \
	addl		s1(CTX, RID2, 4), dst ## d;  \
	shrq $16,	src;                         \
	movb		src ## bl,        RID1b;     \
	movb		src ## bh,        RID2b;     \
	xorl		s2(CTX, RID1, 4), dst ## d;  \
	addl		s3(CTX, RID2, 4), dst ## d;

#define F(a, x) \
	vpshufb	RMASK,	a,    x;    \
	vmovq		x,    RGI1; \
	vpsrldq $8,	x,    x;    \
	vmovq		x,    RGI2; \
	\
	lookup_32bit(RGI1, RFS1);   \
	shrq $16,	RGI1;       \
	lookup_32bit(RGI1, RFS2);   \
	shlq $32,	RFS2;       \
	orq		RFS1, RFS2; \
	\
	lookup_32bit(RGI2, RFS1);   \
	shrq $16,	RGI2;       \
	lookup_32bit(RGI2, RFS3);   \
	shlq $32,	RFS3;       \
	orq		RFS1, RFS3; \
	\
	vmovq		RFS2, x;    \
	vpinsrq $1,	RFS3, x, x;

#define subround(a, b, x) \
	vpxor	b, RK, b; \
	F(b, x);          \
	vpxor	a, x,  a;

#define round(r, l, n) \
	vbroadcastss (p + 4*(n))(CTX), RK; \
	subround(r ## 1, l ## 1, RX);      \
	subround(r ## 2, l ## 2, RX);      \
	subround(r ## 3, l ## 3, RX);      \
	subround(r ## 4, l ## 4, RX);

#define last(i, j) \
	vbroadcastss (p + 4*(i))(CTX), RK; \
	vpxor		RK, RL1, RL1;      \
	vpxor		RK, RL2, RL2;      \
	vpxor		RK, RL3, RL3;      \
	vpxor		RK, RL4, RL4;      \
	vbroadcastss (p + 4*(j))(CTX), RK; \
	vpxor		RK, RR1, RR1;      \
	vpxor		RK, RR2, RR2;      \
	vpxor		RK, RR3, RR3;      \
	vpxor		RK, RR4, RR4;


#define transpose_2x4(x0, x1, t0, t1) \
	vpunpckldq		x1, x0, t0; \
	vpunpckhdq		x1, x0, t1; \
	\
	vpunpcklqdq		t1, t0, x0; \
	vpunpckhqdq		t1, t0, x1;

#define inpack_blocks(in, x0, x1, t0, t1) \
	vmovdqu (0*4*4)(in),	x0; \
	vmovdqu (1*4*4)(in),	x1; \
	vpshufb RMASK, x0,	x0; \
	vpshufb RMASK, x1,	x1; \
	\
	transpose_2x4(x0, x1, t0, t1)

#define outunpack_blocks(out, x0, x1, t0, t1) \
	transpose_2x4(x0, x1, t0, t1) \
	\
	vpshufb RMASK,	x0, x0;           \
	vpshufb RMASK,	x1, x1;           \
	vmovdqu 	x0, (0*4*4)(out); \
	vmovdqu		x1, (1*4*4)(out);

#define outunpack_xor_blocks(out, x0, x1, t0, t1) \
	transpose_2x4(x0, x1, t0, t1) \
	\
	vpshufb RMASK,	x0, x0;               \
	vpshufb RMASK,	x1, x1;               \
	vpxor		(0*4*4)(out), x0, x0; \
	vmovdqu 	x0, (0*4*4)(out);     \
	vpxor		(1*4*4)(out), x1, x1; \
	vmovdqu	        x1, (1*4*4)(out);

.align 16
.Lbswap_mask:
	.byte 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12

.align 16
.global __blowfish_enc_blk_16way
.type   __blowfish_enc_blk_16way,@function;

__blowfish_enc_blk_16way:
	/* input:
	 *	%rdi: ctx, CTX
	 *	%rsi: dst
	 *	%rdx: src
	 *	%rcx: bool, if true: xor output
	 */

	pushq %rbx;
	pushq %rcx;

	vmovdqu .Lbswap_mask, RMASK;

	inpack_blocks(%rdx, RL1, RR1, RK, RX);
	leaq (2*4*4)(%rdx), %rax;
	inpack_blocks(%rax, RL2, RR2, RK, RX);
	leaq (2*4*4)(%rax), %rax;
	inpack_blocks(%rax, RL3, RR3, RK, RX);
	leaq (2*4*4)(%rax), %rax;
	inpack_blocks(%rax, RL4, RR4, RK, RX);

	xorq RID1, RID1;
	xorq RID2, RID2;

	round(RR, RL, 0);
	round(RL, RR, 1);
	round(RR, RL, 2);
	round(RL, RR, 3);
	round(RR, RL, 4);
	round(RL, RR, 5);
	round(RR, RL, 6);
	round(RL, RR, 7);
	round(RR, RL, 8);
	round(RL, RR, 9);
	round(RR, RL, 10);
	round(RL, RR, 11);
	round(RR, RL, 12);
	round(RL, RR, 13);
	round(RR, RL, 14);
	round(RL, RR, 15);
	last(16, 17);

	popq %rcx;
	popq %rbx;

	testb %cl, %cl;
	jnz __enc_xor16;

	outunpack_blocks(%rsi, RR1, RL1, RK, RX);
	leaq (2*4*4)(%rsi), %rax;
	outunpack_blocks(%rax, RR2, RL2, RK, RX);
	leaq (2*4*4)(%rax), %rax;
	outunpack_blocks(%rax, RR3, RL3, RK, RX);
	leaq (2*4*4)(%rax), %rax;
	outunpack_blocks(%rax, RR4, RL4, RK, RX);

	ret;

__enc_xor16:
	outunpack_xor_blocks(%rsi, RR1, RL1, RK, RX);
	leaq (2*4*4)(%rsi), %rax;
	outunpack_xor_blocks(%rax, RR2, RL2, RK, RX);
	leaq (2*4*4)(%rax), %rax;
	outunpack_xor_blocks(%rax, RR3, RL3, RK, RX);
	leaq (2*4*4)(%rax), %rax;
	outunpack_xor_blocks(%rax, RR4, RL4, RK, RX);

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

	pushq %rbx;

	vmovdqu .Lbswap_mask, RMASK;

	inpack_blocks(%rdx, RL1, RR1, RK, RX);
	leaq (2*4*4)(%rdx), %rax;
	inpack_blocks(%rax, RL2, RR2, RK, RX);
	leaq (2*4*4)(%rax), %rax;
	inpack_blocks(%rax, RL3, RR3, RK, RX);
	leaq (2*4*4)(%rax), %rax;
	inpack_blocks(%rax, RL4, RR4, RK, RX);

	xorq RID1, RID1;
	xorq RID2, RID2;

	round(RR, RL, 17);
	round(RL, RR, 16);
	round(RR, RL, 15);
	round(RL, RR, 14);
	round(RR, RL, 13);
	round(RL, RR, 12);
	round(RR, RL, 11);
	round(RL, RR, 10);
	round(RR, RL, 9);
	round(RL, RR, 8);
	round(RR, RL, 7);
	round(RL, RR, 6);
	round(RR, RL, 5);
	round(RL, RR, 4);
	round(RR, RL, 3);
	round(RL, RR, 2);
	last(1, 0);

	popq %rbx;

	outunpack_blocks(%rsi, RR1, RL1, RK, RX);
	leaq (2*4*4)(%rsi), %rax;
	outunpack_blocks(%rax, RR2, RL2, RK, RX);
	leaq (2*4*4)(%rax), %rax;
	outunpack_blocks(%rax, RR3, RL3, RK, RX);
	leaq (2*4*4)(%rax), %rax;
	outunpack_blocks(%rax, RR4, RL4, RK, RX);

	ret;

