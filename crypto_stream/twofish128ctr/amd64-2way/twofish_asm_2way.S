/* twofish_asm_2way.S
 *
 * Copyright © 2011-2013 Jussi Kivilinna <jussi.kivilinna@iki.fi>
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

.file "twofish_asm.S"
.text

// ctx: uint32 s[4][256], w[8], k[32];
#define s0	0
#define s1	1024
#define s2	2048
#define s3	3072
#define w	4096
#define	k	4128

#define do16bit_ror(rot, op1, op2, T0, T1, tmp1, tmp2, ab, dst) \
	movzbl ab ## bl,		tmp2 ## d; \
	movzbl ab ## bh,		tmp1 ## d; \
	rorq $(rot),			ab; \
	op1##l T0(CTX, tmp2, 4),	dst ## d; \
	op2##l T1(CTX, tmp1, 4),	dst ## d;

#define CTX %rdi
#define RIO %rsi

/**********************************************************************
  1-way twofish
 **********************************************************************/
#define RAC0 %rax
#define RBD0 %rbx
#define RAC1 %rcx
#define RBD1 %rdx

#define RAC0d %eax
#define RBD0d %ebx
#define RAC1d %ecx
#define RBD1d %edx

#define RAC0bl %al
#define RBD0bl %bl
#define RAC1bl %cl
#define RBD1bl %dl

#define RAC0bh %ah
#define RBD0bh %bh
#define RAC1bh %ch
#define RBD1bh %dh

#define RX0 %r8
#define RX1 %r9
#define RY0 %r10
#define RY1 %r11

#define RX0d %r8d
#define RX1d %r9d
#define RY0d %r10d
#define RY1d %r11d

#define RD0 %rsi
#define RD1 %rbp
#define RC0 %r12
#define RC1 %r13

#define RD0d %esi
#define RD1d %ebp
#define RC0d %r12d
#define RC1d %r13d

#define RMASK %r14

#define g1(ac, x, u) \
	do16bit_ror(16, mov, xor, s0, s1, RD0, RC0, ac ## u, x ## u); \
	do16bit_ror(16, xor, xor, s2, s3, RD1, RC1, ac ## u, x ## u);
#define g2(bd, y, u) \
	do16bit_ror(16, mov, xor, s1, s2, RD0, RC0, bd ## u, y ## u); \
	do16bit_ror(16, xor, xor, s3, s0, RD1, RC1, bd ## u, y ## u);

#define encrypt_round(n, ac, bd) \
	g1(ac, RX, 0); \
	g2(bd, RY, 0); \
	\
	movl ac ## 0d,			RC0d; \
	movl bd ## 0d,			RD0d; \
	\
	addl RY0d,			RX0d; \
	addl RX0d,			RY0d; \
	addl k+4*(2*(n))(CTX),		RX0d; \
	addl k+4*(2*(n)+1)(CTX),	RY0d; \
	\
	xorl RX0d,			RC0d; \
	rorl $1,			RC0d; \
	roll $1,			RD0d; \
	xorl RY0d,			RD0d; \
	\
	andq RMASK,			ac ## 0; \
	orq RC0,			ac ## 0; \
	andq RMASK,			bd ## 0; \
	orq RD0,			bd ## 0;

#define decrypt_round(n, ac, bd) \
	g1(ac, RX, 0); \
	g2(bd, RY, 0); \
	\
	movl ac ## 0d,			RC0d; \
	movl bd ## 0d,			RD0d; \
	\
	addl RY0d,			RX0d; \
	addl RX0d,			RY0d; \
	addl k+4*(2*(n))(CTX),		RX0d; \
	addl k+4*(2*(n)+1)(CTX),	RY0d; \
	\
	roll $1,			RC0d; \
	xorl RX0d,			RC0d; \
	xorl RY0d,			RD0d; \
	rorl $1,			RD0d; \
	\
	andq RMASK,			ac ## 0; \
	orq RC0,			ac ## 0; \
	andq RMASK,			bd ## 0; \
	orq RD0,			bd ## 0;

#define encrypt_cycle(n) \
	encrypt_round(n*2, RAC, RBD); \
	encrypt_round((n*2)+1, RAC, RBD);

#define decrypt_cycle(n) \
	decrypt_round((n*2)+1, RAC, RBD); \
	decrypt_round((n*2), RAC, RBD);

#define inpack(in, n, xy, m) \
	movq 0+4*(n)(in),		xy ## 0; \
	xorq w+4*m(CTX),		xy ## 0;

#define outunpack(out, n, xy, m) \
	xorq w+4*m(CTX),		xy ## 0; \
	movq xy ## 0,			4*(n)(out);

#define pack_abcd_to_acbd(ab, cd, ac, bd) \
	movl ab ## d,		ac ## d; \
	shrq $32,		ab; \
	movq cd,		bd; \
	shlq $32,		cd; \
	andq RMASK,		bd; \
	orq cd,			ac; \
	orq ab,			bd;

#define inpack_enc() \
	inpack(RIO, 0, RX, 0); \
	inpack(RIO, 2, RY, 2); \
	pack_abcd_to_acbd(RX0, RY0, RAC0, RBD0);

#define outunpack_enc() \
	pack_abcd_to_acbd(RAC0, RBD0, RX0, RY0); \
	outunpack(RIO, 0, RY, 4); \
	outunpack(RIO, 2, RX, 6);

#define inpack_dec() \
	inpack(RIO, 0, RY, 4); \
	inpack(RIO, 2, RX, 6); \
	pack_abcd_to_acbd(RY0, RX0, RAC0, RBD0);

#define outunpack_dec() \
	pack_abcd_to_acbd(RAC0, RBD0, RY0, RX0); \
	outunpack(RIO, 0, RX, 0); \
	outunpack(RIO, 2, RY, 2);

#if 0
.align 8
.global asm_twofish_encrypt1
.type   asm_twofish_encrypt1,@function;

asm_twofish_encrypt1:
	// input:
	//	%rdi: ctx, CTX
	//	%rdx: dst
	//	%rsi: src
	pushq RMASK
	movq $0xffffffff00000000, RMASK;
	pushq %rbp
	pushq %rbx
	pushq %r12
	pushq %r13

	pushq %rsi; // dst
	mov %rdx, RIO // src

	inpack_enc();

	encrypt_cycle(0);
	encrypt_cycle(1);
	encrypt_cycle(2);
	encrypt_cycle(3);
	encrypt_cycle(4);
	encrypt_cycle(5);
	encrypt_cycle(6);
	encrypt_cycle(7);

	popq RIO; // dst

	outunpack_enc();

	popq %r13
	popq %r12
	popq %rbx
	popq %rbp
	popq RMASK

	ret;

.global asm_twofish_decrypt1
.type   asm_twofish_decrypt1,@function;

asm_twofish_decrypt1:
	// input:
	//	%rdi: ctx, CTX
	//	%rsi: dst
	//	%rdx: src
	pushq RMASK
	movq $0xffffffff00000000, RMASK;
	pushq %rbp
	pushq %rbx
	pushq %r12
	pushq %r13

	pushq %rsi; // dst
	mov %rdx, RIO // src

	inpack_dec();

	decrypt_cycle(7);
	decrypt_cycle(6);
	decrypt_cycle(5);
	decrypt_cycle(4);
	decrypt_cycle(3);
	decrypt_cycle(2);
	decrypt_cycle(1);
	decrypt_cycle(0);

	popq RIO; // dst

	outunpack_dec();

	popq %r13
	popq %r12
	popq %rbx
	popq %rbp
	popq RMASK

	ret;
#endif

/**********************************************************************
  2-way twofish
 **********************************************************************/
#define RAB0 %rax
#define RCD0 %rbx
#define RAB1 %rcx
#define RCD1 %rdx

#define RAB0d %eax
#define RCD0d %ebx
#define RAB1d %ecx
#define RCD1d %edx

#define RAB0bl %al
#define RCD0bl %bl
#define RAB1bl %cl
#define RCD1bl %dl

#define RAB0bh %ah
#define RCD0bh %bh
#define RAB1bh %ch
#define RCD1bh %dh

#define RT0 %rsi
#define RT1 %rbp

#define RT0d %esi
#define RT1d %ebp

#define RX0 %r8
#define RX1 %r9
#define RY0 %r10
#define RY1 %r11

#define RX0d %r8d
#define RX1d %r9d
#define RY0d %r10d
#define RY1d %r11d

#define g1g2_2(s, Tx0, Tx1, Tx2, Tx3, Ty0, Ty1, Ty2, Ty3, x, y) \
	/* G1,1 && G2,1 */ \
	do16bit_ror(32, mov, xor, Tx0, Tx1, RT0, x ## 0, s ## 0, x ## 0); \
	do16bit_ror(48, mov, xor, Ty1, Ty2, RT0, y ## 0, s ## 0, y ## 0); \
		do16bit_ror(32, mov, xor, Tx0, Tx1, RT0, x ## 1, s ## 1, x ## 1); \
		do16bit_ror(48, mov, xor, Ty1, Ty2, RT0, y ## 1, s ## 1, y ## 1); \
	\
	/* G1,2 && G2,2 */ \
	do16bit_ror(32, xor, xor, Tx2, Tx3, RT0, RT1, s ## 0, x ## 0); \
	do16bit_ror(16, xor, xor, Ty3, Ty0, RT0, RT1, s ## 0, y ## 0); \
		do16bit_ror(32, xor, xor, Tx2, Tx3, RT0, RT1, s ## 1, x ## 1); \
		do16bit_ror(16, xor, xor, Ty3, Ty0, RT0, RT1, s ## 1, y ## 1);

#define encrypt_round2(ab, cd, n) \
	g1g2_2(ab, s0, s1, s2, s3, s0, s1, s2, s3, RX, RY); \
	\
	leal (RX0d, RY0d, 2),		RT0d; \
	addl RY0d,			RX0d; \
	addl k+4*(2*(n)+1)(CTX),	RT0d; \
	addl k+4*(2*(n))(CTX),		RX0d; \
	xorl cd ## 0d,			RX0d; \
	shrq $32,			cd ## 0; \
	roll $1,			cd ## 0d; \
	xorl RT0d,			cd ## 0d; \
	shlq $32,			cd ## 0; \
	rorl $1,			RX0d; \
	orq RX0,			cd ## 0; \
		leal (RX1d, RY1d, 2),		RT0d; \
		addl RY1d,			RX1d; \
		addl k+4*(2*(n)+1)(CTX),	RT0d; \
		addl k+4*(2*(n))(CTX),		RX1d; \
		xorl cd ## 1d,			RX1d; \
		shrq $32,			cd ## 1; \
		roll $1,			cd ## 1d; \
		xorl RT0d,			cd ## 1d; \
		shlq $32,			cd ## 1; \
		rorl $1,			RX1d; \
		orq RX1,			cd ## 1;

#define decrypt_round2(ba, dc, n) \
	g1g2_2(ba, s1, s2, s3, s0, s3, s0, s1, s2, RY, RX); \
	\
	leal (RX0d, RY0d, 2),		RT0d; \
	addl RY0d,			RX0d; \
	addl k+4*(2*(n)+1)(CTX),	RT0d; \
	addl k+4*(2*(n))(CTX),		RX0d; \
	xorl dc ## 0d,			RT0d; \
	shrq $32,			dc ## 0; \
	roll $1,			dc ## 0d; \
	xorl RX0d,			dc ## 0d; \
	shlq $32,			dc ## 0; \
	rorl $1,			RT0d; \
	orq RT0,			dc ## 0; \
		leal (RX1d, RY1d, 2),		RT0d; \
		addl RY1d,			RX1d; \
		addl k+4*(2*(n)+1)(CTX),	RT0d; \
		addl k+4*(2*(n))(CTX),		RX1d; \
		xorl dc ## 1d,			RT0d; \
		shrq $32,			dc ## 1; \
		roll $1,			dc ## 1d; \
		xorl RX1d,			dc ## 1d; \
		shlq $32,			dc ## 1; \
		rorl $1,			RT0d; \
		orq RT0,			dc ## 1;

#define encrypt_cycle2(ab, cd, n) \
	encrypt_round2(ab, cd, n*2); \
	encrypt_round2(cd, ab, (n*2)+1);

#define decrypt_cycle2(ba, dc, n) \
	decrypt_round2(dc, ba, (n*2)+1); \
	decrypt_round2(ba, dc, (n*2));

#define inpack2(in, n, xy, m) \
	movq 4*(n)(in),			xy ## 0; \
	xorq w+4*m(CTX),		xy ## 0; \
	movq 4*(4+(n))(in),		xy ## 1; \
	xorq w+4*m(CTX),		xy ## 1;

#define outunpack2(op, out, n, xy, m) \
	xorq w+4*m(CTX),		xy ## 0; \
	op ## q xy ## 0,		4*(n)(out); \
	xorq w+4*m(CTX),		xy ## 1; \
	op ## q xy ## 1,		4*(4+(n))(out);

#define inpack_enc2() \
	inpack2(RIO, 0, RAB, 0); \
	inpack2(RIO, 2, RCD, 2);

#define outunpack_enc2(op) \
	outunpack2(op, RIO, 0, RCD, 4); \
	outunpack2(op, RIO, 2, RAB, 6);

#define inpack_dec2() \
	inpack2(RIO, 0, RCD, 4); \
	inpack2(RIO, 2, RAB, 6); \
	rorq $32,			RCD0; \
	rorq $32,			RCD1; \
	rorq $32,			RAB0; \
	rorq $32,			RAB1;

#define outunpack_dec2() \
	rorq $32,			RAB0; \
	rorq $32,			RAB1; \
	rorq $32,			RCD0; \
	rorq $32,			RCD1; \
	outunpack2(mov, RIO, 0, RAB, 0); \
	outunpack2(mov, RIO, 2, RCD, 2);

.align 8
.global twofish_enc_blk2
.type   twofish_enc_blk2,@function;

twofish_enc_blk2:
	// input:
	//	%rdi: ctx, CTX
	//	%rsi: dst
	//	%rdx: src
	//	%rcx: bool xor
	pushq %rbp
	pushq %rbx

	pushq %rsi;
	movq %rdx, RIO;

	inpack_enc2();

	encrypt_cycle2(RAB, RCD, 0);
	encrypt_cycle2(RAB, RCD, 1);
	encrypt_cycle2(RAB, RCD, 2);
	encrypt_cycle2(RAB, RCD, 3);
	encrypt_cycle2(RAB, RCD, 4);
	encrypt_cycle2(RAB, RCD, 5);
	encrypt_cycle2(RAB, RCD, 6);
	encrypt_cycle2(RAB, RCD, 7);

	popq RIO;

	outunpack_enc2(mov);

	popq %rbx
	popq %rbp
	ret;

.global twofish_dec_blk2
.type   twofish_dec_blk2,@function;

twofish_dec_blk2:
	// input:
	//	%rdi: ctx, CTX
	//	%rsi: dst
	//	%rdx: src
	pushq %rbp
	pushq %rbx
	pushq %r12
	pushq %r13

	pushq %rsi;
	movq %rdx, RIO;

	inpack_dec2();

	decrypt_cycle2(RAB, RCD, 7);
	decrypt_cycle2(RAB, RCD, 6);
	decrypt_cycle2(RAB, RCD, 5);
	decrypt_cycle2(RAB, RCD, 4);
	decrypt_cycle2(RAB, RCD, 3);
	decrypt_cycle2(RAB, RCD, 2);
	decrypt_cycle2(RAB, RCD, 1);
	decrypt_cycle2(RAB, RCD, 0);

	popq RIO;

	outunpack_dec2();

	popq %r13
	popq %r12
	popq %rbx
	popq %rbp

	ret;

#endif /*x86_64*/
