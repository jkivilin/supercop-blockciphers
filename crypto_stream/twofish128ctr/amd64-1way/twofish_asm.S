/* twofish_asm.S
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

#define g1g2(s, Tx0, Tx1, Tx2, Tx3, Ty0, Ty1, Ty2, Ty3, x, y) \
	/* G1,1 && G2,1 */ \
	do16bit_ror(32, mov, xor, Tx0, Tx1, RT0, x ## 0, s ## 0, x ## 0); \
	do16bit_ror(48, mov, xor, Ty1, Ty2, RT0, y ## 0, s ## 0, y ## 0); \
	\
	/* G1,2 && G2,2 */ \
	do16bit_ror(32, xor, xor, Tx2, Tx3, RT0, RT1, s ## 0, x ## 0); \
	do16bit_ror(16, xor, xor, Ty3, Ty0, RT0, RT1, s ## 0, y ## 0);

#define encrypt_round(ab, cd, n) \
	g1g2(ab, s0, s1, s2, s3, s0, s1, s2, s3, RX, RY); \
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
	orq RX0,			cd ## 0;

#define decrypt_round(ba, dc, n) \
	g1g2(ba, s1, s2, s3, s0, s3, s0, s1, s2, RY, RX); \
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
	orq RT0,			dc ## 0;

#define encrypt_cycle(ab, cd, n) \
	encrypt_round(ab, cd, n*2); \
	encrypt_round(cd, ab, (n*2)+1);

#define decrypt_cycle(ba, dc, n) \
	decrypt_round(dc, ba, (n*2)+1); \
	decrypt_round(ba, dc, (n*2));

#define inpack(in, n, xy, m) \
	movq 4*(n)(in),			xy ## 0; \
	xorq w+4*m(CTX),		xy ## 0;

#define outunpack(op, out, n, xy, m) \
	xorq w+4*m(CTX),		xy ## 0; \
	op ## q xy ## 0,		4*(n)(out);

#define inpack_enc() \
	inpack(RIO, 0, RAB, 0); \
	inpack(RIO, 2, RCD, 2);

#define outunpack_enc(op) \
	outunpack(op, RIO, 0, RCD, 4); \
	outunpack(op, RIO, 2, RAB, 6);

#define inpack_dec() \
	inpack(RIO, 0, RCD, 4); \
	inpack(RIO, 2, RAB, 6); \
	rorq $32,			RCD0; \
	rorq $32,			RAB0;

#define outunpack_dec() \
	rorq $32,			RAB0; \
	rorq $32,			RCD0; \
	outunpack(mov, RIO, 0, RAB, 0); \
	outunpack(mov, RIO, 2, RCD, 2);

.align 8
.global twofish_enc_blk
.type   twofish_enc_blk,@function;

twofish_enc_blk:
	// input:
	//	%rdi: ctx, CTX
	//	%rsi: dst
	//	%rdx: src
	pushq %rbp
	pushq %rbx

	pushq %rsi;
	movq %rdx, RIO;

	inpack_enc();

	encrypt_cycle(RAB, RCD, 0);
	encrypt_cycle(RAB, RCD, 1);
	encrypt_cycle(RAB, RCD, 2);
	encrypt_cycle(RAB, RCD, 3);
	encrypt_cycle(RAB, RCD, 4);
	encrypt_cycle(RAB, RCD, 5);
	encrypt_cycle(RAB, RCD, 6);
	encrypt_cycle(RAB, RCD, 7);

	popq RIO;

	outunpack_enc(mov);

	popq %rbx
	popq %rbp
	ret;

.global twofish_dec_blk
.type   twofish_dec_blk,@function;

twofish_dec_blk:
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

	inpack_dec();

	decrypt_cycle(RAB, RCD, 7);
	decrypt_cycle(RAB, RCD, 6);
	decrypt_cycle(RAB, RCD, 5);
	decrypt_cycle(RAB, RCD, 4);
	decrypt_cycle(RAB, RCD, 3);
	decrypt_cycle(RAB, RCD, 2);
	decrypt_cycle(RAB, RCD, 1);
	decrypt_cycle(RAB, RCD, 0);

	popq RIO;

	outunpack_dec();

	popq %r13
	popq %r12
	popq %rbx
	popq %rbp

	ret;

#endif /*x86_64*/
