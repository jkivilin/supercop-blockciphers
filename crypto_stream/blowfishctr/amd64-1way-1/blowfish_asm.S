/* blowfish_asm.S
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

.file "blowfish_asm.S"
.text
/* structure of crypto context */
#define p	0
#define s0	((16 + 2) * 4)
#define s1	((16 + 2 + (1 * 256)) * 4)
#define s2	((16 + 2 + (2 * 256)) * 4)
#define s3	((16 + 2 + (3 * 256)) * 4)

/* register macros */
#define CTX %rdi
#define RIO %rsi

#define RX0 %rax
#define RX1 %rbx
#define RX2 %rcx
#define RX3 %rdx

#define RX0d %eax
#define RX1d %ebx
#define RX2d %ecx
#define RX3d %edx

#define RX0bl %al
#define RX1bl %bl
#define RX2bl %cl
#define RX3bl %dl

#define RX0bh %ah
#define RX1bh %bh
#define RX2bh %ch
#define RX3bh %dh

#define RT0 %rbp
#define RT1 %rsi
#define RT2 %r8
#define RT3 %r9

#define RT0d %ebp
#define RT1d %esi
#define RT2d %r8d
#define RT3d %r9d

#define RKEY %r10

/***********************************************************************
 * 1-way blowfish
 ***********************************************************************/
#define F() \
	rorq $16,		RX0; \
	movzbl RX0bh,		RT0d; \
	movzbl RX0bl,		RT1d; \
	rolq $16,		RX0; \
	movl s0(CTX,RT0,4),	RT0d; \
	addl s1(CTX,RT1,4),	RT0d; \
	movzbl RX0bh,		RT1d; \
	movzbl RX0bl,		RT2d; \
	rolq $32,		RX0; \
	xorl s2(CTX,RT1,4),	RT0d; \
	addl s3(CTX,RT2,4),	RT0d; \
	xorq RT0,		RX0;

#define add_roundkey_enc(n) \
	xorq p+4*(n)(CTX), 	RX0;

#define round_enc(n) \
	add_roundkey_enc(n); \
	\
	F(); \
	F();

#define add_roundkey_dec(n) \
	movq p+4*(n-1)(CTX),	RT0; \
	rorq $32,		RT0; \
	xorq RT0,		RX0;

#define round_dec(n) \
	add_roundkey_dec(n); \
	\
	F(); \
	F();

#define read_block() \
	movq (RIO), 		RX0; \
	rorq $32, 		RX0; \
	bswapq 			RX0;

#define write_block() \
	bswapq 			RX0; \
	movq RX0, 		(RIO);

.align 8
.global blowfish_enc_blk
.type   blowfish_enc_blk,@function;

blowfish_enc_blk:
	/* input:
	 *	%rdi: ctx, CTX
	 *	%rsi: dst
	 *	%rdx: src
	 *	%rcx: bool, if true: xor output
	 */
	movq %rbp, %r11;

	movq %rsi, %r10;
	movq %rdx, RIO;

	read_block();

	round_enc(0);
	round_enc(2);
	round_enc(4);
	round_enc(6);
	round_enc(8);
	round_enc(10);
	round_enc(12);
	round_enc(14);
	add_roundkey_enc(16);

	movq %r11, %rbp;

	movq %r10, RIO;
	write_block();

	ret;

.align 8
.global blowfish_dec_blk
.type   blowfish_dec_blk,@function;

blowfish_dec_blk:
	/* input:
	 *	%rdi: ctx, CTX
	 *	%rsi: dst
	 *	%rdx: src
	 */
	movq %rbp, %r11;

	movq %rsi, %r10;
	movq %rdx, RIO;

	read_block();

	round_dec(17);
	round_dec(15);
	round_dec(13);
	round_dec(11);
	round_dec(9);
	round_dec(7);
	round_dec(5);
	round_dec(3);
	add_roundkey_dec(1);

	movq %r10, RIO;
	write_block();

	movq %r11, %rbp;

	ret;

#endif

