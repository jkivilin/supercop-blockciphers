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

/**********************************************************************
  4-way blowfish, four blocks parallel
 **********************************************************************/

/* F() for 4-way. Slower when used alone/1-way, but faster when used
 * parallel/4-way (tested on AMD Phenom II & Intel Xeon E7330)...
 *
 * ... but results with SuperCop say the opposite. Your mileage may vary.
 */
#define F4(x) \
	movzbl x ## bh,		RT1d; \
	movzbl x ## bl,		RT3d; \
	rorq $16,		x; \
	movzbl x ## bh,		RT0d; \
	movzbl x ## bl,		RT2d; \
	rorq $16,		x; \
	movl s0(CTX,RT0,4),	RT0d; \
	addl s1(CTX,RT2,4),	RT0d; \
	xorl s2(CTX,RT1,4),	RT0d; \
	addl s3(CTX,RT3,4),	RT0d; \
	xorq RT0,		x;

#define add_preloaded_roundkey4() \
	xorq RKEY,		RX0; \
	xorq RKEY,		RX1; \
	xorq RKEY,		RX2; \
	xorq RKEY,		RX3;

#define preload_roundkey_enc(n) \
	movq p+4*(n)(CTX),	RKEY;

#define add_roundkey_enc4(n) \
	add_preloaded_roundkey4(); \
	preload_roundkey_enc(n + 2);

#define round_enc4(n) \
	add_roundkey_enc4(n); \
	\
	F4(RX0); \
	F4(RX1); \
	F4(RX2); \
	F4(RX3); \
	\
	F4(RX0); \
	F4(RX1); \
	F4(RX2); \
	F4(RX3);

#define preload_roundkey_dec(n) \
	movq p+4*((n)-1)(CTX),	RKEY; \
	rorq $32,		RKEY;

#define add_roundkey_dec4(n) \
	add_preloaded_roundkey4(); \
	preload_roundkey_dec(n - 2);

#define round_dec4(n) \
	add_roundkey_dec4(n); \
	\
	F4(RX0); \
	F4(RX1); \
	F4(RX2); \
	F4(RX3); \
	\
	F4(RX0); \
	F4(RX1); \
	F4(RX2); \
	F4(RX3);

#define read_block4() \
	movq (RIO),		RX0; \
	rorq $32,		RX0; \
	bswapq 			RX0; \
	\
	movq 8(RIO),		RX1; \
	rorq $32,		RX1; \
	bswapq 			RX1; \
	\
	movq 16(RIO),		RX2; \
	rorq $32,		RX2; \
	bswapq 			RX2; \
	\
	movq 24(RIO),		RX3; \
	rorq $32,		RX3; \
	bswapq 			RX3;

#define write_block4() \
	bswapq 			RX0; \
	movq RX0,		(RIO); \
	\
	bswapq 			RX1; \
	movq RX1,		8(RIO); \
	\
	bswapq 			RX2; \
	movq RX2,		16(RIO); \
	\
	bswapq 			RX3; \
	movq RX3,		24(RIO);

.align 8
.global blowfish_enc_blk4
.type   blowfish_enc_blk4,@function;

blowfish_enc_blk4:
	/* input:
	 *	%rdi: ctx, CTX
	 *	%rsi: dst
	 *	%rdx: src
	 */
	pushq %rbp;
	pushq %rbx;

	preload_roundkey_enc(0);

	movq %rsi, %r11;
	movq %rdx, RIO;

	read_block4();

	round_enc4(0);
	round_enc4(2);
	round_enc4(4);
	round_enc4(6);
	round_enc4(8);
	round_enc4(10);
	round_enc4(12);
	round_enc4(14);
	add_preloaded_roundkey4();

	movq %r11, RIO;
	write_block4();

	popq %rbx;
	popq %rbp;
	ret;

.align 8
.global blowfish_dec_blk4
.type   blowfish_dec_blk4,@function;

blowfish_dec_blk4:
	/* input:
	 *	%rdi: ctx, CTX
	 *	%rsi: dst
	 *	%rdx: src
	 */
	pushq %rbp;
	pushq %rbx;
	preload_roundkey_dec(17);

	movq %rsi, %r11;
	movq %rdx, RIO;

	read_block4();

	round_dec4(17);
	round_dec4(15);
	round_dec4(13);
	round_dec4(11);
	round_dec4(9);
	round_dec4(7);
	round_dec4(5);
	round_dec4(3);
	add_preloaded_roundkey4();

	movq %r11, RIO;
	write_block4();

	popq %rbx;
	popq %rbp;

	ret;

#endif

