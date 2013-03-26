/* aes_asm.S
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

.file "aes_asm.S"
.text

// ctx: uint32 keysched[(AES_MAX_NR + 1) * AES_MAX_NB];
//	uint32 invkeysched[(AES_MAX_NR + 1) * AES_MAX_NB];
//	int Nr;

#define AES_MAX_NR 14
#define AES_MAX_NK 8
#define AES_MAX_NB 4

#define keysched	0
#define invkeysched	((AES_MAX_NR + 1) * AES_MAX_NB * 4)
#define nr		(((AES_MAX_NR + 1) * AES_MAX_NB * 4) * 2)

// aes arrays
.extern aes_E32
#define Emul 4
#define E0 (aes_E32)
#define E1 (aes_E32+4*256)
#define E2 (aes_E32+2*4*256)
#define E3 (aes_E32+3*4*256)

.extern sboxtables
#define Smul 4
#define Sbox0 (sboxtables+(3*4*256))
#define Sbox1 (sboxtables+(2*4*256))
#define Sbox2 (sboxtables+(1*4*256))
#define Sbox3 (sboxtables+(0*4*256))

// registers
#define CTX %rdi
#define RIO0 %r14
#define RIO1 %r15

#define RX0 %rsi
#define RX1 %rbp

#define RX0d %esi
#define RX1d %ebp

#define RX0b %sil
#define RX1b %bpl

// block 64bit
#define RA0 %rax
#define RB0 %rbx
#define RA1 %rcx
#define RB1 %rdx

#define RA0d %eax
#define RB0d %ebx
#define RA1d %ecx
#define RB1d %edx

#define RA0bl %al
#define RB0bl %bl
#define RA1bl %cl
#define RB1bl %dl

#define RA0bh %ah
#define RB0bh %bh
#define RA1bh %ch
#define RB1bh %dh

// new low/high 32bit
#define RLA0 %r14
#define RLB0 %r15
#define RHA0 %r8
#define RHB0 %r9
#define RLA1 %r10
#define RLB1 %r11
#define RHA1 %r12
#define RHB1 %r13

#define RLA0d %r14d
#define RLB0d %r15d
#define RHA0d %r8d
#define RHB0d %r9d
#define RLA1d %r10d
#define RLB1d %r11d
#define RHA1d %r12d
#define RHB1d %r13d

#define RLA0b %r14b
#define RLB0b %r15b
#define RHA0b %r8b
#define RHB0b %r9b
#define RLA1b %r10b
#define RLB1b %r11b
#define RHA1b %r12b
#define RHB1b %r13b

#define do16bit(op, source, tablemul, table1, dest1, table2, dest2, t0, t1) \
	movzbl source ## bh,		t1 ## d; \
	movzbl source ## bl,		t0 ## d; \
	op ## l table1(,t0,tablemul),	dest1 ## d; \
	op ## l table2(,t1,tablemul),	dest2 ## d;

#define do16bit_shr(shf, op, source, tablemul, table1, dest1, table2, dest2, t0, t1) \
	movzbl source ## bl,		t0 ## d; \
	movzbl source ## bh,		t1 ## d; \
	shrq $(shf),			source; \
	op ## l table1(,t0,tablemul),	dest1 ## d; \
	op ## l table2(,t1,tablemul),	dest2 ## d;

#define do16bit_ror(rot, op, source, tablemul, table1, dest1, table2, dest2, t0, t1) \
	movzbl source ## bh,		t1 ## d; \
	movzbl source ## bl,		t0 ## d; \
	rorq $(rot),			source; \
	op ## l table1(,t0,tablemul),	dest1 ## d; \
	op ## l table2(,t1,tablemul),	dest2 ## d;

/********************* ONE BLOCK PART *********************/

#define loadblock1(in, a, b) \
	movq (in ## 0),		a ## 0; \
	movq 8(in ## 0),	b ## 0;

#define saveblock1(out, a, b) \
	movq a ## 0,		(out ## 0); \
	movq b ## 0,		8(out ## 0);

#define xorblock1(out, a, b) \
	xorq a ## 0,		(out); \
	xorq b ## 0,		8(out);

#define addroundkey1(w, a, b) \
	xorq keysched+((w)*4+0)*4(CTX),	a ## 0; \
	xorq keysched+((w)*4+2)*4(CTX),	b ## 0;

#define encround_begin1(w, a, b) \
	/* new_l[0] = E(0, a[0] & 0xFF); */ \
	/* new_h[1] = E(1, a[0] & 0xFF); */ \
	do16bit_ror(48, mov, a ## 0, Emul, E0, RLA0, E1, RHB0, RLA0, RX0); \
	/* new_l[1] = E(0, a[1] & 0xFF); */ \
	/* new_h[0] = E(1, a[1] & 0xFF); */ \
	do16bit_ror(48, mov, b ## 0, Emul, E0, RLB0, E1, RHA0, RLB0, RX1); \
	\
	/* new_h[0] ^= E(2, a[1] & 0xFF); */ \
	/* new_l[0] ^= E(3, a[1] & 0xFF); */ \
	do16bit_shr(32, xor, b ## 0, Emul, E2, RHA0, E3, RLA0, RX0, RX1); \
	/* new_h[1] ^= E(2, a[0] & 0xFF); */ \
	/* new_l[1] ^= E(3, a[0] & 0xFF); */ \
	do16bit_shr(32, xor, a ## 0, Emul, E2, RHB0, E3, RLB0, RX0, RX1); \
	\
	/* new_l[1] ^= E(2, a[0] & 0xFF); */ \
	/* new_h[0] ^= E(3, a[0] & 0xFF); */ \
	do16bit_shr(16, xor, a ## 0, Emul, E2, RLB0, E3, RHA0, RX0, RX1); \
	/* new_l[0] ^= E(2, a[1] & 0xFF); */ \
	/* new_h[1] ^= E(3, a[1] & 0xFF); */ \
	do16bit_shr(16, xor, b ## 0, Emul, E2, RLA0, E3, RHB0, RX0, RX1); \
	\
	/* new_h[0] ^= E(0, a[0] & 0xFF); */ \
	/* new_l[0] ^= E(1, a[0] & 0xFF); */ \
	do16bit(xor, a ## 0, Emul, E0, RHA0, E1, RLA0, RX0, RX1); \
	/* new_h[1] ^= E(0, a[1] & 0xFF); */ \
	/* new_l[1] ^= E(1, a[1] & 0xFF); */ \
	do16bit(xor, b ## 0, Emul, E0, RHB0, E1, RLB0, RX0, RX1);

#define encround_complete_addroundkey1(w, a, b) \
	/* block[0] = ((uint64)new_h[0] << 32) | new_l[0]; */ \
	shlq $32,			RHA0; \
	movq keysched+((w)*4+0)*4(CTX),	a ## 0; \
	xorq RHA0,			a ## 0; \
	xorq RLA0,			a ## 0; \
	\
	/* block[1] = ((uint64)new_h[1] << 32) | new_l[1]; */ \
	shlq $32,			RHB0; \
	movq keysched+((w)*4+2)*4(CTX),	b ## 0; \
	xorq RHB0,			b ## 0; \
	xorq RLB0,			b ## 0;

#define encround1(w, a, b) \
	encround_begin1(w, a, b); \
	encround_complete_addroundkey1(w, a, b);

#define enclastround1(w, a, b) \
	/* new_l[0] = Sbox(3, a[0] & 0xFF); */ \
	/* new_h[1] = Sbox(2, a[0] & 0xFF); */ \
	do16bit_ror(48, mov, a ## 0, Smul, Sbox3, RLA0, Sbox2, RHB0, RLA0, RX0); \
	/* new_l[1] = Sbox(3, a[1] & 0xFF); */ \
	/* new_h[0] = Sbox(2, a[1] & 0xFF); */ \
	do16bit_ror(48, mov, b ## 0, Smul, Sbox3, RLB0, Sbox2, RHA0, RLB0, RX1); \
	\
	/* new_h[0] |= Sbox(1, a[1] & 0xFF); */ \
	/* new_l[0] |= Sbox(0, a[1] & 0xFF); */ \
	do16bit_shr(32, or, b ## 0, Smul, Sbox1, RHA0, Sbox0, RLA0, RX0, RX1); \
	/* new_h[1] |= Sbox(1, a[0] & 0xFF); */ \
	/* new_l[1] |= Sbox(0, a[0] & 0xFF); */ \
	do16bit_shr(32, or, a ## 0, Smul, Sbox1, RHB0, Sbox0, RLB0, RX0, RX1); \
	\
	/* new_l[1] |= Sbox(1, a[0] & 0xFF); */ \
	/* new_h[0] |= Sbox(0, a[0] & 0xFF); */ \
	do16bit_shr(16, or, a ## 0, Smul, Sbox1, RLB0, Sbox0, RHA0, RX0, RX1); \
	/* new_l[0] |= Sbox(1, a[1] & 0xFF); */ \
	/* new_h[1] |= Sbox(0, a[1] & 0xFF); */ \
	do16bit_shr(16, or, b ## 0, Smul, Sbox1, RLA0, Sbox0, RHB0, RX0, RX1); \
	\
	/* new_h[0] |= Sbox(3, a[0] & 0xFF); */ \
	/* new_l[0] |= Sbox(2, a[0] & 0xFF); */ \
	do16bit(or, a ## 0, Smul, Sbox3, RHA0, Sbox2, RLA0, RX0, RX1); \
	/* new_h[1] |= Sbox(3, a[1] & 0xFF); */ \
	/* new_l[1] |= Sbox(2, a[1] & 0xFF); */ \
	do16bit(or, b ## 0, Smul, Sbox3, RHB0, Sbox2, RLB0, RX0, RX1); \
	\
	encround_complete_addroundkey1(w, a, b);

.align 8
.global aes_get_counter_cache
.type   aes_get_counter_cache,@function;

aes_get_counter_cache:
	// input:
	//	%rdi: ctx, CTX
	//	%rsi: ctr_cache (uint32_t[5])
	//	%rdx: iv (big endian)
	pushq %rbp;
	pushq %rbx;
	pushq %r12;
	pushq %r13;
	pushq %r14;
	pushq %r15;
	subq $8, %rsp;

	movq %rsi, (%rsp); // store ctr_cache pointer to stack

	movq %rdx, RIO0; // in1, counter

	loadblock1(RIO, RA, RB);

	/************ partial round 0 ************/

	addroundkey1(0, RA, RB);

	/* new_l[0] = E(0, a[0] & 0xFF); */
	/* new_h[1] = E(1, a[0] & 0xFF); */
	do16bit_ror(16, mov, RA0, Emul, E0, RLA0, E1, RHB0, RX0, RX1);
	/* new_l[1] = E(0, a[1] & 0xFF); */
	/* new_h[0] = E(1, a[1] & 0xFF); */
	do16bit_shr(16, mov, RB0, Emul, E0, RLB0, E1, RHA0, RX0, RX1);

	/* new_l[1] ^= E(2, a[0] & 0xFF); */
	/* new_h[0] ^= E(3, a[0] & 0xFF); */
	do16bit_shr(16, xor, RA0, Emul, E2, RLB0, E3, RHA0, RX0, RX1);
	/* new_l[0] ^= E(2, a[1] & 0xFF); */
	/* new_h[1] ^= E(3, a[1] & 0xFF); */
	do16bit_shr(16, xor, RB0, Emul, E2, RLA0, E3, RHB0, RX0, RX1);

	/* new_h[0] ^= E(0, a[0] & 0xFF); */
	/* new_l[0] ^= E(1, a[0] & 0xFF); */
	do16bit_shr(16, xor, RA0, Emul, E0, RHA0, E1, RLA0, RX0, RX1);
	/* new_h[1] ^= E(0, a[1] & 0xFF); */
	/* new_l[1] ^= E(1, a[1] & 0xFF); */
	do16bit_shr(16, xor, RB0, Emul, E0, RHB0, E1, RLB0, RX0, RX1);

	/* new_h[0] ^= E(2, a[1] & 0xFF); */
	/* new_l[0] ^= 0; ...  E(3, a[1] & 0xFF); */
	movzbl RB0bl,		RX0d;
	xorl E2(,RX0,Emul),	RHA0d;
	/* new_h[1] ^= E(2, a[0] & 0xFF); */
	/* new_l[1] ^= E(3, a[0] & 0xFF); */
	do16bit(xor, RA0, Emul, E2, RHB0, E3, RLB0, RX0, RX1);

	/* block[0] = ((uint64)new_h[0] << 32) | new_l[0]; */
	shlq $32,		RHA0;
	movl RLA0d,		RA0d;
	orq RHA0,		RA0;

	/* block[1] = ((uint64)new_h[1] << 32) | new_l[1]; */
	shlq $32,		RHB0;
	movl RLB0d,		RB0d;
	orq RHB0,		RB0;

	/* ctr_cache[4] = new_l[0]; */
	movq (%rsp),		RX0;
	movl RLA0d,		4*4(RX0);

	/************ partial round 1 ************/

	addroundkey1(1, RA, RB);

	/* block[0] >>= 32); */
	shrq $32,		RA0;

	/* new_l[1] = E(0, a[1] & 0xFF); */
	/* new_h[0] = E(1, a[1] & 0xFF); */
	do16bit_shr(16, mov, RB0, Emul, E0, RLB0, E1, RHA0, RX0, RX1);

	/* new_l[0] ^= E(2, a[1] & 0xFF); */
	/* new_h[1] ^= E(3, a[1] & 0xFF); */
	do16bit_shr(16, mov, RB0, Emul, E2, RLA0, E3, RHB0, RX0, RX1);

	/* new_h[0] ^= E(0, a[0] & 0xFF); */
	/* new_l[0] ^= E(1, a[0] & 0xFF); */
	do16bit_shr(16, xor, RA0, Emul, E0, RHA0, E1, RLA0, RX0, RX1);
	/* new_h[1] ^= E(0, a[1] & 0xFF); */
	/* new_l[1] ^= E(1, a[1] & 0xFF); */
	do16bit_shr(16, xor, RB0, Emul, E0, RHB0, E1, RLB0, RX0, RX1);

	/* new_h[0] ^= E(2, a[1] & 0xFF); */
	/* new_l[0] ^= E(3, a[1] & 0xFF); */
	do16bit(xor, RB0, Emul, E2, RHA0, E3, RLA0, RX0, RX1);
	/* new_h[1] ^= E(2, a[0] & 0xFF); */
	/* new_l[1] ^= E(3, a[0] & 0xFF); */
	do16bit(xor, RA0, Emul, E2, RHB0, E3, RLB0, RX0, RX1);

	/* block[1] = ((uint64)new_h[1] << 32) | new_l[1]; */
	shlq $32,		RHB0;
	movl RLB0d,		RB0d;
	orq RHB0,		RB0;
	/* block[0] = ((uint64)new_h[0] << 32) | new_l[0]; */
	shlq $32,		RHA0;
	movl RLA0d,		RA0d;
	orq RHA0,		RA0;

	/************ partial round 2 ************/
	addroundkey1(2, RA, RB);

	/* ((uint64 *)ctr_cache)[0] = block[0]; */
	/* ((uint64 *)ctr_cache)[2] = block[1]; */
	movq (%rsp), RX0;
	movq RA0, (RX0);
	movq RB0, 8(RX0);

	addq $8, %rsp;
	popq %r15;
	popq %r14;
	popq %r13;
	popq %r12;
	popq %rbx;
	popq %rbp;

	ret;

.align 4
.global aes_enc_blk
.type   aes_enc_blk,@function;

aes_enc_blk:
	// input:
	//	%rdi: ctx,  CTX
	//	%rsi: out... multiple blocks
	//	%rdx: in... multiple blocks
	pushq %rbp;
	pushq %rbx;
	pushq %r12;
	pushq %r13;
	pushq %r14;
	pushq %r15;

	pushq %rsi; // out

	movq %rdx, RIO0; // in1
	loadblock1(RIO, RA, RB);

	addroundkey1(0, RA, RB);
	encround1(1, RA, RB);
	encround1(2, RA, RB);

	jmp .L___enc1_tail;

.align 4
.global aes_enc_blk_ctr_cached
.type   aes_enc_blk_ctr_cached,@function;

aes_enc_blk_ctr_cached:
	// input:
	//	%rdi: ctx, CTX
	//	%rsi: out, two blocks
	//	%rdx: ctr_cache
	//	%cl: counter byte

	pushq %rbp;
	pushq %rbx;
	pushq %r12;
	pushq %r13;
	pushq %r14;
	pushq %r15;
	pushq %rsi; // out

	movq %rdx, %rsi;

	// load data to free registers for use (avoid using RX0 = %rsi)
	movzbl %cl, RLA0d;
	movl 16(%rsi), RA0d;

	// partial round0
	movl keysched+4*4(CTX), RX1d;
	movzbl keysched+15(CTX), RHA0d;

	// E(3, (a[3] ^ key) & 0xFF)
	xorl RHA0d, RLA0d;
	xorl E3(,RLA0,Emul), RA0d;

	movq (%rsi), RHA0;
	movq 8(%rsi), RHB0;

	// partial round 1
	xorl RX1d, RA0d;

	/* block[0] ^=         E(0, b[0] & 0xFF)      ; b[0] >>= 8; */
	/* block[1] ^= (uint64)E(1, b[0] & 0xFF) << 32; b[0] >>= 8; */
	movzbl RA0bl, RX0d;
	movzbl RA0bh, RX1d;
	movl E0(,RX0,Emul), RX0d;
	movl E1(,RX1,Emul), RX1d;
	shrl $16, RA0d;
	shlq $32, RX1;
	xorq RX0, RHA0;
	xorq RX1, RHB0;

	/* block[1] ^=         E(2, b[0] & 0xFF)      ; b[0] >>= 8; */
	/* block[0] ^= (uint64)E(3, b[0] & 0xFF) << 32; */
	movzbl RA0bl, RX0d;
	movzbl RA0bh, RX1d;
	movl E2(,RX0,Emul), RB0d;
	movl E3(,RX1,Emul), RA0d;
	shlq $32, RA0;
	xorq RHA0, RA0;
	xorq RHB0, RB0;

.align 4
.L___enc1_tail:
	encround1(3, RA, RB);
	encround1(4, RA, RB);
	encround1(5, RA, RB);
	encround1(6, RA, RB);
	encround1(7, RA, RB);
	encround1(8, RA, RB);
	encround1(9, RA, RB);

	cmp $12, nr(CTX);
	jae .L___enc1_keylen_over_or_eq_12;

	enclastround1(10, RA, RB);

.align 4
.L___enc1_exit:
	popq RIO0; // out
	saveblock1(RIO, RA, RB);

	popq %r15;
	popq %r14;
	popq %r13;
	popq %r12;
	popq %rbx;
	popq %rbp;

	ret;

.align 4
.L___enc1_keylen_over_or_eq_12:
	je .L___enc1_keylen_eq_12;

	encround1(10, RA, RB);
	encround1(11, RA, RB);
	encround1(12, RA, RB);
	encround1(13, RA, RB);
	enclastround1(14, RA, RB);

	jmp .L___enc1_exit;

.align 4
.L___enc1_keylen_eq_12:

	encround1(10, RA, RB);
	encround1(11, RA, RB);
	enclastround1(12, RA, RB);

	jmp .L___enc1_exit;

/********************* TWO BLOCKS PART *********************/

#define loadblock2(in, a, b) \
	movq (in),		a ## 0; \
	movq 16(in),		a ## 1; \
	movq 8(in),		b ## 0; \
	movq 24(in),		b ## 1;

#define saveblock2(out, a, b) \
	movq a ## 0,		(out); \
	movq a ## 1,		16(out); \
	movq b ## 0,		8(out); \
	movq b ## 1,		24(out);

#define xorblock2(out, a, b) \
	xorq a ## 0,		(out); \
	xorq a ## 1,		16(out); \
	xorq b ## 0,		8(out); \
	xorq b ## 1,		24(out);

#define addroundkey2(w, a, b) \
	xorq keysched+((w)*4+0)*4(CTX),	a ## 0; \
	xorq keysched+((w)*4+0)*4(CTX),	a ## 1; \
	xorq keysched+((w)*4+2)*4(CTX),	b ## 0; \
	xorq keysched+((w)*4+2)*4(CTX),	b ## 1;

/* Too much interleaving here kills performance, don't do it! */
#define encround_begin2(a, b) \
	/* new_l[0] = E(0, a[0] & 0xFF); */ \
	/* new_h[1] = E(1, a[0] & 0xFF); */ \
	do16bit_ror(48, mov, a ## 0, Emul, E0, RLA0, E1, RHB0, RLA0, RX0); \
	/* new_l[1] = E(0, a[1] & 0xFF); */ \
	/* new_h[0] = E(1, a[1] & 0xFF); */ \
	do16bit_ror(48, mov, b ## 0, Emul, E0, RLB0, E1, RHA0, RLB0, RX1); \
	/* new_h[0] ^= E(2, a[1] & 0xFF); */ \
	/* new_l[0] ^= E(3, a[1] & 0xFF); */ \
	do16bit_shr(32, xor, b ## 0, Emul, E2, RHA0, E3, RLA0, RX0, RX1); \
	/* new_h[1] ^= E(2, a[0] & 0xFF); */ \
	/* new_l[1] ^= E(3, a[0] & 0xFF); */ \
	do16bit_shr(32, xor, a ## 0, Emul, E2, RHB0, E3, RLB0, RX0, RX1); \
	/* new_l[1] ^= E(2, a[0] & 0xFF); */ \
	/* new_h[0] ^= E(3, a[0] & 0xFF); */ \
	do16bit_shr(16, xor, a ## 0, Emul, E2, RLB0, E3, RHA0, RX0, RX1); \
	/* new_l[0] ^= E(2, a[1] & 0xFF); */ \
	/* new_h[1] ^= E(3, a[1] & 0xFF); */ \
	do16bit_shr(16, xor, b ## 0, Emul, E2, RLA0, E3, RHB0, RX0, RX1); \
	/* new_h[0] ^= E(0, a[0] & 0xFF); */ \
	/* new_l[0] ^= E(1, a[0] & 0xFF); */ \
	do16bit(xor, a ## 0, Emul, E0, RHA0, E1, RLA0, RX0, RX1); \
	/* new_h[1] ^= E(0, a[1] & 0xFF); */ \
	/* new_l[1] ^= E(1, a[1] & 0xFF); */ \
	do16bit(xor, b ## 0, Emul, E0, RHB0, E1, RLB0, RX0, RX1); \
		/* new_l[0] = E(0, a[0] & 0xFF); */ \
		/* new_h[1] = E(1, a[0] & 0xFF); */ \
		do16bit_ror(48, mov, a ## 1, Emul, E0, RLA1, E1, RHB1, RLA1, RX0); \
		/* new_l[1] = E(0, a[1] & 0xFF); */ \
		/* new_h[0] = E(1, a[1] & 0xFF); */ \
		do16bit_ror(48, mov, b ## 1, Emul, E0, RLB1, E1, RHA1, RLB1, RX1); \
		/* new_h[0] ^= E(2, a[1] & 0xFF); */ \
		/* new_l[0] ^= E(3, a[1] & 0xFF); */ \
		do16bit_shr(32, xor, b ## 1, Emul, E2, RHA1, E3, RLA1, RX0, RX1); \
		/* new_h[1] ^= E(2, a[0] & 0xFF); */ \
		/* new_l[1] ^= E(3, a[0] & 0xFF); */ \
		do16bit_shr(32, xor, a ## 1, Emul, E2, RHB1, E3, RLB1, RX0, RX1); \
		/* new_l[1] ^= E(2, a[0] & 0xFF); */ \
		/* new_h[0] ^= E(3, a[0] & 0xFF); */ \
		do16bit_shr(16, xor, a ## 1, Emul, E2, RLB1, E3, RHA1, RX0, RX1); \
		/* new_l[0] ^= E(2, a[1] & 0xFF); */ \
		/* new_h[1] ^= E(3, a[1] & 0xFF); */ \
		do16bit_shr(16, xor, b ## 1, Emul, E2, RLA1, E3, RHB1, RX0, RX1); \
		/* new_h[0] ^= E(0, a[0] & 0xFF); */ \
		/* new_l[0] ^= E(1, a[0] & 0xFF); */ \
		do16bit(xor, a ## 1, Emul, E0, RHA1, E1, RLA1, RX0, RX1); \
		/* new_h[1] ^= E(0, a[1] & 0xFF); */ \
		/* new_l[1] ^= E(1, a[1] & 0xFF); */ \
		do16bit(xor, b ## 1, Emul, E0, RHB1, E1, RLB1, RX0, RX1);

#define encround_complete_addroundkey2(w, a, b) \
	/* block[0] = ((uint64)new_h[0] << 32) | new_l[0]; */ \
	shlq $32,			RHA0; \
	movq keysched+((w)*4+0)*4(CTX),	a ## 0; \
	orq RHA0,			RLA0; \
	xorq RLA0,			a ## 0; \
	\
	/* block[1] = ((uint64)new_h[1] << 32) | new_l[1]; */ \
	shlq $32,			RHB0; \
	movq keysched+((w)*4+2)*4(CTX),	b ## 0; \
	orq RHB0,			RLB0; \
	xorq RLB0,			b ## 0; \
	\
		/* block[0] = ((uint64)new_h[0] << 32) | new_l[0]; */ \
		shlq $32,			RHA1; \
		movq keysched+((w)*4+0)*4(CTX),	a ## 1; \
		orq RHA1,			RLA1; \
		xorq RLA1,			a ## 1; \
		\
		/* block[1] = ((uint64)new_h[1] << 32) | new_l[1]; */ \
		shlq $32,			RHB1; \
		movq keysched+((w)*4+2)*4(CTX),	b ## 1; \
		orq RHB1,			RLB1; \
		xorq RLB1,			b ## 1;

#define encround2(w, a, b) \
	encround_begin2(a, b); \
	encround_complete_addroundkey2(w, a, b);

#define enclastround2(w, a, b) \
	/* new_l[0] = Sbox(3, a[0] & 0xFF); */ \
	/* new_h[1] = Sbox(2, a[0] & 0xFF); */ \
	do16bit_ror(48, mov, a ## 0, Smul, Sbox3, RLA0, Sbox2, RHB0, RX0, RX1); \
	/* new_l[1] = Sbox(3, a[1] & 0xFF); */ \
	/* new_h[0] = Sbox(2, a[1] & 0xFF); */ \
	do16bit_ror(48, mov, b ## 0, Smul, Sbox3, RLB0, Sbox2, RHA0, RX0, RX1); \
	/* new_h[0] |= Sbox(1, a[1] & 0xFF); */ \
	/* new_l[0] |= Sbox(0, a[1] & 0xFF); */ \
	do16bit_shr(32, or, b ## 0, Smul, Sbox1, RHA0, Sbox0, RLA0, RX0, RX1); \
	/* new_h[1] |= Sbox(1, a[0] & 0xFF); */ \
	/* new_l[1] |= Sbox(0, a[0] & 0xFF); */ \
	do16bit_shr(32, or, a ## 0, Smul, Sbox1, RHB0, Sbox0, RLB0, RX0, RX1); \
	/* new_l[1] |= Sbox(1, a[0] & 0xFF); */ \
	/* new_h[0] |= Sbox(0, a[0] & 0xFF); */ \
	do16bit_shr(16, or, a ## 0, Smul, Sbox1, RLB0, Sbox0, RHA0, RX0, RX1); \
	/* new_l[0] |= Sbox(1, a[1] & 0xFF); */ \
	/* new_h[1] |= Sbox(0, a[1] & 0xFF); */ \
	do16bit_shr(16, or, b ## 0, Smul, Sbox1, RLA0, Sbox0, RHB0, RX0, RX1); \
		/* new_l[0] = Sbox(3, a[0] & 0xFF); */ \
		/* new_h[1] = Sbox(2, a[0] & 0xFF); */ \
		do16bit_ror(48, mov, a ## 1, Smul, Sbox3, RLA1, Sbox2, RHB1, RX0, RX1); \
		/* new_l[1] = Sbox(3, a[1] & 0xFF); */ \
		/* new_h[0] = Sbox(2, a[1] & 0xFF); */ \
		do16bit_ror(48, mov, b ## 1, Smul, Sbox3, RLB1, Sbox2, RHA1, RX0, RX1); \
		/* new_h[0] |= Sbox(1, a[1] & 0xFF); */ \
		/* new_l[0] |= Sbox(0, a[1] & 0xFF); */ \
		do16bit_shr(32, or, b ## 1, Smul, Sbox1, RHA1, Sbox0, RLA1, RX0, RX1); \
		/* new_h[1] |= Sbox(1, a[0] & 0xFF); */ \
		/* new_l[1] |= Sbox(0, a[0] & 0xFF); */ \
		do16bit_shr(32, or, a ## 1, Smul, Sbox1, RHB1, Sbox0, RLB1, RX0, RX1); \
		/* new_l[1] |= Sbox(1, a[0] & 0xFF); */ \
		/* new_h[0] |= Sbox(0, a[0] & 0xFF); */ \
		do16bit_shr(16, or, a ## 1, Smul, Sbox1, RLB1, Sbox0, RHA1, RX0, RX1); \
		/* new_l[0] |= Sbox(1, a[1] & 0xFF); */ \
		/* new_h[1] |= Sbox(0, a[1] & 0xFF); */ \
		do16bit_shr(16, or, b ## 1, Smul, Sbox1, RLA1, Sbox0, RHB1, RX0, RX1); \
	\
	/* new_h[0] |= Sbox(3, a[0] & 0xFF); */ \
	/* new_l[0] |= Sbox(2, a[0] & 0xFF); */ \
	do16bit(or, a ## 0, Smul, Sbox3, RHA0, Sbox2, RLA0, RX0, RX1); \
	/* new_h[1] |= Sbox(3, a[1] & 0xFF); */ \
	/* new_l[1] |= Sbox(2, a[1] & 0xFF); */ \
	do16bit(or, b ## 0, Smul, Sbox3, RHB0, Sbox2, RLB0, RX0, RX1); \
	\
		/* new_h[0] |= Sbox(3, a[0] & 0xFF); */ \
		/* new_l[0] |= Sbox(2, a[0] & 0xFF); */ \
		do16bit(or, a ## 1, Smul, Sbox3, RHA1, Sbox2, RLA1, RX0, RX1); \
		/* new_h[1] |= Sbox(3, a[1] & 0xFF); */ \
		/* new_l[1] |= Sbox(2, a[1] & 0xFF); */ \
		do16bit(or, b ## 1, Smul, Sbox3, RHB1, Sbox2, RLB1, RX0, RX1); \
		\
	encround_complete_addroundkey2(w, a, b);

.align 4
.global aes_enc_blk2
.type   aes_enc_blk2,@function;

aes_enc_blk2:
	// input:
	//	%rdi: ctx,  CTX
	//	%rsi: out: [2n: 16 bytes][2n+1: 16 bytes]...
	//	%rdx: in: [2n: 16 bytes][2n+1: 16 bytes]...

	pushq %rbp;
	pushq %rbx;
	pushq %r12;
	pushq %r13;
	pushq %r14;
	pushq %r15;

	pushq %rsi; /* out */

	movq %rdx, RIO0; // in
	loadblock2(RIO0, RA, RB);

	addroundkey2(0, RA, RB);
	encround2(1, RA, RB);
	encround2(2, RA, RB);
	jmp .L___enc2_tail;

.align 4
.global aes_enc_blk2_ctr_cached
.type   aes_enc_blk2_ctr_cached,@function;

aes_enc_blk2_ctr_cached:
	// input:
	//	%rdi: ctx, CTX
	//	%rsi: out, two blocks
	//	%rdx: ctr_cache
	//	%cl: counter byte

	pushq %rbp;
	pushq %rbx;
	pushq %r12;
	pushq %r13;
	pushq %r14;
	pushq %r15;
	pushq %rsi; // out

	movq %rdx, %rsi;

	// load data to free registers for use (avoid using RX0 = %rsi)
	movzbl %cl, RLA0d;
	movl 16(%rsi), RA0d;
		leal 1(RLA0d), RLA1d;
		movl RA0d, RA1d;

	// partial round0
	movl keysched+4*4(CTX), RX1d;
	movzbl keysched+15(CTX), RHA0d;

	// E(3, (a[3] ^ key) & 0xFF)
	xorl RHA0d, RLA0d;
	xorl E3(,RLA0,Emul), RA0d;
		xorl RHA0d, RLA1d;
		xorl E3(,RLA1,Emul), RA1d;

	movq (%rsi), RHA0;
	movq 8(%rsi), RHB0;
		movq RHA0, RHA1;
		movq RHB0, RHB1;

	// partial round 1
	xorl RX1d, RA0d;
		xorl RX1d, RA1d;

	/* block[0] ^=         E(0, b[0] & 0xFF)      ; b[0] >>= 8; */
	/* block[1] ^= (uint64)E(1, b[0] & 0xFF) << 32; b[0] >>= 8; */
	movzbl RA0bl, RX0d;
	movzbl RA0bh, RX1d;
	movl E0(,RX0,Emul), RX0d;
	movl E1(,RX1,Emul), RX1d;
	shrl $16, RA0d;
	shlq $32, RX1;
	xorq RX0, RHA0;
	xorq RX1, RHB0;
		movzbl RA1bl, RX0d;
		movzbl RA1bh, RX1d;
		movl E0(,RX0,Emul), RX0d;
		movl E1(,RX1,Emul), RX1d;
		shrl $16, RA1d;
		shlq $32, RX1;
		xorq RX0, RHA1;
		xorq RX1, RHB1;

	/* block[1] ^=         E(2, b[0] & 0xFF)      ; b[0] >>= 8; */
	/* block[0] ^= (uint64)E(3, b[0] & 0xFF) << 32; */
	movzbl RA0bl, RX0d;
	movzbl RA0bh, RX1d;
	movl E2(,RX0,Emul), RB0d;
	movl E3(,RX1,Emul), RA0d;
	shlq $32, RA0;
	xorq RHA0, RA0;
	xorq RHB0, RB0;
		movzbl RA1bl, RX0d;
		movzbl RA1bh, RX1d;
		movl E2(,RX0,Emul), RB1d;
		movl E3(,RX1,Emul), RA1d;
		shlq $32, RA1;
		xorq RHA1, RA1;
		xorq RHB1, RB1;

.align 4
.L___enc2_tail:
	encround2(3, RA, RB);
	encround2(4, RA, RB);
	encround2(5, RA, RB);
	encround2(6, RA, RB);
	encround2(7, RA, RB);
	encround2(8, RA, RB);
	encround2(9, RA, RB);

	cmp $12, nr(CTX);
	jae .L___enc2_keylen_over_or_eq_12;

	enclastround2(10, RA, RB);

.align 4
.L___enc2_exit:
	popq RIO0; // out
	saveblock2(RIO0, RA, RB);

	popq %r15;
	popq %r14;
	popq %r13;
	popq %r12;
	popq %rbx;
	popq %rbp;

	ret;

.align 4
.L___enc2_keylen_over_or_eq_12:
	je .L___enc2_keylen_eq_12;

	encround2(10, RA, RB);
	encround2(11, RA, RB);
	encround2(12, RA, RB);
	encround2(13, RA, RB);
	enclastround2(14, RA, RB);

	jmp .L___enc2_exit;

.align 4
.L___enc2_keylen_eq_12:
	encround2(10, RA, RB);
	encround2(11, RA, RB);
	enclastround2(12, RA, RB);

	jmp .L___enc2_exit;

#endif
