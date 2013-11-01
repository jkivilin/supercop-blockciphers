supercop-blockciphers
=====================

This repository contains fast block cipher implementations (for x86-64) in counter-mode for the SUPERCOP cryptographic benchmarking framework. These are the artifacts of the implementation/integration part of my Master's Thesis "Block Ciphers: Fast Implementations on x86-64 Architecture". Fulltext is available at: http://koti.mbnet.fi/axh/mastersthesis/

SUPERCOP: http://bench.cr.yp.to/supercop.html

Installation: Copy contents of crypto_stream/ of this repository to crypto_stream/ in SUPERCOP package.

Licensing note: Some implementations contain GPLv2 licensed code, while other are mix of permissive licenses (ISC, new BSD, MIT, public-domain).

-Jussi Kivilinna

beyond_master branch
====================

This branch contains new implementations, that were not included in Master's Thesis.

New implementations so far:
 - Camellia AES-NI/AVX2
 - Serpent AVX2 (by Johannes Götzfried)
 - Twofish AVX2 (using vpgatherdd)
 - Twofish AVX2 (without vpgatherdd, based on AVX impl.)
 - Blowfish AVX2 (using vpgatherdd)

Results on Intel i5-4570 (haswell):

 - Blowfish
   + Improved 16-way word-sliced with table look-ups (AVX): 8.11 cycles/byte
   + 4-way table look-up: 8.55 cycles/byte
   + Götzfried's 16-way word-sliced with table look-ups (AVX): 10.35 cycles/byte
   + 32-way word-sliced (AVX2, vpgatherdd): 12.95 cycles/byte
   + 1-way table look-up: 24.26 cycles/byte
   + OpenSSL: 26.59 cycles/byte
   + Crypto++: 28.07 cycles/byte
 - AES
   + Crypto++ (AES-NI): 0.82 cycles/byte
   + 8-way AVX bit-sliced:  6.16 cycles/byte
   + 8-way SSSE3 bit-sliced (Käsper & Schwabe): 6.36 cycles/byte
   + 2-way table look-up: 7.85 cycles/byte
   + 1-way table look-up: 10.87 cycles/byte
 - Camellia
   + 32-way byte-sliced with (AVX2 & AES-NI): 3.74 cycles/byte
   + 16-way byte-sliced with (AVX & AES-NI): 5.92 cycles/byte
   + 2-way table look-up: 10.37 cycles/byte
   + 1-way table look-up: 16.72 cycles/byte
   + OpenSSL: 18.91 cycles/byte
   + Crypto++: 22.12 cycles/byte
 - Serpent
   + Götzfried's 16-way word-sliced (AVX2): 5.18 cycles/byte
   + Götzfried's 8-way word-sliced (AVX): 10.29 cycles/byte
   + 8-way word-sliced (SSE2): 10.47 cycles/byte
   + C impl. from Linux kernel: 34.18 cycles/byte
 - Twofish
   + 16-way word-sliced with table look-ups (AVX2, without vpgatherdd): 8.37 cycles/byte
   + Improved 8-way word-sliced with table look-ups (AVX): 8.81 cycles/byte
   + Götzfried's 16-way word-sliced with table look-ups (AVX): 10.33 cycles/byte
   + 3-way table look-up: 11.24 cycles/byte
   + 2-way table look-up: 12.10 cycles/byte
   + 16-way word-sliced (AVX2, vpgatherdd): 12.73 cycles/byte
   + Assembly impl. from Linux kernel: 16.85 cycles/byte
   + Crypto++: 18.10 cycles/byte
   + 1-way table look-up: 18.71 cycles/byte
