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
