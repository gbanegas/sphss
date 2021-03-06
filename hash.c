/*
 * hash.c
 *
 *  Created on: Mar 7, 2022
 *      Author: Gustavo Banegas
 */

#include "hash.h"

void hash_init(sha256_ctx *ctx) {
	sha256_init(ctx);
}

void hash(const unsigned char *input, size_t inlen, unsigned char *output) {
	sha256(input, inlen, output);
	//sha3_256(output, input, inlen);
}

void hash_update(const unsigned char *input, const size_t inlen,
		sha256_ctx *ctx) {

	sha256_update(ctx, input, inlen);
	//sha3_256_inc_absorb(ctx, input, inlen);

}

void hash_finish(sha256_ctx *ctx, unsigned char *output) {
	sha256_final(ctx, output);
}
