/*
 * hash.c
 *
 *  Created on: Mar 7, 2022
 *      Author: Gustavo Banegas
 */

#include "hash.h"

void hash(const unsigned char *input, size_t inlen, unsigned char *output) {
	sha3_256(output, input, inlen);
}

void hash_update(const unsigned char *input, const size_t inlen,
		sha3_256incctx *ctx) {

	sha3_256_inc_absorb(ctx, input, inlen);

}
