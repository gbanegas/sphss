/*
 * hash.h
 *
 *  Created on: Mar 7, 2022
 *      Author: Gustavo Banegas
 */

#ifndef HASH_H_
#define HASH_H_

#include <stddef.h>
//#include "fips202.h"
#include "fips180.h"

void hash_init(sha256_ctx *ctx);

void hash(const unsigned char *input, size_t inlen, unsigned char *output);

void hash_update(const unsigned char *input, const size_t inlen,
		sha256_ctx *ctx);

void hash_finish(sha256_ctx *ctx, unsigned char *output);
#endif /* HASH_H_ */
