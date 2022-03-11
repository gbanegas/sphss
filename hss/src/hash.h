/*
 * hash.h
 *
 *  Created on: Mar 7, 2022
 *      Author: Gustavo Banegas
 */

#ifndef HASH_H_
#define HASH_H_

#include <stddef.h>
#include "fips202.h"

void hash(const unsigned char *input, size_t inlen, unsigned char *output);

void hash_update(const unsigned char *input, const size_t inlen,
		sha3_256incctx *ctx);
#endif /* HASH_H_ */
