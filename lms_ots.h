/*
 * lms_ots.h
 *
 *  Created on: Mar 2, 2022
 *      Author: Gustavo Banegas
 */

#ifndef LMS_OTS_H_
#define LMS_OTS_H_
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "randombytes.h"
#include "params.h"
#include "hash.h"
#include "fips202.h"
#include "lms_utils.h"


int lms_ots_keygen(unsigned char *sk, unsigned char *pk);

int lms_ots_sign(unsigned char *message, size_t input_size, unsigned char *sk,
		unsigned char *signature);

int lms_ots_sign_internal(const unsigned char *message, const size_t input_size,
		lmots_private_key *private_key, lmots_signature *sig);

int lms_ots_verify(unsigned char *message, size_t input_size, unsigned char *pk,
		unsigned char *signature);

void gen_lmots_public_key(lmots_private_key *sk, lmots_public_key *pk);

#endif /* LMS_OTS_H_ */
