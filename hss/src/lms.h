/*
 * lms.h
 *
 *  Created on: Mar 2, 2022
 *      Author: Gustavo Banegas
 */

#ifndef LMS_H_
#define LMS_H_

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "randombytes.h"
#include "params.h"
#include "hash.h"
#include "fips202.h"
#include "lms_ots.h"
#include "internal.h"

void keygen_lms_private_key(lms_private_key *sk);

void keygen_lms_public_key(lms_private_key *sk, lms_public_key *pk);

int lms_keygen(unsigned char *sk, unsigned char *pk);

int lms_sign_internal(const unsigned char *message, const size_t input_size,
		lms_private_key *sk, lms_signature *sig);

int lms_sign(const unsigned char *message, const size_t input_size,
		unsigned char *sk, unsigned char *signature);

int lms_verify(const unsigned char *message, const size_t input_size,
		unsigned char *pk, unsigned char *signature);

int lms_verify_internal(const unsigned char *message, const size_t input_size,
		lms_public_key *pk, lms_signature *signature);

#endif /* LMS_H_ */
