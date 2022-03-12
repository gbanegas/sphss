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
#include "errors.h"

/**
 * Generation of the LMS private key
 */
void keygen_lms_private_key(lms_private_key *sk);

/**
 * Generation of the LMS public key
 */
void keygen_lms_public_key(lms_private_key *sk, lms_public_key *pk);

/**
 * Key Generation of LMS
 */
int lms_keygen(unsigned char *sk, unsigned char *pk);

/**
 * Signing procedure of a message using the lms_private_key and lms_signature structure.
 */
int lms_sign_internal(const unsigned char *message, const size_t input_size,
		lms_private_key *sk, lms_signature *sig);

/**
 * Signing procedure of a message using the LMS. The SK should be in the format https://datatracker.ietf.org/doc/html/rfc8554#section-5.2
 * the signature will be in the format proposed in https://datatracker.ietf.org/doc/html/rfc8554#section-5.4
 */
int lms_sign(const unsigned char *message, const size_t input_size,
		unsigned char *sk, unsigned char *signature);

/**
 * Verify procedure of a message using the LMS. The PK should be in the format https://datatracker.ietf.org/doc/html/rfc8554#section-5.3
 * the signature should be in the format proposed in https://datatracker.ietf.org/doc/html/rfc8554#section-5.4
 */

int lms_verify(const unsigned char *message, const size_t input_size,
		unsigned char *pk, unsigned char *signature);

/**
 * Verify procedure of a message using the lms_public_key and lms_signature structure.
 */
int lms_verify_internal(const unsigned char *message, const size_t input_size,
		lms_public_key *pk, lms_signature *signature);

#endif /* LMS_H_ */
