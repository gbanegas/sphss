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
#include "fips180.h"
#include "lms_utils.h"
#include "errors.h"
#include "sphss_defs.h"

/**
 * Key generation of LMS-OTS signature
 */

int lms_ots_keygen(unsigned char *sk, unsigned char *pk);

/**
 * Signing procedure of a message using the LMS. The SK should be in the format https://datatracker.ietf.org/doc/html/rfc8554#section-4.2
 * the signature will be in the format proposed in https://datatracker.ietf.org/doc/html/rfc8554#section-4.5
 */
int lms_ots_sign(const unsigned char *message, const size_t input_size, unsigned char *sk,
		unsigned char *signature);

/**
 * Verify procedure of a message using the LMS. The PK should be in the format https://datatracker.ietf.org/doc/html/rfc8554#section-4.3
 * the signature should be in the format proposed in https://datatracker.ietf.org/doc/html/rfc8554#section-4.5
 */
int lms_ots_verify(unsigned char *message, size_t input_size, unsigned char *pk,
		unsigned char *signature);

void gen_lmots_public_key(unsigned char *sk, unsigned char *pk);

#endif /* LMS_OTS_H_ */
