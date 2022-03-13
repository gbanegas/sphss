/*
 * hss.h
 *
 *  Created on: Mar 2, 2022
 *      Author: Gustavo Banegas
 */

#ifndef HSS_H_
#define HSS_H_

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "randombytes.h"
#include "params.h"
#include "hash.h"
#include "lms_ots.h"
#include "lms_utils.h"
#include "lms.h"
#include "fips202.h"
#include "sphss_defs.h"

/**
 * Key Generation of HSS. As it is defined in https://datatracker.ietf.org/doc/html/rfc8554#section-6.1
 */
int hss_keygen(unsigned char *sk, unsigned char *pk);

/**
 * Signing procedure of a message using the HSS. As it is defined in https://datatracker.ietf.org/doc/html/rfc8554#section-6.2
 */
int hss_sign(const unsigned char *message, const size_t input_size,
		unsigned char *sk, unsigned char *signature);

/**
 * Verify procedure of a message using the HSS. AS it is define in https://datatracker.ietf.org/doc/html/rfc8554#section-6.3
 */
int hss_verify(const unsigned char *message, const size_t input_size,
		unsigned char *pk, unsigned char *signature);

#endif /* HSS_H_ */
