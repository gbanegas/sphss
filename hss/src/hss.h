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

int hss_keygen(unsigned char *sk, unsigned char *pk);

int hss_sign(unsigned char *message, size_t input_size, unsigned char *sk,
		unsigned char *signature);

int hss_verify(unsigned char *message, size_t input_size, unsigned char *pk,
		unsigned char *signature);

#endif /* HSS_H_ */
