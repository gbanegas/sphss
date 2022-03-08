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


int lms_ots_keygen(unsigned char *sk, unsigned char *pk);

int lms_ots_sign(unsigned char *message, size_t input_size, unsigned char *sk,
		unsigned char *signature);

int lms_ots_verify(unsigned char *message, size_t input_size, unsigned char *pk,
		unsigned char *signature);
#endif /* LMS_OTS_H_ */