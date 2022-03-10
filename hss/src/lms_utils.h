/*
 * lms_utils.h
 *
 *  Created on: Mar 9, 2022
 *      Author: Gustavo Banegas
 */

#ifndef LMS_UTILS_H_
#define LMS_UTILS_H_

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "randombytes.h"
#include "params.h"
#include "hash.h"
#include "fips202.h"

void concat_hash_value(const uint_fast8_t *S, const uint_fast8_t *tmp,
		uint16_t i, uint8_t j, uint_fast8_t *result);

uint8_t lms_ots_coeff(const unsigned char *Q, int i, int w);

unsigned lms_ots_compute_checksum(const unsigned char *Q);

void deserialize_lms_private_key(unsigned char *from, lms_private_key *to);

void serialize_lms_private_key(lms_private_key *from, unsigned char *to);

void deserialize_lms_public_key(unsigned char *from, lms_public_key *to);

void serialize_lms_public_key(lms_public_key *from, unsigned char *to);

void serialize_lms_signature(lms_signature *from, unsigned char *to);

void deserialize_lms_signature(unsigned char *from, lms_signature *to);

#endif /* LMS_UTILS_H_ */
