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
#include "sphss_defs.h"

/**
 * Concatenation of S, tmp, i in big endian, and j.
 */
void concat_hash_value(const uint_fast8_t *S, const uint_fast8_t *tmp,
		uint16_t i, uint8_t j, uint_fast8_t *result);

/**
 * Function to get the ith bit from Q as define in https://datatracker.ietf.org/doc/html/rfc8554#section-3.1.3
 */
uint8_t lms_ots_coeff(const unsigned char *Q, int i, int w);

/**
 * Computation of the checksum define in https://datatracker.ietf.org/doc/html/rfc8554#section-4.4
 *
 */
unsigned lms_ots_compute_checksum(const unsigned char *Q);

/**
 * From unsigned char array to lms_private_key
 */
void deserialize_lms_private_key(unsigned char *from, lms_private_key *to);

/**
 * Transform lms_private_key into array of unsigned char
 */
void serialize_lms_private_key(lms_private_key *from, unsigned char *to);

/**
 * From unsigned char array to lms_public_key
 */
void deserialize_lms_public_key(unsigned char *from, lms_public_key *to);

/**
 * Transform lms_public_key into array of unsigned char
 */
void serialize_lms_public_key(lms_public_key *from, unsigned char *to);

/**
 * Transform lms_signature into array of unsigned char
 */
void serialize_lms_signature(lms_signature *from, unsigned char *to);

/**
 * Transform lms_signature into array of unsigned char
 */
void deserialize_lms_signature(unsigned char *from, lms_signature *to);

#endif /* LMS_UTILS_H_ */
