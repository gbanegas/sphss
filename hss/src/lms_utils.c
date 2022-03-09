/*
 * lms_utils.c
 *
 *  Created on: Mar 9, 2022
 *      Author: Gustavo Banegas
 */
#include "lms_utils.h"


void concat_hash_value(const uint_fast8_t *S, const uint_fast8_t *tmp,
		uint16_t i, uint8_t j, uint_fast8_t *result) {
	uint_fast8_t buff[2];
	put_bigendian(buff, i, 2);
	memcpy(result, S, 20);
	memcpy(result + 20, buff, 2);
	memcpy(result + 22, &j, 1);
	memcpy(result + 23, tmp, 32);

}

uint8_t lms_ots_coeff(const unsigned char *Q, int i, int w) {
	unsigned index = (i * w) / 8; /* Which byte holds the coefficient */
	/* we want */
	unsigned digits_per_byte = 8 / w;
	unsigned shift = w * (~i & (digits_per_byte - 1)); /* Where in the byte */
	/* the coefficient is */
	unsigned mask = (1 << w) - 1; /* How to mask off the parts we're not */
	/* interested in */

	return (Q[index] >> shift) & mask;
}

unsigned lms_ots_compute_checksum(const unsigned char *Q) {
	unsigned sum = 0;
	unsigned i;
	unsigned u = 8 * N / W;
	unsigned max_digit = (1 << W) - 1;
	for (i = 0; i < u; i++) {
		sum += max_digit - lms_ots_coeff(Q, i, W);
	}
	return sum << LS;
}
