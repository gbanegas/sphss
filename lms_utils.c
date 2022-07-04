/*
 * lms_utils.c
 *
 *  Created on: Mar 9, 2022
 *      Author: Gustavo Banegas
 */
#include "lms_utils.h"

void serialize_lmsots_signature(lmots_signature *from, unsigned char *to) {
	ull_to_bytes(to, from->alg_type, 4);
	memcpy(to + 4, from->C, 32);
	memcpy(to + 36, from->y, P * 32);
}

void deserialize_lmsots_signature(unsigned char *from, lmots_signature *to) {
	to->alg_type = bytes_to_ull(from, 4);
	memcpy(to->C, from + 4, 32);
	memcpy(to->y, from + 36, P * 32);
}

void concat_hash_value(const uint_fast8_t *S, const uint_fast8_t *tmp,
		uint16_t i, uint8_t j, uint_fast8_t *result) {
	memcpy(result, S, 20);
	ull_to_bytes(result + 20, i, 2);
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

void deserialize_lms_private_key(unsigned char *from, lms_private_key *to) {
	to->lmos_alg_type = bytes_to_ull(from, 4);
	to->lms_type = bytes_to_ull(from + 4, 4);
	memcpy(to->param_I, from + 8, 16);
	memcpy(to->SEED, from + 24, 32);
	to->q = bytes_to_ull(from + 56, 4);

}

void serialize_lms_private_key(lms_private_key *from, unsigned char *to) {
	ull_to_bytes(to, from->lmos_alg_type, 4);
	ull_to_bytes(to + 4, from->lms_type, 4);
	memcpy(to + 8, from->param_I, 16);
	memcpy(to + 24, from->SEED, 32);
	ull_to_bytes(to + 56, from->q, 4);

}
void deserialize_lms_public_key(unsigned char *from, lms_public_key *to) {

	to->lmos_alg_type = bytes_to_ull(from, 4);
	to->lms_type = bytes_to_ull(from + 4, 4);
	memcpy(to->param_I, from + 8, 16);
	memcpy(to->K, from + 24, 32);

}

void serialize_lms_public_key(lms_public_key *from, unsigned char *to) {
	ull_to_bytes(to, from->lmos_alg_type, 4);
	ull_to_bytes(to + 4, from->lms_type, 4);
	memcpy(to + 8, from->param_I, 16);
	memcpy(to + 24, from->K, 32);

}

void serialize_lms_signature(lms_signature *from, unsigned char *to) {
	ull_to_bytes(to, from->q, 4);
	ull_to_bytes(to + 4, LMOTS_ALG_TYPE, 4);
	memcpy(to + 8, &from->lmots_sig[0] + 4, 32);
	memcpy(to + 40, &from->lmots_sig[0] + 36, 32 * P);
	ull_to_bytes(to + (44 + (32 * P)), from->lms_type, 4);
	for (int i = 0; i < H; i++) {
		memcpy(to + (48 + (32 * P) + (i * 32)), from->path[i].node, 32);
	}

}

void deserialize_lms_signature(unsigned char *from, lms_signature *to) {
	to->q = bytes_to_ull(from, 4);
	memcpy(to->lmots_sig, from + 4, 4);
	//to->lmots_sig.alg_type = bytes_to_ull(from + 4, 4);
	memcpy(to->lmots_sig + 4, from + 8, 32);
	//memcpy(to->lmots_sig.C, from + 8, 32);
	memcpy(to->lmots_sig + 36, from + 40, 32 * P);
	//memcpy(to->lmots_sig.y, from + 40, 32 * P);
	to->lms_type = bytes_to_ull(from + (40 + (32 * P)), 4);
	for (int i = 0; i < H; i++) {
		memcpy(to->path[i].node, from + (44 + (32 * P) + (i * 32)), 32);
	}

}

