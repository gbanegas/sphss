/*
 * sphss_defs.h
 *
 *  Created on: Mar 12, 2022
 *      Author: Gustavo Banegas
 */

#ifndef SPHSS_DEFS_H_
#define SPHSS_DEFS_H_

#include <stdint.h>
#include "params.h"

/* one-time signatures */

typedef struct lmots_signature {
	lmots_algorithm_type alg_type;
	unsigned char C[32];
	unsigned char y[P * 32];
} lmots_signature;

typedef struct lmots_private_key {
	lmots_algorithm_type alg_type;
	unsigned char S[20];
	unsigned char SEED[32];
	uint32_t remain_sign;
} lmots_private_key;

typedef struct lmots_public_key {
	lmots_algorithm_type alg_type;
	unsigned char S[20];
	unsigned char K[32];
} lmots_public_key;

/* hash-based signatures (lms) */

typedef struct lms_path {
	uint8_t node[32];
} lms_path;

typedef struct lms_signature {
	unsigned int q;
	unsigned char lmots_sig[CRYPTO_BYTES_LMOS];
	lms_algorithm_type lms_type;
	lms_path path[H];
} lms_signature;

typedef struct lms_public_key {
	lmots_algorithm_type lmos_alg_type;
	lms_algorithm_type lms_type;
	unsigned char param_I[16];
	unsigned char K[32];
} lms_public_key;

typedef struct lms_private_key {
	unsigned int q;
	lmots_algorithm_type lmos_alg_type;
	lms_algorithm_type lms_type;
	uint8_t param_I[16];
	uint8_t SEED[32];

} lms_private_key;

/* hierarchical signature system (hss) */
typedef struct hss_private_key {
	unsigned int L;
	int remain;
	unsigned char priv[LEVELS][LMS_PRIV_KEY_SIZE];
	unsigned char pubs[LEVELS][LMS_PUB_KEY_SIZE];
	unsigned char sigs[LEVELS][CRYPTO_BYTES_LMS];
} hss_private_key;

typedef struct hss_public_key {
	unsigned int L;
	unsigned char pub[LMS_PUB_KEY_SIZE];
} hss_public_key;

typedef struct signed_public_key {
	lms_signature sig[LEVELS];
	lms_public_key pub;
} signed_public_key;

typedef struct hss_signature {
	unsigned int Nspk;
	unsigned char signed_pub_key[LEVELS][CRYPTO_BYTES_LMS];
	unsigned char pub_key[LEVELS][LMS_PUB_KEY_SIZE];
	unsigned char sig[CRYPTO_BYTES_LMS];
} hss_signature;

#endif /* SPHSS_DEFS_H_ */
