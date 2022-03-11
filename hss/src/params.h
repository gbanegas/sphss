/*
 * params.h
 *
 *  Created on: Mar 2, 2022
 *      Author: Gustavo Banegas
 */

#ifndef PARAMS_H_
#define PARAMS_H_

#include <stdint.h>

/* one-time signatures */

typedef enum lmots_algorithm_type {
	lmots_reserved = 0,
	lmots_sha256_n32_w1 = 1,
	lmots_sha256_n32_w2 = 2,
	lmots_sha256_n32_w4 = 3,
	lmots_sha256_n32_w8 = 4
} lmots_algorithm_type;

#define N 32

#define D_PBLC 0x8080 //defined in https://datatracker.ietf.org/doc/html/rfc8554#section-4.3
#define D_MESG 0x8181
#define D_LEAF 0x8282
#define D_INTR 0x8383
#define D_PRG 0xFF

#ifdef LMOTS_SHA256_N32_W1
#define ALG_NAME_LMOTS "LMOTS_SHA256_N32_W1"
#define P 265
#define W 1
#define LS 7
#define LMOTS_ALG_TYPE lmots_sha256_n32_w1
#endif

#ifdef LMOTS_SHA256_N32_W2
#define ALG_NAME_LMOTS "LMOTS_SHA256_N32_W2"
#define P 133
#define W 2
#define LS 6
#define LMOTS_ALG_TYPE lmots_sha256_n32_w2
#endif

#ifdef LMOTS_SHA256_N32_W4
#define ALG_NAME_LMOTS "LMOTS_SHA256_N32_W4"
#define P 67
#define W 4
#define LS 4
#define LMOTS_ALG_TYPE lmots_sha256_n32_w4
#endif

#ifdef LMOTS_SHA256_N32_W8
#define ALG_NAME_LMOTS "LMOTS_SHA256_N32_W8"
#define P 34
#define W 8
#define LS 0
#define LMOTS_ALG_TYPE lmots_sha256_n32_w8
#endif

#define CRYPTO_BYTES_LMOS (32*P)+N+4
#define LMSOTS_PUB_KEY_SIZE 56
#define LMSOTS_PRIV_KEY_SIZE 60

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
/* hash-based signatures (hbs) */

typedef enum lms_algorithm_type {

	lms_reserved = 0,
	lms_sha256_n32_h5 = 5,
	lms_sha256_n32_h10 = 6,
	lms_sha256_n32_h15 = 7,
	lms_sha256_n32_h20 = 8,
	lms_sha256_n32_h25 = 9
} lms_algorithm_type;

#define M 32
#define I 64
#define ALG_NAME_LMS "LMS_SHA256_M32_H5"
#define H 5
#define LMS_ALG_TYPE lms_sha256_n32_h5

#ifdef LMS_SHA256_M32_H10
#define ALG_NAME_LMS "LMS_SHA256_M32_H10"
#define H 10
#define LMS_ALG_TYPE lms_sha256_n32_h10
#endif

#ifdef LMS_SHA256_M32_H15
#define ALG_NAME_LMS "LMS_SHA256_M32_H15"
#define H 15
#define LMS_ALG_TYPE lms_sha256_n32_h15
#endif

#ifdef LMS_SHA256_M32_H20
#define ALG_NAME_LMS "LMS_SHA256_M32_H20"
#define H 20
#define LMS_ALG_TYPE lms_sha256_n32_h20
#endif

#ifdef LMS_SHA256_M32_H25
#define ALG_NAME_LMS "LMS_SHA256_M32_H25"
#define H 25
#define LMS_ALG_TYPE lms_sha256_n32_h25
#endif

#define CRYPTO_BYTES_LMS (32*P)+N+4+4+4+(32*H)
#define LMS_PRIV_KEY_SIZE 60
#define LMS_PUB_KEY_SIZE 56

typedef struct lms_path {
	uint8_t node[32];
} lms_path;

typedef struct lms_signature {
	unsigned int q;
	lmots_signature lmots_sig;
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

#define MAX_HSS_LEVELS 8
#define LEVELS 2

#define HSS_PRIVATE_KEY 4+(LEVELS*(64))

#define HSS_PUBLIC_KEY (4+4+4+16+32)

#define CRYPTO_BYTES_HSS CRYPTO_BYTES_LMS*LEVELS+(LMS_PUB_KEY_SIZE*LEVELS) + (CRYPTO_BYTES_LMS*LEVELS)

typedef struct hss_private_key {
	unsigned int L;
	unsigned int remain;
	lms_private_key priv[LEVELS];
	lms_public_key pubs[LEVELS];
	lms_signature sigs[LEVELS];
} hss_private_key;

typedef struct hss_public_key {
	unsigned int L;
	lms_public_key pub;
} hss_public_key;

typedef struct signed_public_key {
	lms_signature sig[LEVELS];
	lms_public_key pub;
} signed_public_key;

typedef struct hss_signature {
	unsigned int Nspk;
	lms_signature signed_pub_key[LEVELS];
	lms_public_key pub_key[LEVELS];
	lms_signature sig;
} hss_signature;

#endif /* PARAMS_H_ */
