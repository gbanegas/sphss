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

//#ifdef LMOTS_SHA256_N32_W1
#define ALG_NAME_LMOTS "LMOTS_SHA256_N32_W1"
#define P 265
#define W 1
#define LS 7
//#endif

#ifdef LMOTS_SHA256_N32_W2
#define ALG_NAME_LMOTS "LMOTS_SHA256_N32_W2"
#define P 133
#define W 2
#define LS 6
#endif

#ifdef LMOTS_SHA256_N32_W4
#define ALG_NAME_LMOTS "LMOTS_SHA256_N32_W4"
#define P 67
#define W 4
#define LS 4
#endif

#ifdef LMOTS_SHA256_N32_W4
#define ALG_NAME_LMOTS "LMOTS_SHA256_N32_W4"
#define P 34
#define W 8
#define LS 0
#endif

typedef struct lmots_signature {
	lmots_algorithm_type alg_type;
	unsigned char C[32];
	unsigned char y[P * 32];
} lmots_signature;

typedef struct lmots_private_key {
	lmots_algorithm_type alg_type;
	unsigned char S[20];
	unsigned char SEED[32];
	size_t remain_sign;
} lmots_private_key;

typedef struct lmots_public_key {
	lmots_algorithm_type alg_type;
	unsigned char S[20];
	unsigned char K[32];
} lmots_public_key;
/* hash-based signatures (hbs) */

enum lms_algorithm_type {

	lms_reserved = 0,
	lms_sha256_n32_h5 = 5,
	lms_sha256_n32_h10 = 6,
	lms_sha256_n32_h15 = 7,
	lms_sha256_n32_h20 = 8,
	lms_sha256_n32_h25 = 9
};

#define M 32
#define I 64
#define ALG_NAME_LMS "LMS_SHA256_M32_H5"
#define H 5

#ifdef LMS_SHA256_M32_H10
#define ALG_NAME_LMS "LMS_SHA256_M32_H10"
#define H 10
#endif

#ifdef LMS_SHA256_M32_H15
#define ALG_NAME_LMS "LMS_SHA256_M32_H15"
#define H 15
#endif

#ifdef LMS_SHA256_M32_H20
#define ALG_NAME_LMS "LMS_SHA256_M32_H20"
#define H 20
#endif

#ifdef LMS_SHA256_M32_H25
#define ALG_NAME_LMS "LMS_SHA256_M32_H25"
#define H 25
#endif

typedef struct lms_signature {
	unsigned int q;
	lmots_signature lmots_sig;
//lms_path nodes;
} lms_signature;

/* hierarchical signature system (hss) */

/*struct hss_public_key {
 unsigned int L;
 lms_public_key pub;
 };

 struct signed_public_key {
 lms_signature sig;
 lms_public_key pub;
 };

 struct hss_signature {
 signed_public_key signed_keys<7>;
 lms_signature sig_of_message;
 };*/

#endif /* PARAMS_H_ */
