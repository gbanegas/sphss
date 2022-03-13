#include <stdio.h>
#include <stdlib.h>

#include "utils.h"
#include "params.h"
#include "lms_ots.h"
#include "lms.h"
#include "hss.h"

#define MESSAGE_SIZE 5
#define ITER 31
#define ITER_HSS 1025

int test_lms_ots() {
	unsigned char sk[LMSOTS_PRIV_KEY_SIZE];
	memset(sk, 0, LMSOTS_PRIV_KEY_SIZE);
	unsigned char pk[LMSOTS_PUB_KEY_SIZE];
	memset(pk, 0, LMSOTS_PUB_KEY_SIZE);

	unsigned char message[MESSAGE_SIZE] = "teste";
	unsigned char signature[CRYPTO_BYTES_LMOS] = { 0 };
	memset(signature, 0, CRYPTO_BYTES_LMOS);

	for (int i = 0; i < ITER; i++) {
		lms_ots_keygen(sk, pk);

		int ret_sign = lms_ots_sign(message, MESSAGE_SIZE, sk, signature);

		printf("LMS_OTS ret_sign ? %d\n", ret_sign);

		int ret = lms_ots_verify(message, MESSAGE_SIZE, pk, signature);
		if (ret) {
			printf("LMS_OTS valid!  \n");
		} else {
			printf("ret: %d\n", ret);
			printf("LMS_OTS invalid!  \n");
			return -1;
		}

	}
	return 1;
}

int test_lms() {
	unsigned char sk[LMS_PRIV_KEY_SIZE];
	memset(sk, 0, LMS_PRIV_KEY_SIZE);
	unsigned char pk[LMS_PUB_KEY_SIZE];
	memset(pk, 0, LMS_PUB_KEY_SIZE);

	unsigned char message[MESSAGE_SIZE] = "teste";
	unsigned char signature[CRYPTO_BYTES_LMS] = { 0 };
	memset(signature, 0, CRYPTO_BYTES_LMS);

	lms_keygen(sk, pk);
	for (int i = 0; i < ITER; i++) {
		int ret_sign = lms_sign(message, MESSAGE_SIZE, sk, signature);

		printf("LMS ret_sign ? %d\n", ret_sign);

		int ret = lms_verify(message, MESSAGE_SIZE, pk, signature);

		if (ret) {
			printf("LMS valid!  \n");
		} else {
			printf("LMS invalid!  \n");
			return -1;
		}
	}
	return 1;
}

int test_hss() {
	unsigned char sk[HSS_PRIVATE_KEY];
	memset(sk, 0, HSS_PRIVATE_KEY);
	unsigned char pk[HSS_PUBLIC_KEY];
	memset(pk, 0, HSS_PUBLIC_KEY);

	unsigned char message[MESSAGE_SIZE] = "teste";
	unsigned char signature[CRYPTO_BYTES_HSS] = { 0 };
	memset(signature, 0, HSS_PUBLIC_KEY);

	hss_keygen(sk, pk);

	for (int i = 0; i < ITER_HSS; i++) {
		printf("Iter: %d\n", i);
		int ret_sign = hss_sign(message, MESSAGE_SIZE, sk, signature);

		printf("HSS ret_sign ? %d\n", ret_sign);

		int ret = hss_verify(message, MESSAGE_SIZE, pk, signature);

		if (ret) {
			printf("HSS valid!  \n");
		} else {
			printf("HSS invalid!  \n");
			return -1;
		}
	}
	return 1;
}
int main(void) {

	int ret = test_lms_ots();
	if (ret != 1)
		exit(-1);
	ret = test_lms();
	if (ret != 1)
		exit(-1);
	ret = test_hss();
	if (ret != 1)
		exit(-1);

	return EXIT_SUCCESS;
}
