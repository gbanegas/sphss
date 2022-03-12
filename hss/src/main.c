#include <stdio.h>
#include <stdlib.h>

#include "utils.h"
#include "params.h"
#include "lms_ots.h"
#include "lms.h"
#include "hss.h"

#define MESSAGE_SIZE 5

void test_lms_ots() {
	unsigned char sk[LMSOTS_PRIV_KEY_SIZE];
	memset(sk, 0, LMSOTS_PRIV_KEY_SIZE);
	unsigned char pk[LMSOTS_PUB_KEY_SIZE];
	memset(pk, 0, LMSOTS_PUB_KEY_SIZE);

	unsigned char message[MESSAGE_SIZE] = "teste";
	unsigned char signature[CRYPTO_BYTES_LMOS] = { 0 };
	memset(signature, 0, CRYPTO_BYTES_LMOS);

	lms_ots_keygen(sk, pk);

	int ret_sign = lms_ots_sign(message, MESSAGE_SIZE, sk, signature);

	printf("LMS_OTS ret_sign ? %d\n", ret_sign);

	int ret = lms_ots_verify(message, MESSAGE_SIZE, pk, signature);

	printf("LMS_OTS valid ? %d\n", ret);
}

void test_lms() {
	unsigned char sk[LMS_PRIV_KEY_SIZE];
	memset(sk, 0, LMS_PRIV_KEY_SIZE);
	unsigned char pk[LMS_PUB_KEY_SIZE];
	memset(pk, 0, LMS_PUB_KEY_SIZE);

	unsigned char message[MESSAGE_SIZE] = "teste";
	unsigned char signature[CRYPTO_BYTES_LMS] = { 0 };
	memset(signature, 0, CRYPTO_BYTES_LMS);

	lms_keygen(sk, pk);

	int ret_sign = lms_sign(message, MESSAGE_SIZE, sk, signature);

	printf("LMS ret_sign ? %d\n", ret_sign);

	int ret = lms_verify(message, MESSAGE_SIZE, pk, signature);

	printf("LMS valid ? %d\n", ret);
}

void test_hss() {
	unsigned char sk[HSS_PRIVATE_KEY];
	memset(sk, 0, HSS_PRIVATE_KEY);
	unsigned char pk[HSS_PUBLIC_KEY];
	memset(pk, 0, HSS_PUBLIC_KEY);

	unsigned char message[MESSAGE_SIZE] = "teste";
	unsigned char signature[CRYPTO_BYTES_HSS] = { 0 };
	memset(signature, 0, HSS_PUBLIC_KEY);

	hss_keygen(sk, pk);

	int ret_sign = hss_sign(message, MESSAGE_SIZE, sk, signature);

	printf("HSS ret_sign ? %d\n", ret_sign);

	int ret = hss_verify(message, MESSAGE_SIZE, pk, signature);

	printf("HSS valid ? %d\n", ret);
}
int main(void) {

	//test_lms_ots();
	//test_lms();
	test_hss();

	return EXIT_SUCCESS;
}
