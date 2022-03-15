#include <stdio.h>
#include <stdlib.h>

#include "utils.h"
#include "params.h"
#include "lms_ots.h"
#include "lms.h"
#include "hss.h"
#include "cpucycles.h"

#define MESSAGE_SIZE 5
#define ITER 100
#define ITER_HSS 100

unsigned long long time_lmots_keygen_f[ITER];
unsigned long long time_lmots_sign_f[ITER];
unsigned long long time_lmots_verify_f[ITER];

unsigned long long time_lms_keygen_f[ITER];
unsigned long long time_lms_sign_f[ITER];
unsigned long long time_lms_verify_f[ITER];

unsigned long long time_hss_keygen_f[ITER_HSS];
unsigned long long time_hss_sign_f[ITER_HSS];
unsigned long long time_hss_verify_f[ITER_HSS];

int test_lms_ots() {
	unsigned char sk[LMSOTS_PRIV_KEY_SIZE];
	memset(sk, 0, LMSOTS_PRIV_KEY_SIZE);
	unsigned char pk[LMSOTS_PUB_KEY_SIZE];
	memset(pk, 0, LMSOTS_PUB_KEY_SIZE);

	unsigned char message[MESSAGE_SIZE] = "teste";
	unsigned char signature[CRYPTO_BYTES_LMOS] = { 0 };
	unsigned long long start, end;
	memset(signature, 0, CRYPTO_BYTES_LMOS);
	printf("Warming up.... lms_ots\n");
	for (int i = 0; i < ITER; i++) {
		printf("..");
		lms_ots_keygen(sk, pk);
		lms_ots_sign(message, MESSAGE_SIZE, sk, signature);
		lms_ots_verify(message, MESSAGE_SIZE, pk, signature);

	}
	printf("\n Starting test:\n");

	for (int i = 0; i < ITER; i++) {

		start = cpucycles();
		lms_ots_keygen(sk, pk);
		end = cpucycles();
		time_lmots_keygen_f[i] = end - start;

		start = cpucycles();
		lms_ots_sign(message, MESSAGE_SIZE, sk, signature);
		end = cpucycles();
		time_lmots_sign_f[i] = end - start;
		//printf("LMS_OTS ret_sign ? %d\n", ret_sign);
		start = cpucycles();
		int ret = lms_ots_verify(message, MESSAGE_SIZE, pk, signature);
		end = cpucycles();
		time_lmots_verify_f[i] = end - start;
		if (!ret) {
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

	unsigned long long start, end;
	printf("Warming up.... lms\n");
	for (int i = 0; i < ITER; i++) {
		printf("..");
		lms_keygen(sk, pk);
		lms_sign(message, MESSAGE_SIZE, sk, signature);
		lms_verify(message, MESSAGE_SIZE, pk, signature);

	}
	printf("\n Starting test:\n");

	for (int i = 0; i < ITER; i++) {
		start = cpucycles();
		lms_keygen(sk, pk);
		end = cpucycles();
		time_lms_keygen_f[i] = end - start;
		start = cpucycles();
		lms_sign(message, MESSAGE_SIZE, sk, signature);
		end = cpucycles();
		time_lms_sign_f[i] = end - start;

		//printf("LMS ret_sign ? %d\n", ret_sign);
		start = cpucycles();
		int ret = lms_verify(message, MESSAGE_SIZE, pk, signature);
		end = cpucycles();
		time_lms_verify_f[i] = end - start;

		if (!ret) {
			printf("LMS invalid!  \n");
			return -1;
		}
	}
	printf("end test\n");
	return 1;
}

int test_hss() {
#ifdef LMOTS_SHA256_N32_W8
	unsigned char sk[HSS_PRIVATE_KEY];
	memset(sk, 0, HSS_PRIVATE_KEY);
#else
	unsigned char *sk = calloc(HSS_PRIVATE_KEY, sizeof(unsigned char));
#endif
	unsigned char pk[HSS_PUBLIC_KEY];
	memset(pk, 0, HSS_PUBLIC_KEY);

	unsigned char message[MESSAGE_SIZE] = "teste";
	unsigned char signature[CRYPTO_BYTES_HSS] = { 0 };
	memset(signature, 0, HSS_PUBLIC_KEY);
	unsigned long long start, end;
	printf("Warming up.... hss\n");
	for (int i = 0; i < ITER_HSS / 2; i++) {
		printf("..");
		hss_keygen(sk, pk);
		hss_sign(message, MESSAGE_SIZE, sk, signature);
		hss_verify(message, MESSAGE_SIZE, pk, signature);
	}
	printf("\n Starting test:\n");

	for (int i = 0; i < ITER_HSS; i++) {
		start = cpucycles();
		hss_keygen(sk, pk);
		end = cpucycles();
		time_hss_keygen_f[i] = end - start;

		start = cpucycles();
		hss_sign(message, MESSAGE_SIZE, sk, signature);
		end = cpucycles();
		time_hss_sign_f[i] = end - start;

		start = cpucycles();
		int ret = hss_verify(message, MESSAGE_SIZE, pk, signature);
		end = cpucycles();
		time_hss_verify_f[i] = end - start;

		if (!ret) {
			printf("HSS invalid!  \n");
			return -1;
		}
	}
	return 1;
}

int main(void) {

	memset(time_lmots_keygen_f, 0, sizeof(unsigned long long) * ITER);
	memset(time_lmots_sign_f, 0, sizeof(unsigned long long) * ITER);
	memset(time_lmots_verify_f, 0, sizeof(unsigned long long) * ITER);

	memset(time_lms_keygen_f, 0, sizeof(unsigned long long) * ITER);
	memset(time_lms_sign_f, 0, sizeof(unsigned long long) * ITER);
	memset(time_lms_verify_f, 0, sizeof(unsigned long long) * ITER);

	memset(time_hss_keygen_f, 0, sizeof(unsigned long long) * ITER);
	memset(time_hss_sign_f, 0, sizeof(unsigned long long) * ITER);
	memset(time_hss_verify_f, 0, sizeof(unsigned long long) * ITER);

	int ret = test_lms_ots();
	if (ret != 1)
		exit(-1);
	ret = test_lms();
	if (ret != 1)
		exit(-1);
	ret = test_hss();
	if (ret != 1)
		exit(-1);

	unsigned long long median_hss_keygen = 0, median_hss_sign = 0,
			median_hss_verify = 0;
	unsigned long long median_lms_keygen = 0, median_lms_sign = 0,
			median_lms_verify = 0;
	unsigned long long median_lms_ots_keygen = 0, median_lms_ots_sign = 0,
			median_lms_ots_verify = 0;
	for (int i = 0; i < ITER; i++) {
		median_lms_keygen += time_lms_keygen_f[i];
		median_lms_sign += time_lms_sign_f[i];
		median_lms_verify += time_lms_verify_f[i];

		median_lms_ots_keygen += time_lmots_keygen_f[i];
		median_lms_ots_sign += time_lmots_sign_f[i];
		median_lms_ots_verify += time_lmots_verify_f[i];
	}

	for (int i = 0; i < ITER_HSS; i++) {
		median_hss_keygen += time_hss_keygen_f[i];
		median_hss_sign += time_hss_sign_f[i];
		median_hss_verify += time_hss_verify_f[i];
	}

	printf("median lms-ots keygen: %llu cycles \n",
			median_lms_ots_keygen / ITER);
	printf("median lms-ots sign: %llu cycles \n", median_lms_ots_sign / ITER);
	printf("median lms-ots verify: %llu cycles \n",
			median_lms_ots_verify / ITER);

	printf("median lms keygen: %llu cycles \n", median_lms_keygen / ITER);
	printf("median lms sign: %llu cycles \n", median_lms_sign / ITER);
	printf("median lms verify: %llu cycles \n", median_lms_verify / ITER);

	printf("median hss keygen: %llu cycles \n", median_hss_keygen / ITER_HSS);
	printf("median hss sign: %llu cycles \n", median_hss_sign / ITER_HSS);
	printf("median hss verify: %llu cycles \n", median_hss_verify / ITER_HSS);

	return EXIT_SUCCESS;
}
