#include <stdio.h>
#include <stdlib.h>

#include "utils.h"
#include "params.h"
#include "lms_ots.h"
#include "lms.h"
#include "hss.h"

#define MESSAGE_SIZE 5
int main(void) {
	unsigned char sk[LMSOTS_PRIV_KEY_SIZE];
	memset(sk, 0, LMSOTS_PRIV_KEY_SIZE);
	unsigned char pk[LMSOTS_PUB_KEY_SIZE];
	memset(pk, 0, LMSOTS_PUB_KEY_SIZE);

	unsigned char message[MESSAGE_SIZE] = "teste";
	unsigned char signature[CRYPTO_BYTES_LMOS] = { 0 };
	memset(signature, 0, CRYPTO_BYTES_LMOS);

	lms_ots_keygen(sk, pk);

	int ret_sign = lms_ots_sign(message, MESSAGE_SIZE, sk, signature);
	printf("ret_sign ? %d\n", ret_sign);

	int ret = lms_ots_verify(message, MESSAGE_SIZE, pk, signature);

	printf("valid ? %d\n", ret);

	/*hss_keygen(sk, pk);

	 hss_sign(message, 5, sk, signature);
	 int ret = hss_verify(message, 5, pk, signature);
	 printf("valid ? %d\n", ret);*/
	//print_hex(signature, CRYPTO_BYTES_HSS);
	/*printf("sk:\n");
	 print_hex(sk, 60);
	 printf("pk: \n");
	 print_hex(pk, 56);*/

	/*lms_sign(message, 5, sk, signature);
	 //print_hex(signature, CRYPTO_BYTES_LMS);

	 int ret = lms_verify(message, 5, pk, signature);
	 printf("valid ? %d\n", ret);*/
	/*
	 lms_ots_sign(message, 5, sk, signature);

	 printf("signature: \n");
	 print_hex(signature, CRYPTO_BYTES_LMOS);
	 int ret = lms_ots_verify(message, 5, pk, signature);
	 printf("valid ? %d\n", ret);*/

	return EXIT_SUCCESS;
}
