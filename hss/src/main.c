/*
 ============================================================================
 Name        : main.c
 Author      : Gustavo Banegas
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>

#include "utils.h"
#include "params.h"
#include "lms_ots.h"
#include "lms.h"
#include "hss.h"

int main(void) {
	puts("!!!Hello World!!!"); /* prints !!!Hello World!!! */
	unsigned char sk[HSS_PRIVATE_KEY];
	memset(sk, 0, 60);
	unsigned char pk[HSS_PUBLIC_KEY];
	memset(pk, 0, 60);
	unsigned char message[5] = "teste";
	unsigned char signature[CRYPTO_BYTES_HSS] = { 0 };
	memset(signature, 0, CRYPTO_BYTES_HSS);
	hss_keygen(sk, pk);

	hss_sign(message, 5, sk, signature);
	int ret = hss_verify(message, 5, pk, signature);
	printf("valid ? %d\n", ret);
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
