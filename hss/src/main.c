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

int main(void) {
	puts("!!!Hello World!!!"); /* prints !!!Hello World!!! */
	unsigned char sk[55];
	memset(sk, 0, 55);
	unsigned char pk[64];
	memset(pk, 0, 64);
	unsigned char message[5] = "teste";
	unsigned char signature[CRYPTO_BYTES_LMOS] = { 0 };
	memset(signature, 0, CRYPTO_BYTES_LMOS);
	lms_ots_keygen(sk, pk);
	printf("sk:\n");
	print_hex(sk, 55);
	printf("pk: \n");
	print_hex(pk, 56);

	lms_ots_sign(message, 5, sk, signature);

	printf("signature: \n");
	print_hex(signature, CRYPTO_BYTES_LMOS);
	int ret = lms_ots_verify(message, 5, pk, signature);
	printf("valid ? %d\n", ret);

	return EXIT_SUCCESS;
}
