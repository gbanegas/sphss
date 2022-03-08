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
	unsigned char sk[56] = { 0 };
	unsigned char pk[56] = { 0 };
	unsigned char message[5] = "teste";
	unsigned char signature[8516] = { 0 };
	lms_ots_keygen(sk, pk);
	/*printf("sk:\n");
	 print_hex(sk, 56);
	 printf("pk: \n");
	 print_hex(pk, 56);*/

	lms_ots_sign(message, 5, sk, signature);
	//printf("signature: \n");
	//print_hex(signature, 8516);
	int ret = lms_ots_verify(message, 5, pk, signature);
	printf("ret: %d\n", ret);

	return EXIT_SUCCESS;
}
