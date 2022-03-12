#include "utils.h"

/**
 * Converts the value of 'in' to 'outlen' bytes in big-endian byte order.
 */
void ull_to_bytes(void *target, unsigned long long value, size_t bytes) {
	unsigned char *b = target;
	int i;

	for (i = bytes - 1; i >= 0; i--) {
		b[i] = value & 0xff;
		value >>= 8;
	}
}

/**
 * Converts the inlen bytes in 'in' from big-endian byte order to an integer.
 */
unsigned long long bytes_to_ull(const void *target, size_t bytes) {
	const unsigned char *b = target;
	unsigned long long result = 0;
	int i;

	for (i = 0; i < bytes; i++) {
		result = 256 * result + (b[i] & 0xff);
	}

	return result;
}

/**
 * Print the inlen bytes in hex.
 */
void print_hex(unsigned char *array, unsigned int inlen) {
	printf("0x");
	for (unsigned int i = 0; i < inlen; i++) {
		if ((i + 1) % 33 == 0)
			printf("\n");
		printf("%02x,", array[i]);
	}
	printf("\n");
}

void print_lmots_signature(lmots_signature *sig) {
	printf("LMOS Type: %d\n", sig->alg_type);
	printf("C: ");
	print_hex(sig->C, 32);
	printf("y: ");
	print_hex(sig->y, P * 32);

}

/**
 * Print the lms_signature in hex.
 */

void print_lms_signature(lms_signature *sig) {
	for (int i = 0; i < 32; i++) {
		printf("-");
	}
	printf("\n");
	printf("LMS Type: %u\n", sig->lms_type);
	print_lmots_signature(&sig->lmots_sig);
	for (int i = 0; i < H; i++) {
		printf("path[%d]: ", i);
		print_hex(sig->path[i].node, 32);
	}
	for (int i = 0; i < 32; i++) {
		printf("-");
	}
	printf("\n");

}

/**
 * Print the lms_public_key in hex.
 */

void print_lms_pub_key(lms_public_key *sk) {
	printf("LMS type: %u\n", sk->lms_type);
	printf("LMOTS type: %u\n", sk->lmos_alg_type);
	printf("param_I: ");
	print_hex(sk->param_I, 16);
	printf("K: ");
	print_hex(sk->K, 32);
}

/**
 * Print the lms_private_key in hex.
 */
void print_lms_priv_key(lms_private_key *sk) {
	printf("LMS type: %u\n", sk->lms_type);
	printf("LMOTS type: %u\n", sk->lmos_alg_type);
	printf("param_I: ");
	print_hex(sk->param_I, 16);
	printf("SEED: ");
	print_hex(sk->SEED, 32);
	printf("q: %u\n", sk->q);
}

/**
 * Print the hss_signature in hex.
 */

void print_hss_signature(hss_signature *sig) {
	for (int i = 0; i < 8; i++)
		printf("-");
	printf("HSS Signature");
	for (int i = 0; i < 8; i++)
		printf("-");
	printf("\n");
	printf("Nspk: %u\n", sig->Nspk);
	for (int i = 0; i < sig->Nspk; i++) {
		print_lms_signature(&sig->signed_pub_key[i]);
	}
	for (int i = 0; i < sig->Nspk; i++) {
		print_lms_pub_key(&sig->pub_key[i]);
	}
	print_lms_signature(&sig->sig);
}

/**
 * Print the hss_private_key in hex.
 */
void print_hss_private_key(hss_private_key *sk) {
	for (int i = 0; i < 8; i++)
		printf("-");
	printf("HSS Private Key");
	for (int i = 0; i < 8; i++)
		printf("-");
	printf("\n");
	printf("remain: %u\n", sk->remain);
	printf("levels: %u\n", sk->L);

	for (int i = 0; i < sk->L; i++) {
		printf("Level: %d\n", i);
		print_lms_priv_key(&sk->priv[i]);
		print_lms_pub_key(&sk->pubs[i]);

	}
	/*for (int i = 0; i < sk->L-1; i++) {
		print_lms_signature(&sk->sigs[i]);
	}*/

}

/**
 * Print the hss_public_key in hex.
 */

void print_hss_public_key(hss_public_key *pk) {
	for (int i = 0; i < 8; i++)
		printf("-");
	printf("HSS Public Key");
	for (int i = 0; i < 8; i++)
		printf("-");
	printf("\n");

	printf("levels: %u\n", pk->L);
	printf("LMS type: %u\n", pk->pub.lms_type);
	printf("LMOTS type: %u\n", pk->pub.lmos_alg_type);
	printf("param_I: ");
	print_hex(pk->pub.param_I, 16);
	printf("K: ");
	print_hex(pk->pub.K, 32);

}

