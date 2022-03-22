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
	int index = 0;
	//printf("[0]: 0x");
	for (unsigned int i = 0; i < inlen; i++) {
		if (i % 32 == 0) {
			printf("\n[%d]: ", index);
			index++;
		}
		printf("%02x,", array[i]);
	}
	printf("\n");
}

void print_lmots_signature(lmots_signature *sig) {
	printf("LMOS Type: %d\n", sig->alg_type);
	printf("C: ");
	print_hex(sig->C, 32);
	printf("y: \n");
	print_hex(sig->y, P * 32);

}

void print_lmots_signature_pure(unsigned char *sig) {
	lmots_signature signature;
	deserialize_lmsots_signature(sig, &signature);
	print_lmots_signature(&signature);

}

void print_lmots_public_key_pure(unsigned char *pk) {
	unsigned long long lmos_t = bytes_to_ull(pk, 4);
	printf("LMOS Type: %llu\n", lmos_t);
	printf("K: ");
	print_hex(pk + 4, 32);
	printf("S: ");
	print_hex(pk + 36, 16);

}

/**
 * Print the lms_signature in hex.
 */

void print_lms_signature(lms_signature *sig) {
	for (int i = 0; i < 32; i++) {
		printf("-");
	}
	printf("\n");
	printf("q: %u\n", sig->q);
	printf("LMS Type: %u\n", sig->lms_type);
	print_lmots_signature_pure(sig->lmots_sig);
	for (int i = 0; i < H; i++) {
		printf("path[%d]: ", i);
		print_hex(sig->path[i].node, 32);
	}
	for (int i = 0; i < 32; i++) {
		printf("-");
	}
	printf("\n");

}

void print_lms_signature_pure(unsigned char *sig) {
	lms_signature signature;
	deserialize_lms_signature(sig, &signature);

	print_lms_signature(&signature);
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

void print_lms_pub_key_pure(unsigned char *pk) {
	printf("LMS type: %llu\n", bytes_to_ull(pk, 4));
	printf("LMOTS type: %llu\n", bytes_to_ull(pk + 4, 4));
	printf("param_I: ");
	print_hex(pk + 8, 16);
	printf("K: ");
	print_hex(pk + 24, 32);
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
		print_lms_signature_pure(sig->signed_pub_key[i]);
	}
	/*for (int i = 0; i < sig->Nspk; i++) {
		print_lms_pub_key_pure(sig->pub_key[i]);
	}*/
	/*
	print_lms_signature_pure(sig->sig);*/
}

/**
 * Print the hss_private_key in hex.
 */
void print_hss_private_key_pure(unsigned char *sk) {
	for (int i = 0; i < 8; i++)
		printf("-");
	printf("HSS Private Key");
	for (int i = 0; i < 8; i++)
		printf("-");
	printf("\n");

	/*	hss_private_key private_key;
	 private_key->remain = bytes_to_ull(sk, 4);
	 private_key->L = bytes_to_ull(sk + 4, 4);
	 for (unsigned int i = 0; i < private_key->L; i++) {
	 private_key->priv[i] = bytes_to_ull(sk + 8 + (i * 68), 4);
	 private_key->priv[i].lms_type = bytes_to_ull(sk + 12 + (i * 68), 4);
	 memcpy(private_key->priv[i].param_I, sk + 16 + (i * 68), 16);
	 memcpy(private_key->priv[i].SEED, sk + 32 + (i * 68), 32);
	 private_key->priv[i].q = bytes_to_ull(sk + 64 + (i * 68), 4);

	 }
	 for (unsigned int i = 0; i < private_key->L; i++) {
	 deserialize_lms_public_key(
	 sk + (private_key->L * 68)
	 + (i * (LMS_PUB_KEY_SIZE + CRYPTO_BYTES_LMS)),
	 &private_key->pubs[i]);
	 deserialize_lms_signature(
	 sk + (private_key->L * 68) + LMS_PUB_KEY_SIZE
	 + (i * (LMS_PUB_KEY_SIZE + CRYPTO_BYTES_LMS)),
	 &private_key->sigs[i]);
	 }

	 printf("remain: %u\n", sk->remain);
	 printf("levels: %u\n", sk->L);

	 for (int i = 0; i < sk->L; i++) {
	 printf("Level: %d\n", i);
	 print_lms_priv_key(&sk->priv[i]);
	 print_lms_pub_key(&sk->pubs[i]);

	 }*/
	/*for (int i = 0; i < sk->L-1; i++) {
	 print_lms_signature(&sk->sigs[i]);
	 }*/

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

void print_hss_public_key_pure(unsigned char *pk) {
	hss_public_key public_key;
	lms_public_key pk_lms;
	public_key.L = bytes_to_ull(pk, 4);

	deserialize_lms_public_key(pk + 4, &pk_lms);
	for (int i = 0; i < 8; i++)
		printf("-");
	printf("HSS Public Key");
	for (int i = 0; i < 8; i++)
		printf("-");
	printf("\n");

	printf("levels: %u\n", public_key.L);
	printf("LMS type: %u\n", pk_lms.lms_type);
	printf("LMOTS type: %u\n", pk_lms.lmos_alg_type);
	printf("param_I: ");
	print_hex(pk_lms.param_I, 16);
	printf("K: ");
	print_hex(pk_lms.K, 32);

}

/*
 void deserialize_hss_private_key(unsigned char *sk,
 hss_private_key *private_key) {

 private_key->remain = bytes_to_ull(sk, 4);
 private_key->L = bytes_to_ull(sk + 4, 4);
 for (unsigned int i = 0; i < private_key->L; i++) {
 private_key->priv[i].lmos_alg_type = bytes_to_ull(sk + 8 + (i * 68), 4);
 private_key->priv[i].lms_type = bytes_to_ull(sk + 12 + (i * 68), 4);
 memcpy(private_key->priv[i].param_I, sk + 16 + (i * 68), 16);
 memcpy(private_key->priv[i].SEED, sk + 32 + (i * 68), 32);
 private_key->priv[i].q = bytes_to_ull(sk + 64 + (i * 68), 4);

 }
 for (unsigned int i = 0; i < private_key->L; i++) {
 deserialize_lms_public_key(
 sk + (private_key->L * 68)
 + (i * (LMS_PUB_KEY_SIZE + CRYPTO_BYTES_LMS)),
 &private_key->pubs[i]);
 deserialize_lms_signature(
 sk + (private_key->L * 68) + LMS_PUB_KEY_SIZE
 + (i * (LMS_PUB_KEY_SIZE + CRYPTO_BYTES_LMS)),
 &private_key->sigs[i]);
 }

 }

 void serialize_hss_private_key(hss_private_key *private_key, unsigned char *sk) {
 ull_to_bytes(sk, private_key->remain, 4);
 ull_to_bytes(sk + 4, private_key->L, 4);
 for (unsigned int i = 0; i < private_key->L; i++) {

 ull_to_bytes(sk + 8 + (i * 68), private_key->priv[i].lmos_alg_type, 4);
 ull_to_bytes(sk + 12 + (i * 68), private_key->priv[i].lms_type, 4);
 memcpy(sk + 16 + (i * 68), private_key->priv[i].param_I, 16);
 memcpy(sk + 32 + (i * 68), private_key->priv[i].SEED, 32);
 ull_to_bytes(sk + 64 + (i * 68), private_key->priv[i].q, 4);

 }

 for (unsigned int i = 0; i < private_key->L; i++) {
 serialize_lms_public_key(&private_key->pubs[i],
 sk + (private_key->L * 68)
 + (i * (LMS_PUB_KEY_SIZE + CRYPTO_BYTES_LMS)));
 serialize_lms_signature(&private_key->sigs[i],
 sk + (private_key->L * 68) + LMS_PUB_KEY_SIZE
 + (i * (LMS_PUB_KEY_SIZE + CRYPTO_BYTES_LMS)));
 }

 }

 void deserialize_hss_public_key(unsigned char *pk, hss_public_key *public_key) {
 public_key->L = bytes_to_ull(pk, 4);
 public_key->pub.lmos_alg_type = bytes_to_ull(pk + 4, 4);
 public_key->pub.lms_type = bytes_to_ull(pk + 8, 4);
 memcpy(public_key->pub.param_I, pk + 12, 16);
 memcpy(public_key->pub.K, pk + 28, 32);
 }

 void serialize_hss_public_key(hss_public_key *public_key, unsigned char *pk) {
 ull_to_bytes(pk, public_key->L, 4);
 ull_to_bytes(pk + 4, public_key->pub.lmos_alg_type, 4);
 ull_to_bytes(pk + 8, public_key->pub.lms_type, 4);
 memcpy(pk + 12, public_key->pub.param_I, 16);
 memcpy(pk + 28, public_key->pub.K, 32);
 }*/

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
	lms_public_key pub;
	deserialize_lms_public_key(pk->pub, &pub);
	printf("LMS type: %u\n", pub.lms_type);
	printf("LMOTS type: %u\n", pub.lmos_alg_type);
	printf("param_I: ");
	print_hex(pub.param_I, 16);
	printf("K: ");
	print_hex(pub.K, 32);

}

