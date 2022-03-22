/*
 * hss.c
 *
 *  Created on: Mar 2, 2022
 *      Author: Gustavo Banegas
 */

#include "hss.h"

void gen_hss_private_key(unsigned char *sk) { //https://datatracker.ietf.org/doc/html/rfc8554#section-6.1
	/*sk->remain = (1 << (LEVELS * H));
	 sk->L = LEVELS;*/
	ull_to_bytes(sk, (1 << (LEVELS * H)), 4);
	ull_to_bytes(sk + 4, LEVELS, 4);
	keygen_lms_private_key(sk + 8);


	keygen_lms_public_key(sk + 8, sk + 8 + (LEVELS * LMS_PRIV_KEY_SIZE));

	for (int i = 1; i < LEVELS; i++) {
		keygen_lms_private_key(sk + 8 + (i * LMS_PRIV_KEY_SIZE));
		//memcpy(sk->priv[i].SEED, sk->priv[0].SEED, 32);
		keygen_lms_public_key(sk + 8 + (i * LMS_PRIV_KEY_SIZE),
				sk + 8 + (LEVELS * LMS_PRIV_KEY_SIZE) + (i * LMS_PUB_KEY_SIZE));
		lms_sign_internal_f(
				sk + 8 + (LEVELS * LMS_PRIV_KEY_SIZE) + (i * LMS_PUB_KEY_SIZE),
				LMS_PUB_KEY_SIZE, sk + 8 + ((i - 1) * LMS_PRIV_KEY_SIZE),
				sk + 8 + (LEVELS * LMS_PRIV_KEY_SIZE)
						+ (LEVELS * LMS_PUB_KEY_SIZE)
						+ ((i - 1) * CRYPTO_BYTES_LMS));
	}

}

void gen_hss_public_key(unsigned char *sk, unsigned char *pk) {
	ull_to_bytes(pk, LEVELS, 4);
	memcpy(pk + 4, sk + 8 + (LEVELS * LMS_PRIV_KEY_SIZE), LMS_PUB_KEY_SIZE);

}
int hss_keygen(unsigned char *sk, unsigned char *pk) {

	gen_hss_private_key(sk);
	gen_hss_public_key(sk, pk);

	/*	serialize_hss_public_key(&public_key, pk);
	 serialize_hss_private_key(&private_key, sk);*/

	return 1;
}

/*void serialize_hss_signature(hss_signature *from, unsigned char *to) {

	ull_to_bytes(to, from->Nspk, 4);
	for (int i = 0; i < from->Nspk; i++) {
		//printf("pointer at: %u\n", 4 + (i * (CRYPTO_BYTES_LMS)));
		memcpy(to + 4 + (i * CRYPTO_BYTES_LMS), from->signed_pub_key[i],
		CRYPTO_BYTES_LMS);
		//print_hex(to + 4 + (i * CRYPTO_BYTES_LMS), CRYPTO_BYTES_LMS);
	}
	for (int i = 0; i < from->Nspk; i++) {
		memcpy(
				to + 4 + (from->Nspk * (CRYPTO_BYTES_LMS))
						+ (i * (LMS_PUB_KEY_SIZE)), from->pub_key[i],
				LMS_PUB_KEY_SIZE);
	}
	memcpy(
			to + 4 + (from->Nspk * (CRYPTO_BYTES_LMS))
					+ (from->Nspk * (LMS_PUB_KEY_SIZE)), from->sig,
			CRYPTO_BYTES_LMS);
}

void deserialize_hss_signature(unsigned char *from, hss_signature *to) {

	to->Nspk = bytes_to_ull(from, 4);
	for (int i = 0; i < to->Nspk; i++) {
		//printf("pointer at: %u\n", 4 + (i * (CRYPTO_BYTES_LMS)));
		memcpy(&to->signed_pub_key[i][0], from + 4 + (i * (CRYPTO_BYTES_LMS)),
		CRYPTO_BYTES_LMS);
		print_hex(from + 4 + (i * CRYPTO_BYTES_LMS), CRYPTO_BYTES_LMS);

	}
	//printf("pointer at: %u\n", 4 + (to->Nspk * (CRYPTO_BYTES_LMS)));
	print_hex(&to->signed_pub_key[0][0], CRYPTO_BYTES_LMS);
	for (int i = 0; i < to->Nspk; i++) {
	 memcpy(to->pub_key[i],
	 from + 4 + (to->Nspk * (CRYPTO_BYTES_LMS))
	 + (i * (LMS_PUB_KEY_SIZE)), LMS_PUB_KEY_SIZE);
	 }

	 memcpy(to->sig,
	 from + 4 + (to->Nspk * (CRYPTO_BYTES_LMS))
	 + (to->Nspk * (LMS_PUB_KEY_SIZE)),
	 CRYPTO_BYTES_LMS);
}*/
void refresh_keys(unsigned char *sk, int *to_refresh, int nr_to_refresh) {

	//unsigned char pub_serial[LMS_PUB_KEY_SIZE] = { 0 };
	for (int i = 0; i < nr_to_refresh; i++) {
		keygen_lms_private_key(sk + 8 + (to_refresh[i] * LMS_PRIV_KEY_SIZE));
		keygen_lms_public_key(sk + 8 + (to_refresh[i] * LMS_PRIV_KEY_SIZE),
				sk + 8 + (LEVELS * LMS_PRIV_KEY_SIZE)
						+ (to_refresh[i] * LMS_PUB_KEY_SIZE));
		//serialize_lms_public_key(sk->pubs[to_refresh[i]], pub_serial);
		lms_sign_internal_f(
				sk + 8 + (LEVELS * LMS_PRIV_KEY_SIZE)
						+ (to_refresh[i] * LMS_PUB_KEY_SIZE), LMS_PUB_KEY_SIZE,
				sk + 8 + ((to_refresh[i] - 1) * LMS_PRIV_KEY_SIZE),
				sk + 8 + (LEVELS * LMS_PRIV_KEY_SIZE)
						+ (LEVELS * LMS_PUB_KEY_SIZE)
						+ ((to_refresh[i] - 1) * CRYPTO_BYTES_LMS));

	}
}

int hss_sign(const unsigned char *message, const size_t input_size,
		unsigned char *sk, unsigned char *signature) {
	//deserialize_hss_private_key(sk, &private_key);
	unsigned long long remain = bytes_to_ull(sk, 4);

	if (remain == 0)
		return err_private_key_exhausted;

	int to_refresh[LEVELS] = { 0 };
	int is_to_refresh = 0;
	unsigned long long L = bytes_to_ull(sk + 4, 4);
	for (unsigned int i = 1; i < L; i++) {
		if (is_exhausted(sk + 16 + (i * LMS_PRIV_KEY_SIZE))) {
			to_refresh[is_to_refresh] = i;
			is_to_refresh++;
		}
	}
	if (is_to_refresh != 0) {
		refresh_keys(sk, to_refresh, is_to_refresh);
	}

	ull_to_bytes(signature, L - 1, 4);
	for (int i = 0; i < L - 1; i++) {
		/*deserialize_lms_signature(
		 sk + 8 + (L * LMS_PRIV_KEY_SIZE) + (L * LMS_PUB_KEY_SIZE)
		 + (i * CRYPTO_BYTES_LMS),
		 &hss_signature.signed_pub_key[i]);*/

		memcpy(signature + 4 + (i * (CRYPTO_BYTES_LMS)),
				sk + 8 + (L * LMS_PRIV_KEY_SIZE) + (L * LMS_PUB_KEY_SIZE)
						+ (i * CRYPTO_BYTES_LMS),
				CRYPTO_BYTES_LMS);
		/*deserialize_lms_public_key(
		 sk + 8 + (L * LMS_PRIV_KEY_SIZE) + ((i + 1) * LMS_PUB_KEY_SIZE),
		 &hss_signature.pub_key[i]);*/

		memcpy(
				signature + 4 + ((L - 1) * (CRYPTO_BYTES_LMS))
						+ (i * (LMS_PUB_KEY_SIZE)),
				sk + 8 + (L * LMS_PRIV_KEY_SIZE) + ((i + 1) * LMS_PUB_KEY_SIZE),
				LMS_PUB_KEY_SIZE);

	}
	lms_sign_internal_f(message, input_size,
			sk + 8 + ((L - 1) * LMS_PRIV_KEY_SIZE),
			signature + 4 + ((L - 1) * (CRYPTO_BYTES_LMS))
					+ ((L - 1) * (LMS_PUB_KEY_SIZE)));
	//deserialize_lms_signature(tmp_sig, &hss_signature.sig);

	//print_hss_signature(&hss_signature);
	//serialize_hss_signature(&hss_signature, signature);
	remain -= 1;
	ull_to_bytes(sk + 4, remain, 4);

	//serialize_hss_private_key(&private_key, sk);

	return 1;
}

int hss_verify(const unsigned char *message, const size_t input_size,
		unsigned char *pk, unsigned char *signature) {

	unsigned char tmp_pub[CRYPTO_BYTES_LMS];

	//deserialize_hss_public_key(pk, &public_key);
	/*deserialize_hss_signature(signature, &hss_sig);
	 print_hss_signature(&hss_sig);*/

	unsigned long long L = bytes_to_ull(pk, 4);
	unsigned long long nspk = bytes_to_ull(signature, 4);

	if (nspk + 1 != L)
		return err_wrong_levels;
	memcpy(tmp_pub, pk + 4, LMS_PUB_KEY_SIZE);

	for (int i = 0; i < nspk; i++) {
		if (lms_verify_internal_f(
				signature + 4 + (nspk * (CRYPTO_BYTES_LMS))
						+ (i * (LMS_PUB_KEY_SIZE)), LMS_PUB_KEY_SIZE, tmp_pub,
				signature + 4 + (i * (CRYPTO_BYTES_LMS))) != 1) {
			return err_invalid_signature;
		} else {
			memcpy(tmp_pub,
					signature + 4 + (nspk * (CRYPTO_BYTES_LMS))
							+ (i * (LMS_PUB_KEY_SIZE)),
					LMS_PUB_KEY_SIZE);
		}
	}

	return lms_verify_internal_f(message, input_size, tmp_pub,
			signature + 4 + (nspk * (CRYPTO_BYTES_LMS))
					+ (nspk * (LMS_PUB_KEY_SIZE)));
}
