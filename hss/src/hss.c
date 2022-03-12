/*
 * hss.c
 *
 *  Created on: Mar 2, 2022
 *      Author: Gustavo Banegas
 */

#include "hss.h"

void gen_hss_private_key(hss_private_key *sk) { //https://datatracker.ietf.org/doc/html/rfc8554#section-6.1
	sk->remain = (1 << (LEVELS * H));
	sk->L = LEVELS;
	keygen_lms_private_key(&sk->priv[0]);
	keygen_lms_public_key(&sk->priv[0], &sk->pubs[0]);
	for (int i = 1; i < LEVELS; i++) {
		keygen_lms_private_key(&sk->priv[i]);
		//memcpy(sk->priv[i].SEED, sk->priv[0].SEED, 32);
		keygen_lms_public_key(&sk->priv[i], &sk->pubs[i]);
		unsigned char pub_serial[LMS_PUB_KEY_SIZE] = { 0 };
		serialize_lms_public_key(&sk->pubs[i], pub_serial);
		lms_sign_internal(pub_serial, LMS_PUB_KEY_SIZE, &sk->priv[i - 1],
				&sk->sigs[i - 1]);
	}

}

void gen_hss_public_key(hss_private_key *sk, hss_public_key *pk) {
	pk->L = LEVELS;
	memcpy(&pk->pub, &sk->pubs[0], sizeof(lms_public_key));

}

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
}

int hss_keygen(unsigned char *sk, unsigned char *pk) {

	hss_private_key private_key;
	hss_public_key public_key;

	gen_hss_private_key(&private_key);
	gen_hss_public_key(&private_key, &public_key);

	serialize_hss_public_key(&public_key, pk);
	serialize_hss_private_key(&private_key, sk);

	return 1;
}

void serialize_hss_signature(hss_signature *from, unsigned char *to) {

	ull_to_bytes(to, from->Nspk, 4);
	for (int i = 0; i < from->Nspk; i++) {
		memcpy(to + 4 + (i * sizeof(lms_signature)), &from->signed_pub_key[i],
				sizeof(lms_signature));
	}
	for (int i = 0; i < from->Nspk; i++) {
		memcpy(
				to + 4 + (from->Nspk * sizeof(lms_signature))
						+ (i * sizeof(lms_public_key)), &from->pub_key[i],
				sizeof(lms_public_key));
	}
	memcpy(
			to + 4 + (from->Nspk * sizeof(lms_signature))
					+ (from->Nspk * sizeof(lms_public_key)), &from->sig,
			sizeof(lms_signature));
}

void deserialize_hss_signature(unsigned char *from, hss_signature *to) {

	to->Nspk = bytes_to_ull(from, 4);
	for (int i = 0; i < to->Nspk; i++) {
		memcpy(&to->signed_pub_key[i], from + 4 + (i * sizeof(lms_signature)),
				sizeof(lms_signature));
	}
	for (int i = 0; i < to->Nspk; i++) {
		memcpy(&to->pub_key[i],
				from + 4 + (to->Nspk * sizeof(lms_signature))
						+ (i * sizeof(lms_public_key)), sizeof(lms_public_key));
	}
	memcpy(&to->sig,
			from + 4 + (to->Nspk * sizeof(lms_signature))
					+ (to->Nspk * sizeof(lms_public_key)),
			sizeof(lms_signature));
}

int hss_sign(const unsigned char *message, const size_t input_size,
		unsigned char *sk, unsigned char *signature) {
	hss_private_key private_key;
	deserialize_hss_private_key(sk, &private_key);

	if (private_key.remain == 0)
		return err_private_key_exhausted;
	//TODO: check if it is exhausted
	hss_signature hss_signature;
	hss_signature.Nspk = private_key.L - 1;
	lms_sign_internal(message, input_size, &private_key.priv[private_key.L - 1],
			&hss_signature.sig);
	for (int i = 0; i < private_key.L - 1; i++) {
		memcpy(&hss_signature.signed_pub_key[i], &private_key.sigs[i],
				sizeof(lms_signature));
		memcpy(&hss_signature.pub_key[i], &private_key.pubs[i + 1],
				sizeof(lms_public_key));
	}
	serialize_hss_signature(&hss_signature, signature);
	private_key.remain -= 1;

	serialize_hss_private_key(&private_key, sk);

	return 1;
}

int hss_verify(const unsigned char *message, const size_t input_size,
		unsigned char *pk, unsigned char *signature) {

	hss_public_key public_key;
	hss_signature hss_signature;

	deserialize_hss_public_key(pk, &public_key);
	deserialize_hss_signature(signature, &hss_signature);

	if (hss_signature.Nspk + 1 != public_key.L)
		return err_wrong_levels;

	for (int i = 0; i < hss_signature.Nspk; i++) {
		unsigned char pub_serial[LMS_PUB_KEY_SIZE] = { 0 };
		serialize_lms_public_key(&hss_signature.pub_key[i], pub_serial);
		if (!lms_verify_internal(pub_serial, LMS_PUB_KEY_SIZE, &public_key.pub,
				&hss_signature.signed_pub_key[i])) {
			return err_invalid_signature;
		} else {
			memcpy(&public_key.pub, &hss_signature.pub_key[i],
					sizeof(lms_public_key));
		}
	}
	return lms_verify_internal(message, input_size, &public_key.pub,
			&hss_signature.sig);
}
