/*
 * hss.c
 *
 *  Created on: Mar 2, 2022
 *      Author: Gustavo Banegas
 */

#include "hss.h"

void gen_hss_private_key(hss_private_key *sk) {//https://datatracker.ietf.org/doc/html/rfc8554#section-6.1
	sk->remain = (1 << (LEVELS * H));
	sk->L = LEVELS;
	gen_lms_private_key(&sk->priv[0]);
	gen_lms_public_key(&sk->priv[0], &sk->pubs[0]);
	for (int i = 1; i < LEVELS; i++) {
		gen_lms_private_key(&sk->priv[i]);
		memcpy(sk->priv[i].SEED, sk->priv[0].SEED, 32);
		gen_lms_public_key(&sk->priv[i], &sk->pubs[i]);
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

	private_key->L = get_bigendian(sk, 4);
	for (unsigned int i = 0; i < private_key->L; i++) {
		private_key->priv[i].lmos_alg_type = get_bigendian(sk + 4 + (i * 64),
				4);
		private_key->priv[i].lms_type = get_bigendian(sk + 8 + (i * 64), 4);
		memcpy(private_key->priv[i].param_I, sk + 12 + (i * 64), 16);
		memcpy(private_key->priv[i].SEED, sk + 28 + (i * 64), 32);
		private_key->priv[i].q = get_bigendian(sk + 60 + (i * 64), 4);

	}
	for (unsigned int i = 1; i < private_key->L; i++) {
		deserialize_lms_public_key(
				sk + 64 + (i * (LMS_PUB_KEY_SIZE + CRYPTO_BYTES_LMS)),
				&private_key->pubs[i]);
		deserialize_lms_signature(
				sk + 64 + LMS_PUB_KEY_SIZE
						+ (i * (LMS_PUB_KEY_SIZE + CRYPTO_BYTES_LMS)),
				&private_key->sigs[i - 1]);
	}

}

void serialize_hss_private_key(hss_private_key *private_key, unsigned char *sk) {
	put_bigendian(sk, private_key->L, 4);
	for (unsigned int i = 0; i < private_key->L; i++) {
		put_bigendian(sk + 4 + (i * 64), private_key->priv[i].lmos_alg_type, 4);
		put_bigendian(sk + 8 + (i * 64), private_key->priv[i].lms_type, 4);
		memcpy(sk + 12 + (i * 64), private_key->priv[i].param_I, 16);
		memcpy(sk + 28 + (i * 64), private_key->priv[i].SEED, 32);
		put_bigendian(sk + 60 + (i * 64), private_key->priv[i].q, 4);

	}
	for (unsigned int i = 1; i < private_key->L; i++) {
		serialize_lms_public_key(&private_key->pubs[i],
				sk + 64 + (i * (LMS_PUB_KEY_SIZE + CRYPTO_BYTES_LMS)));
		serialize_lms_signature(&private_key->sigs[i - 1],
				sk + 64 + LMS_PUB_KEY_SIZE
						+ (i * (LMS_PUB_KEY_SIZE + CRYPTO_BYTES_LMS)));
	}

}

void deserialize_hss_public_key(unsigned char *pk, hss_public_key *public_key) {
	public_key->L = get_bigendian(pk, 4);
	public_key->pub.lmos_alg_type = get_bigendian(pk + 4, 4);
	public_key->pub.lms_type = get_bigendian(pk + 8, 4);
	memcpy(public_key->pub.param_I, pk + 12, 16);
	memcpy(public_key->pub.K, pk + 28, 32);
}

void serialize_hss_public_key(hss_public_key *public_key, unsigned char *pk) {
	put_bigendian(pk, public_key->L, 4);
	put_bigendian(pk + 4, public_key->pub.lmos_alg_type, 4);
	put_bigendian(pk + 8, public_key->pub.lms_type, 4);
	memcpy(pk + 12, public_key->pub.param_I, 16);
	memcpy(pk + 28, public_key->pub.K, 32);
}

int hss_keygen(unsigned char *sk, unsigned char *pk) {

	hss_private_key private_key;
	hss_public_key public_key;

	gen_hss_private_key(&private_key);
	gen_hss_public_key(&private_key, &public_key);

	print_hss_private_key(&private_key);
	print_hss_public_key(&public_key);

	serialize_hss_public_key(&public_key, pk);
	serialize_hss_private_key(&private_key, sk);

	return 1;
}



int hss_sign(const unsigned char *message, const size_t input_size,
		unsigned char *sk, unsigned char *signature) {
	hss_private_key private_key;
	deserialize_hss_private_key(sk, &private_key);
	print_hss_private_key(&private_key);
	//TODO: check if it still valid
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
	print_hss_signature(&hss_signature);
	//put_bigendian(signature, private_key.L - 1, 4);
	//for (int i = 1; i < private_key.L; i++) {

	/*serialize_lms_signature(&private_key.sigs[1], signature + 4);
	 serialize_lms_public_key(&private_key.pubs[1],
	 signature + 4 + CRYPTO_BYTES_LMS);
	 //	}
	 serialize_lms_signature(&tmp_sig,
	 signature + 4 + CRYPTO_BYTES_LMS + HSS_PUBLIC_KEY);*/

	return 1;
}
