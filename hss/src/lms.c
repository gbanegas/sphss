/*
 * lms.c
 *
 *  Created on: Mar 2, 2022
 *      Author: Gustavo Banegas
 */

#include "lms.h"

void gen_lms_private_key(lms_private_key *sk) {
	randombytes(sk->param_I, 16);
	sk->q = 0;
	sk->lmos_alg_type = LMOTS_ALG_TYPE;
	sk->lms_type = LMS_ALG_TYPE;
	randombytes(sk->SEED, 32);
	//int max_digit = 1 << H;
}

void compute_node_r(const unsigned char *param_I, unsigned char *k,
		lmots_private_key *priv_keys, lmots_public_key *pub_keys,
		unsigned int r) {
	unsigned int max_digit = 1 << H;
	if (r >= max_digit) {
		uint16_t value = D_LEAF;
		uint8_t tmp[55] = { 0 };
		memcpy(tmp, param_I, 16);
		put_bigendian(tmp + 16, r, 4);
		memcpy(tmp + 20, &value, 2);
		memcpy(tmp + 22, pub_keys[r - max_digit].K, 32);
		sha3_256(k, tmp, 55);
	} else {
		uint8_t tmp_1[32] = { 0 };
		uint8_t tmp_2[32] = { 0 };
		uint16_t value = D_INTR;
		compute_node_r(param_I, tmp_1, priv_keys, pub_keys, 2 * r);
		compute_node_r(param_I, tmp_2, priv_keys, pub_keys, (2 * r) + 1);
		uint8_t tmp[87] = { 0 };
		memcpy(tmp, param_I, 16);
		put_bigendian(tmp + 16, r, 4);
		memcpy(tmp + 20, &value, 2);
		memcpy(tmp + 22, tmp_1, 32);
		memcpy(tmp + 54, tmp_2, 32);
		sha3_256(k, tmp, 87);

	}

}

void gen_lms_public_key(lms_private_key *sk, lms_public_key *pk) {
	pk->lms_type = sk->lms_type;
	pk->lmos_alg_type = sk->lmos_alg_type;
	int max_digit = 1 << H;
	unsigned char tmp_S[20] = { 0 };
	memcpy(tmp_S, sk->param_I, 16);
	lmots_private_key priv_keys[(1 << H)];
	lmots_public_key pub_keys[(1 << H)];
	for (int j = 0; j < max_digit; j++) {
		put_bigendian(tmp_S + 16, j, 4);
		memcpy(priv_keys[j].SEED, sk->SEED, 32);
		memcpy(priv_keys[j].S, tmp_S, 20);
		priv_keys[j].alg_type = sk->lmos_alg_type;
		gen_lmots_public_key(&priv_keys[j], &pub_keys[j]);
	}
	pk->lmos_alg_type = sk->lmos_alg_type;
	pk->lms_type = sk->lms_type;
	memcpy(pk->param_I, sk->param_I, 16);
	compute_node_r(pk->param_I, pk->K, priv_keys, pub_keys, 1);

}

int lms_keygen(unsigned char *sk, unsigned char *pk) {
	//TODO: put number in big endian
	lms_private_key private_key;
	lms_public_key public_key;
	gen_lms_private_key(&private_key);
	gen_lms_public_key(&private_key, &public_key);
	memcpy(sk, &private_key.lmos_alg_type, 4);
	memcpy(sk + 4, &private_key.lms_type, 4);
	memcpy(sk + 8, private_key.param_I, 16);
	memcpy(sk + 24, private_key.SEED, 32);
	memcpy(sk + 56, &private_key.q, 4);

	memcpy(pk, &public_key.lmos_alg_type, 4);
	memcpy(pk + 4, &public_key.lms_type, 4);
	memcpy(pk + 8, public_key.param_I, 16);
	memcpy(pk + 24, public_key.K, 32);

	return 1;
}

