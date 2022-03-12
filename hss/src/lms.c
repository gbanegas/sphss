/*
 * lms.c
 *
 *  Created on: Mar 2, 2022
 *      Author: Gustavo Banegas
 */

#include "lms.h"

void keygen_lms_private_key(lms_private_key *sk) {

	randombytes(sk->param_I, 16);
	sk->q = 0;
	sk->lmos_alg_type = LMOTS_ALG_TYPE;
	sk->lms_type = LMS_ALG_TYPE;
	randombytes(sk->SEED, 32);
}

void compute_node_r(const unsigned char *param_I, unsigned char *k,
		lmots_private_key *priv_keys, lmots_public_key *pub_keys,
		unsigned int r) {
	unsigned int max_digit = 1 << H;
	if (r >= max_digit) {
		uint16_t value = D_LEAF;
		uint8_t tmp[55] = { 0 };
		memcpy(tmp, param_I, 16);
		ull_to_bytes(tmp + 16, r, 4);
		memcpy(tmp + 20, &value, 2);
		memcpy(tmp + 22, pub_keys[r - max_digit].K, 32);
		sha3_256(k, tmp, 54);

	} else {
		uint8_t tmp_1[32] = { 0 };
		uint8_t tmp_2[32] = { 0 };
		uint16_t value = D_INTR;
		compute_node_r(param_I, tmp_1, priv_keys, pub_keys, 2 * r);
		compute_node_r(param_I, tmp_2, priv_keys, pub_keys, (2 * r) + 1);
		uint8_t tmp[87] = { 0 };
		memcpy(tmp, param_I, 16);
		ull_to_bytes(tmp + 16, r, 4);
		memcpy(tmp + 20, &value, 2);
		memcpy(tmp + 22, tmp_1, 32);
		memcpy(tmp + 54, tmp_2, 32);
		sha3_256(k, tmp, 86);

	}

}

void keygen_lms_public_key(lms_private_key *sk, lms_public_key *pk) {
	int max_digit = 1 << H;
	unsigned char tmp_S[20] = { 0 };
	memcpy(tmp_S, sk->param_I, 16);
	lmots_private_key priv_keys[(1 << H)];
	lmots_public_key pub_keys[(1 << H)];
	for (unsigned int j = 0; j < max_digit; j++) {
		ull_to_bytes(tmp_S + 16, j, 4);
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
	lms_private_key private_key;
	lms_public_key public_key;
	keygen_lms_private_key(&private_key);
	keygen_lms_public_key(&private_key, &public_key);
	serialize_lms_public_key(&public_key, pk);
	serialize_lms_private_key(&private_key, sk);

	return 1;
}
void compute_tree(const unsigned char *param_I, unsigned char *k,
		lmots_private_key *priv_keys, lmots_public_key *pub_keys,
		unsigned int r, Node *nodes) {
	unsigned int max_digit = 1 << H;

	if (r >= max_digit) {
		uint16_t value = D_LEAF;
		uint8_t tmp[55] = { 0 };
		memcpy(tmp, param_I, 16);
		ull_to_bytes(tmp + 16, r, 4);
		memcpy(tmp + 20, &value, 2);
		memcpy(tmp + 22, pub_keys[r - max_digit].K, 32);
		sha3_256(k, tmp, 54);
		memcpy(nodes[r].data, k, 32);

	} else {
		uint8_t tmp_1[32] = { 0 };
		uint8_t tmp_2[32] = { 0 };
		uint16_t value = D_INTR;
		compute_tree(param_I, tmp_1, priv_keys, pub_keys, 2 * r, nodes);
		compute_tree(param_I, tmp_2, priv_keys, pub_keys, (2 * r) + 1, nodes);
		uint8_t tmp[87] = { 0 };
		memcpy(tmp, param_I, 16);
		ull_to_bytes(tmp + 16, r, 4);
		memcpy(tmp + 20, &value, 2);
		memcpy(tmp + 22, tmp_1, 32);
		memcpy(tmp + 54, tmp_2, 32);
		sha3_256(k, tmp, 86);
		memcpy(nodes[r].data, k, 32);

	}

}
void compute_path(const unsigned char *param_I, lmots_private_key *priv_keys,
		lmots_public_key *pub_keys, unsigned int r, lms_path *path) {
	Node nodes[2 * (1 << H) + 1];
	unsigned char k[32] = { 0 };
	compute_tree(param_I, k, priv_keys, pub_keys, 1, nodes);

	unsigned int node_pos = (1 << H) + r;
	for (int i = 0; i < H; i++) {
		if ((node_pos % 2) != 0) {
			memcpy(path[i].node, nodes[node_pos - 1].data, 32);
		} else {
			memcpy(path[i].node, nodes[node_pos + 1].data, 32);
		}
		node_pos = node_pos / 2;
	}

}

void sign_and_compute_path(const unsigned char *message,
		const size_t input_size, lms_private_key *sk, lms_signature *sig) {
	int max_digit = 1 << H;
	unsigned char tmp_S[20] = { 0 };
	memcpy(tmp_S, sk->param_I, 16);
	lmots_private_key priv_keys[(1 << H)];
	lmots_public_key pub_keys[(1 << H)];
	for (int j = 0; j < max_digit; j++) {
		ull_to_bytes(tmp_S + 16, j, 4);
		memcpy(priv_keys[j].SEED, sk->SEED, 32);
		memcpy(priv_keys[j].S, tmp_S, 20);
		priv_keys[j].remain_sign = 1;
		priv_keys[j].alg_type = sk->lmos_alg_type;
		gen_lmots_public_key(&priv_keys[j], &pub_keys[j]);
	}
	lms_ots_sign_internal(message, input_size, &priv_keys[sk->q],
			&sig->lmots_sig);
	compute_path(sk->param_I, priv_keys, pub_keys, sk->q, sig->path);

}

int lms_sign_internal(const unsigned char *message, const size_t input_size,
		lms_private_key *sk, lms_signature *sig) {
	unsigned int max_digit = 1 << H;
	if (sk->q >= max_digit) {
		return err_private_key_exhausted;
	}
	sign_and_compute_path(message, input_size, sk, sig);
	sig->lms_type = sk->lms_type;
	sig->lmots_sig.alg_type = sk->lmos_alg_type;
	sig->q = sk->q;
	sk->q += 1;

	return 1;
}

int lms_sign(const unsigned char *message, const size_t input_size,
		unsigned char *sk, unsigned char *signature) {
	lms_private_key private_key;
	lms_signature sig;
	deserialize_lms_private_key(sk, &private_key);
	int ret = lms_sign_internal(message, input_size, &private_key, &sig);
	if (ret == 1) {
		serialize_lms_signature(&sig, signature);
		serialize_lms_private_key(&private_key, sk);
	}
	return ret;
}

void recover_lmots_public_key(lms_public_key *pk, lms_signature *sig,
		const unsigned char *message, const size_t input_size,
		unsigned char *pk_tc) {
	uint16_t a = D_MESG;
	unsigned char tmp_S[20] = { 0 };
	memcpy(tmp_S, pk->param_I, 16);
	ull_to_bytes(tmp_S + 16, sig->q, 4);
	unsigned char concat_message[54 + input_size];
	memset(concat_message, 0, 54 + input_size);

	memcpy(concat_message, tmp_S, 20);
	memcpy(concat_message + 20, &a, 2);
	memcpy(concat_message + 22, sig->lmots_sig.C, 32);
	memcpy(concat_message + 54, message, input_size);

	unsigned char hash[34] = { 0 };
	sha3_256(hash, concat_message, 54 + input_size);
	uint16_t checksum_result = 0;
	checksum_result = lms_ots_compute_checksum(hash);
	ull_to_bytes(hash + 32, checksum_result, 2);

	sha3_256incctx ctx;
	uint16_t D_public = 0x8080;
	uint_fast8_t tmp_concat[22] = { 0 };
	sha3_256_inc_init(&ctx);

	memcpy(tmp_concat, tmp_S, 20);
	memcpy(tmp_concat + 20, &D_public, 2);
	hash_update(tmp_concat, 22, &ctx);
	unsigned char concatenated[56] = { 0 };
	unsigned max_digit = (1 << W) - 1;
	for (int i = 0; i < P; i++) {
		unsigned char tmp[32] = { 0 };
		memcpy(tmp, sig->lmots_sig.y + (i * 32), 32);
		for (uint16_t j = lms_ots_coeff(hash, i, W); j < max_digit; j++) {
			concat_hash_value(tmp_S, tmp, i, j, concatenated);
			sha3_256(tmp, concatenated, 55);
		}
		hash_update(tmp, 32, &ctx);
	}
	sha3_256_inc_finalize(pk_tc, &ctx);

}

int lms_verify(const unsigned char *message, const size_t input_size,
		unsigned char *pk, unsigned char *signature) {
	lms_signature sig;
	lms_public_key public_key;
	//unsigned char lmots_pk[32] = { 0 };
	deserialize_lms_signature(signature, &sig);
	deserialize_lms_public_key(pk, &public_key);

	return lms_verify_internal(message, input_size, &public_key, &sig);
}

int lms_verify_internal(const unsigned char *message, const size_t input_size,
		lms_public_key *public_key, lms_signature *sig) {

	unsigned char lmots_pk[32] = { 0 };
	int max_digit = 1 << H;
	if (public_key->lms_type != sig->lms_type)
		return err_algorithm_mismatch;

	if (sig->q > max_digit)
		return err_invalid_signature;

	//TODO: add check path
	recover_lmots_public_key(public_key, sig, message, input_size, lmots_pk);
	unsigned int node_pos = sig->q + (1 << H);
	unsigned char tmp[87] = { 0 };
	memcpy(tmp, public_key->param_I, 16);
	ull_to_bytes(tmp + 16, node_pos, 4);
	ull_to_bytes(tmp + 20, D_LEAF, 2);
	memcpy(tmp + 22, lmots_pk, 32);
	unsigned char res[32] = { 0 };
	sha3_256(res, tmp, 54);
	for (int i = 0; i < H; i++) {
		if ((node_pos % 2) == 0) {
			memcpy(tmp, public_key->param_I, 16);
			ull_to_bytes(tmp + 16, (node_pos / 2), 4);
			ull_to_bytes(tmp + 20, D_INTR, 2);
			memcpy(tmp + 22, res, 32);
			memcpy(tmp + 54, sig->path[i].node, 32);

		} else {
			memcpy(tmp, public_key->param_I, 16);
			ull_to_bytes(tmp + 16, (node_pos / 2), 4);
			ull_to_bytes(tmp + 20, D_INTR, 2);
			memcpy(tmp + 22, sig->path[i].node, 32);
			memcpy(tmp + 54, res, 32);

		}
		sha3_256(res, tmp, 86);
		node_pos = node_pos / 2;
	}

	return memcmp(public_key->K, res, 32) == 0;

}

