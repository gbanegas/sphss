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

void deserialize_private_key(unsigned char *from, lms_private_key *to) {
	to->lmos_alg_type = get_bigendian(from, 4);
	to->lms_type = get_bigendian(from + 4, 4);
	memcpy(to->param_I, from + 8, 16);
	memcpy(to->SEED, from + 24, 32);
	to->q = get_bigendian(from + 56, 4);

}

void serialize_private_key(lms_private_key *from, unsigned char *to) {
	put_bigendian(to, from->lmos_alg_type, 4);
	//memcpy(to, &from->lmos_alg_type, 4);
	put_bigendian(to + 4, from->lms_type, 4);
	memcpy(to + 8, from->param_I, 16);
	memcpy(to + 24, from->SEED, 32);
	put_bigendian(to + 56, from->q, 4);

}
void deserialize_public_key(unsigned char *from, lms_public_key *to) {

	to->lmos_alg_type = get_bigendian(from, 4);
	to->lms_type = get_bigendian(from + 4, 4);
	memcpy(to->param_I, from + 8, 16);
	memcpy(to->K, from + 24, 32);

}

void serialize_public_key(lms_public_key *from, unsigned char *to) {
	put_bigendian(to, from->lmos_alg_type, 4);
	put_bigendian(to + 4, from->lms_type, 4);
	memcpy(to + 8, from->param_I, 16);
	memcpy(to + 24, from->K, 32);

}
int lms_keygen(unsigned char *sk, unsigned char *pk) {
	lms_private_key private_key;
	lms_public_key public_key;
	gen_lms_private_key(&private_key);
	gen_lms_public_key(&private_key, &public_key);
	serialize_public_key(&public_key, pk);
	serialize_private_key(&private_key, sk);

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
		put_bigendian(tmp + 16, r, 4);
		memcpy(tmp + 20, &value, 2);
		memcpy(tmp + 22, pub_keys[r - max_digit].K, 32);
		sha3_256(nodes[r].data, tmp, 55);
	} else {
		uint8_t tmp_1[32] = { 0 };
		uint8_t tmp_2[32] = { 0 };
		uint16_t value = D_INTR;
		uint8_t tmp[87] = { 0 };
		compute_tree(param_I, tmp_1, priv_keys, pub_keys, 2 * r, nodes);
		compute_tree(param_I, tmp_2, priv_keys, pub_keys, (2 * r) + 1, nodes);
		memcpy(tmp, param_I, 16);
		put_bigendian(tmp + 16, r, 4);
		memcpy(tmp + 20, &value, 2);
		memcpy(tmp + 22, tmp_1, 32);
		memcpy(tmp + 54, tmp_2, 32);
		sha3_256(nodes[r].data, tmp, 87);

	}

}
void compute_path(const unsigned char *param_I, lmots_private_key *priv_keys,
		lmots_public_key *pub_keys, unsigned int r, lms_path *path) {
	Node nodes[2 * (1 << H) + 1];
	int index = 0;
	compute_tree(param_I, 0, priv_keys, pub_keys, 1, nodes);
	unsigned int node_pos = (1 << H) + r;
	while (node_pos > 1) {
		if ((node_pos % 2) == 0) {
			memcpy(path[index].node, nodes[node_pos - 1].data, 32);
		} else {
			memcpy(path[index].node, nodes[node_pos + 1].data, 32);
		}
		index++;
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
		put_bigendian(tmp_S + 16, j, 4);
		memcpy(priv_keys[j].SEED, sk->SEED, 32);
		memcpy(priv_keys[j].S, tmp_S, 20);
		priv_keys[j].alg_type = sk->lmos_alg_type;
		gen_lmots_public_key(&priv_keys[j], &pub_keys[j]);
	}
	lms_ots_sign_internal(message, input_size, &priv_keys[sk->q],
			&sig->lmots_sig);
	compute_path(sk->param_I, priv_keys, pub_keys, sk->q, sig->path);

}

void serialize_lms_signature(lms_signature *from, unsigned char *to) {
	put_bigendian(to, from->q, 4);
	put_bigendian(to + 4, from->lmots_sig.alg_type, 4);
	memcpy(to + 8, from->lmots_sig.C, 32);
	memcpy(to + 40, from->lmots_sig.y, 32 * P);
	put_bigendian(to + (40 + (32 * P)), from->lms_type, 4);
	for (int i = 0; i < H; i++) {
		memcpy(to + (44 + (32 * P) + (i * 32)), from->path[i].node, 32);
	}

}

int lms_sign(const unsigned char *message, const size_t input_size,
		unsigned char *sk, unsigned char *signature) {
	lms_private_key private_key;
	lms_signature sig;
	deserialize_private_key(sk, &private_key);
	unsigned int max_digit = 1 << H;
	if (private_key.q > max_digit) {
		return 0;
	}
	sign_and_compute_path(message, input_size, &private_key, &sig);
	sig.lms_type = private_key.lms_type;
	sig.q = private_key.q;
	private_key.q += 1;
	print_lms_signature(&sig);

	serialize_lms_signature(&sig, signature);
	serialize_private_key(&private_key, sk);

	return 1;
}

