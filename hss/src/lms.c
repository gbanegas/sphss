/*
 * lms.c
 *
 *  Created on: Mar 2, 2022
 *      Author: Gustavo Banegas
 */

#include "lms.h"

void gen_lms_private_key(lms_private_key *sk) {
	uint8_t p_I[] = { 0xd7, 0x62, 0xd3, 0xf3, 0xa8, 0x61, 0x1a, 0x4a, 0x8c,
			0x19, 0x5a, 0x8f, 0x21, 0x3c, 0x8f, 0x35 };
	uint8_t seed[] = { 0x9d, 0x91, 0x4e, 0x71, 0x15, 0x86, 0xa9, 0x2c, 0x40,
			0x21, 0x73, 0x77, 0x37, 0x1e, 0xb6, 0x3e, 0x3f, 0xdf, 0x2e, 0x38,
			0x89, 0xe5, 0xb9, 0x6f, 0x63, 0x4d, 0x72, 0x1a, 0xb7, 0xfd, 0xdd,
			0xe1 };
	memcpy(sk->param_I, p_I, 16);
	memcpy(sk->SEED, seed, 32);
	//randombytes(sk->param_I, 16);
	sk->q = 0;
	sk->lmos_alg_type = LMOTS_ALG_TYPE;
	sk->lms_type = LMS_ALG_TYPE;
	//randombytes(sk->SEED, 32);
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
		sha3_256(k, tmp, 54);

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
		sha3_256(k, tmp, 86);

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
	for (unsigned int j = 0; j < max_digit; j++) {
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
		put_bigendian(tmp + 16, r, 4);
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

void deserialize_lms_signature(unsigned char *from, lms_signature *to) {
	to->q = get_bigendian(from, 4);
	to->lmots_sig.alg_type = get_bigendian(from + 4, 4);
	memcpy(to->lmots_sig.C, from + 8, 32);
	memcpy(to->lmots_sig.y, from + 40, 32 * P);
	to->lms_type = get_bigendian(from + (40 + (32 * P)), 4);
	for (int i = 0; i < H; i++) {
		memcpy(to->path[i].node, from + (44 + (32 * P) + (i * 32)), 32);
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


	serialize_lms_signature(&sig, signature);
	serialize_private_key(&private_key, sk);

	return 1;
}

void recover_lmots_public_key(lms_public_key *pk, lms_signature *sig,
		const unsigned char *message, const size_t input_size,
		lmots_public_key *pk_tc) {
	uint16_t a = D_MESG;
	unsigned char tmp_S[20] = { 0 };
	memcpy(tmp_S, pk->param_I, 16);
	put_bigendian(tmp_S + 16, sig->q, 4);

	unsigned char concat_message[86] = { 0 };

	/*printf("y: ");
	 print_hex(sig.y, P * 32);*/

	memcpy(concat_message, tmp_S, 20);
	memcpy(concat_message + 20, &a, 2);
	memcpy(concat_message + 22, sig->lmots_sig.C, 32);
	memcpy(concat_message + 54, message, input_size);

	unsigned char hash[34] = { 0 };
	sha3_256(hash, concat_message, 54 + input_size);
	uint16_t checksum_result = 0;
	checksum_result = lms_ots_compute_checksum(hash);
	uint8_t buff_check[2] = { 0 };
	put_bigendian(buff_check, checksum_result, 2);
	memcpy(hash + 32, buff_check, 2);

	sha3_256incctx ctx;
	uint16_t D_public = 0x8080;
	uint_fast8_t tmp_concat[22] = { 0 };
	sha3_256_inc_init(&ctx);

	memcpy(tmp_concat, tmp_S, 20);
	memcpy(tmp_concat + 20, &D_public, 2);
	hash_update(tmp_concat, 22, &ctx);
	unsigned char concatenated[55] = { 0 };
	unsigned max_digit = (1 << W) - 1;
	for (int i = 0; i < P; i++) {
		unsigned char tmp[32] = { 0 };
		memcpy(tmp, sig->lmots_sig.y + (i * 32), 32);
		for (uint16_t j = lms_ots_coeff(hash, i, W); j < max_digit; j++) {
			concat_hash_value(tmp_S, tmp, i, j, concatenated);
			sha3_256(tmp, concatenated, 54);
		}
		hash_update(tmp, 32, &ctx);
	}
	sha3_256_inc_finalize(pk_tc->K, &ctx);

}

int lms_verify(const unsigned char *message, const size_t input_size,
		unsigned char *pk, unsigned char *signature) {
	lms_signature sig;
	lms_public_key public_key;
	lmots_public_key lmots_pk;
	deserialize_lms_signature(signature, &sig);
	deserialize_public_key(pk, &public_key);
	print_lms_signature(&sig);
	//TODO: add the verifications
	recover_lmots_public_key(&public_key, &sig, message, input_size, &lmots_pk);
	unsigned int node_pos = sig.q + (1 << H);
	unsigned char tmp[87] = { 0 };
	memcpy(tmp, public_key.param_I, 16);
	put_bigendian(tmp + 16, node_pos, 4);
	put_bigendian(tmp + 20, D_LEAF, 2);
	memcpy(tmp + 22, lmots_pk.K, 32);
	unsigned char res[32] = { 0 };
	sha3_256(res, tmp, 54);
	for (int i = 0; i < H; i++) {
		memset(tmp, 0, 86);
		memcpy(tmp, public_key.param_I, 16);
		put_bigendian(tmp + 16, node_pos / 2, 4);
		put_bigendian(tmp + 20, D_INTR, 2);
		if ((node_pos % 2) != 0) {
			memcpy(tmp + 22, sig.path[i].node, 32);
			memcpy(tmp + 54, res, 32);

		} else {
			memcpy(tmp + 32, res, 32);
			memcpy(tmp + 54, sig.path[i].node, 32);
		}
		sha3_256(res, tmp, 86);
		node_pos /= 2;
	}
	print_hex(public_key.K, 32);
	print_hex(res, 32);

	return memcmp(public_key.K, res, 32);

}

