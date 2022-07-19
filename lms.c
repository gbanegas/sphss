/*
 * lms.c
 *
 *  Created on: Mar 2, 2022
 *      Author: Gustavo Banegas
 */

#include "lms.h"

void keygen_lms_private_key(unsigned char *sk) {

	ull_to_bytes(sk, LMOTS_ALG_TYPE, 4);
	ull_to_bytes(sk + 4, LMS_ALG_TYPE, 4);

	randombytes(sk + 8, 16);
	randombytes(sk + 24, 32);
	ull_to_bytes(sk + 56, 0, 4);
}

void compute_node_r(const unsigned char *param_I, unsigned char *k,
		unsigned char priv_keys[1 << H][LMSOTS_PRIV_KEY_SIZE],
		unsigned char pub_keys[1 << H][LMSOTS_PUB_KEY_SIZE], unsigned int r) {
	unsigned int max_digit = 1 << H;
	if (r >= max_digit) {
		uint16_t value = D_LEAF;
		uint8_t tmp[55] = { 0 };
		memcpy(tmp, param_I, 16);
		ull_to_bytes(tmp + 16, r, 4);
		memcpy(tmp + 20, &value, 2);
		memcpy(tmp + 22, pub_keys[r - max_digit] + 4, 32);
		//hash(tmp, 54, k);
		sha256(tmp, 54, k);
		//sha3_256(k, tmp, 54);

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
		//hash(tmp, 86, k);
		sha256(tmp, 86, k);
		//sha3_256(k, tmp, 86);

	}

}

void keygen_lms_public_key(unsigned char *sk, unsigned char *pk) {
	int max_digit = 1 << H;
	unsigned char tmp_S[20] = { 0 };
	memcpy(tmp_S, sk + 8, 16);
	unsigned char priv_keys[(1 << H)][LMSOTS_PRIV_KEY_SIZE];
	unsigned char pub_keys[(1 << H)][LMSOTS_PUB_KEY_SIZE];
	for (unsigned int j = 0; j < max_digit; j++) {
		ull_to_bytes(tmp_S + 16, j, 4);
		memcpy(priv_keys[j] + 4, tmp_S, 20);

		memcpy(priv_keys[j] + 24, sk + 24, 32);
		ull_to_bytes(priv_keys[j], LMOTS_ALG_TYPE, 4);
		gen_lmots_public_key(priv_keys[j], pub_keys[j]);
	}

	/*for (int j = 0; j < max_digit; j++) {
	 print_lmots_public_key_pure(pub_keys[j]);
	 }*/

	/*for (int i = 0; i < 1 << H; i++) {
	 print_lmots_public_key_pure(pub_keys[i]);
	 }*/
	ull_to_bytes(pk, LMOTS_ALG_TYPE, 4);
	ull_to_bytes(pk + 4, LMS_ALG_TYPE, 4);
	memcpy(pk + 8, sk + 8, 16);
	compute_node_r(pk + 8, pk + 24, priv_keys, pub_keys, 1);

}

int lms_keygen(unsigned char *sk, unsigned char *pk) {
	keygen_lms_private_key(sk);
	keygen_lms_public_key(sk, pk);
	//serialize_lms_public_key(&public_key, pk);
	//serialize_lms_private_key(&private_key, sk);

	return 1;
}
void compute_tree(const unsigned char *param_I, unsigned char *k,
		unsigned char priv_keys[1 << H][LMSOTS_PRIV_KEY_SIZE],
		unsigned char pub_keys[1 << H][LMSOTS_PUB_KEY_SIZE], unsigned int r,
		Node *nodes) {
	unsigned int max_digit = 1 << H;

	if (r >= max_digit) {
		uint16_t value = D_LEAF;
		uint8_t tmp[55] = { 0 };
		memcpy(tmp, param_I, 16);
		ull_to_bytes(tmp + 16, r, 4);
		memcpy(tmp + 20, &value, 2);
		memcpy(tmp + 22, pub_keys[r - max_digit] + 4, 32);
		//hash(tmp, 54, k);
		sha256(tmp, 54, k);
		//sha3_256(k, tmp, 54);
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
		//hash(tmp, 86, k);
		sha256(tmp, 86, k);
		//sha3_256(k, tmp, 86);
		memcpy(nodes[r].data, k, 32);

	}

}
void compute_path(const unsigned char *param_I,
		unsigned char priv_keys[1 << H][LMSOTS_PRIV_KEY_SIZE],
		unsigned char pub_keys[1 << H][LMSOTS_PUB_KEY_SIZE], unsigned int r,
		lms_path *path) {
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
void compute_path_f(const unsigned char *param_I,
		unsigned char priv_keys[1 << H][LMSOTS_PRIV_KEY_SIZE],
		unsigned char pub_keys[1 << H][LMSOTS_PUB_KEY_SIZE], unsigned int r,
		unsigned char *path) {
	Node nodes[2 * (1 << H) + 1];
	unsigned char k[32] = { 0 };
	compute_tree(param_I, k, priv_keys, pub_keys, 1, nodes);

	unsigned int node_pos = (1 << H) + r;
	for (int i = 0; i < H; i++) {
		if ((node_pos % 2) != 0) {
			memcpy(path + (i * 32), nodes[node_pos - 1].data, 32);
		} else {
			memcpy(path + (i * 32), nodes[node_pos + 1].data, 32);
		}
		node_pos = node_pos / 2;
	}

}

void sign_and_compute_path(const unsigned char *message,
		const size_t input_size, unsigned char *sk, lms_signature *sig) {
	int max_digit = 1 << H;
	unsigned char tmp_S[20] = { 0 };
	memcpy(tmp_S, sk + 8, 16);
	unsigned char priv_keys[(1 << H)][LMSOTS_PRIV_KEY_SIZE];
	unsigned char pub_keys[(1 << H)][LMSOTS_PUB_KEY_SIZE];
	int alg_type = bytes_to_ull(sk, 4);
	unsigned long long q = bytes_to_ull(sk + 56, 4);
	sig->lms_type = LMS_ALG_TYPE;
	for (int j = 0; j < max_digit; j++) {
		ull_to_bytes(tmp_S + 16, j, 4);
		memcpy(priv_keys[j] + 24, sk + 24, 32);
		memcpy(priv_keys[j] + 4, tmp_S, 20);
		ull_to_bytes(priv_keys[j] + 56, 1, 4);
		ull_to_bytes(priv_keys[j], alg_type, 4);
		gen_lmots_public_key(priv_keys[j], pub_keys[j]);
	}

	lms_ots_sign(message, input_size, priv_keys[q], sig->lmots_sig);
	compute_path(sk + 8, priv_keys, pub_keys, q, sig->path);

}

void sign_and_compute_path_f(const unsigned char *message,
		const size_t input_size, unsigned char *sk, unsigned char *sig) {
	int max_digit = 1 << H;
	unsigned char tmp_S[20] = { 0 };
	memcpy(tmp_S, sk + 8, 16);
	unsigned char priv_keys[(1 << H)][LMSOTS_PRIV_KEY_SIZE];
	unsigned char pub_keys[(1 << H)][LMSOTS_PUB_KEY_SIZE];
	int alg_type = bytes_to_ull(sk, 4);
	unsigned long long q = bytes_to_ull(sk + 56, 4);
	//sig->lms_type = LMS_ALG_TYPE;
	for (int j = 0; j < max_digit; j++) {
		ull_to_bytes(tmp_S + 16, j, 4);
		memcpy(priv_keys[j] + 24, sk + 24, 32);
		memcpy(priv_keys[j] + 4, tmp_S, 20);
		ull_to_bytes(priv_keys[j] + 56, 1, 4);
		ull_to_bytes(priv_keys[j], alg_type, 4);
		gen_lmots_public_key(priv_keys[j], pub_keys[j]);
	}
	lms_ots_sign(message, input_size, priv_keys[q], sig + 4);
	compute_path_f(sk + 8, priv_keys, pub_keys, q, sig + (44 + (32 * P)));

}

int lms_sign_internal(const unsigned char *message, const size_t input_size,
		lms_private_key *sk, lms_signature *sig) {
	unsigned int max_digit = 1 << H;
	if (sk->q >= max_digit) {
		return err_private_key_exhausted;
	}
	//sign_and_compute_path(message, input_size, sk, sig);
	sig->lms_type = sk->lms_type;
	sig->q = sk->q;
	sk->q += 1;

	return 1;
}
int is_exhausted(unsigned char *key) {
	unsigned long long q = bytes_to_ull(key, 4);
	unsigned long long max_digit = 1 << H;
	return (max_digit - q) == 0;

}

int lms_sign_internal_f(const unsigned char *message, const size_t input_size,
		unsigned char *sk, unsigned char *signature) {

	//lms_signature sig;
	unsigned long long max_digit = 1 << H;
	unsigned long long q = bytes_to_ull(sk + 56, 4);
	if (q >= max_digit) {
		return err_private_key_exhausted;
	}
	ull_to_bytes(signature, q, 4);
	ull_to_bytes(signature + 4, LMOTS_ALG_TYPE, 4);
	ull_to_bytes(signature + (40 + (32 * P)), LMS_ALG_TYPE, 4);

	sign_and_compute_path_f(message, input_size, sk, signature);
	//sig->lms_type = sk->lms_type;
	//sig->q = sk->q;
	//serialize_lms_signature(&sig, signature);
	q += 1;
	ull_to_bytes(sk + 56, q, 4);

	return 1;

}

int lms_sign(const unsigned char *message, const size_t input_size,
		unsigned char *sk, unsigned char *signature) {
	//lms_private_key private_key;
	//lms_signature sig;
	//deserialize_lms_private_key(sk, &private_key);
	int ret = lms_sign_internal_f(message, input_size, sk, signature);

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
	memcpy(concat_message + 22, sig->lmots_sig + 4, 32);
	memcpy(concat_message + 54, message, input_size);

	unsigned char hash[34] = { 0 };
	sha256(concat_message, 54 + input_size, hash);
	//hash(concat_message, 54 + input_size, hash);
	uint16_t checksum_result = 0;
	checksum_result = lms_ots_compute_checksum(hash);
	ull_to_bytes(hash + 32, checksum_result, 2);

	sha256_ctx ctx;
	uint16_t D_public = 0x8080;
	uint8_t tmp_concat[22] = { 0 };
	sha256_init(&ctx);
	//sha2_256_init(&ctx, pk_tc);

	memcpy(tmp_concat, tmp_S, 20);
	memcpy(tmp_concat + 20, &D_public, 2);
	sha256_update(&ctx, tmp_concat, 22);
	//hash_update(tmp_concat, 22, &ctx);
	unsigned char concatenated[56] = { 0 };
	unsigned max_digit = (1 << W) - 1;
	for (int i = 0; i < P; i++) {
		unsigned char tmp[32] = { 0 };
		memcpy(tmp, sig->lmots_sig + 36 + (i * 32), 32);
		for (uint16_t j = lms_ots_coeff(hash, i, W); j < max_digit; j++) {
			concat_hash_value(tmp_S, tmp, i, j, concatenated);
			sha256(concatenated, 55, tmp);
			//sha3_256(tmp, concatenated, 55);
		}
		sha256_update(&ctx, tmp, 32);
	}
	sha256_final(&ctx, pk_tc);
	/*(void) sha2_256_finish(&ctx);

	 uint16_t a = D_MESG;
	 unsigned char tmp_S[20] = { 0 };
	 memcpy(tmp_S, pk->param_I, 16);
	 ull_to_bytes(tmp_S + 16, sig->q, 4);
	 unsigned char concat_message[54 + input_size];
	 memset(concat_message, 0, 54 + input_size);

	 memcpy(concat_message, tmp_S, 20);
	 memcpy(concat_message + 20, &a, 2);
	 memcpy(concat_message + 22, sig->lmots_sig + 4, 32);
	 memcpy(concat_message + 54, message, input_size);

	 unsigned char hash[34] = { 0 };
	 sha256(concat_message, 54 + input_size, hash);
	 //hash(concat_message, 54 + input_size, hash);
	 uint16_t checksum_result = 0;
	 checksum_result = lms_ots_compute_checksum(hash);
	 ull_to_bytes(hash + 32, checksum_result, 2);
	 printf("V: ");
	 print_hex(hash, 34);

	 sha256_ctx ctx;
	 uint16_t D_public = 0x8080;
	 uint_fast8_t tmp_concat[22] = { 0 };
	 sha256_init(&ctx);
	 //sha2_256_init(&ctx, pk_tc);

	 memcpy(tmp_concat, tmp_S, 20);
	 memcpy(tmp_concat + 20, &D_public, 2);
	 sha256_update(&ctx, tmp_concat, 22);
	 unsigned char concatenated[56] = { 0 };
	 unsigned max_digit = (1 << W);
	 for (int i = 0; i < P; i++) {
	 unsigned char tmp[32] = { 0 };
	 memcpy(tmp, sig->lmots_sig + 36 + (i * 32), 32);
	 //print_hex(tmp, 32);
	 for (uint16_t j = lms_ots_coeff(hash, i, W); j < max_digit; j++) {
	 concat_hash_value(tmp_S, tmp, i, j, concatenated);
	 sha256(concatenated, 55, tmp);
	 }
	 sha256_update(&ctx, tmp, 32);
	 }
	 sha256_final(&ctx, pk_tc);*/
	//sha3_256_inc_finalize(pk_tc, &ctx);
}

void recover_lmots_public_key_f(unsigned char *pk, unsigned char *sig,
		const unsigned char *message, const size_t input_size,
		unsigned char *pk_tc) {

	uint16_t a = D_MESG;
	unsigned char tmp_S[20] = { 0 };
	memcpy(tmp_S, pk + 8, 16);
	memcpy(tmp_S + 16, sig, 4);
	unsigned char concat_message[54 + input_size];
	memset(concat_message, 0, 54 + input_size);

	memcpy(concat_message, tmp_S, 20);
	memcpy(concat_message + 20, &a, 2);
	memcpy(concat_message + 22, sig + 8, 32);
	memcpy(concat_message + 54, message, input_size);

	unsigned char hash[34] = { 0 };
	sha256(concat_message, 54 + input_size, hash);
	//hash(concat_message, 54 + input_size, hash);
	uint16_t checksum_result = 0;
	checksum_result = lms_ots_compute_checksum(hash);
	ull_to_bytes(hash + 32, checksum_result, 2);

	sha256_ctx ctx;
	uint16_t D_public = 0x8080;
	uint8_t tmp_concat[22] = { 0 };
	sha256_init(&ctx);
	//sha2_256_init(&ctx, pk_tc);

	memcpy(tmp_concat, tmp_S, 20);
	memcpy(tmp_concat + 20, &D_public, 2);
	sha256_update(&ctx, tmp_concat, 22);
	//hash_update(tmp_concat, 22, &ctx);
	unsigned char concatenated[56] = { 0 };
	unsigned max_digit = (1 << W) - 1;
	for (int i = 0; i < P; i++) {
		unsigned char tmp[32] = { 0 };
		memcpy(tmp, sig + 40 + (i * 32), 32);
		for (uint16_t j = lms_ots_coeff(hash, i, W); j < max_digit; j++) {
			concat_hash_value(tmp_S, tmp, i, j, concatenated);
			sha256(concatenated, 55, tmp);
			//sha3_256(tmp, concatenated, 55);
		}
		sha256_update(&ctx, tmp, 32);
	}
	sha256_final(&ctx, pk_tc);

}
int lms_verify_internal_f(const unsigned char *message, const size_t input_size,
		unsigned char *public_key, unsigned char *sig) {

	unsigned char lmots_pk[32] = { 0 };
	int max_digit = 1 << H;
	unsigned long long type_sig = bytes_to_ull(sig + (40 + (32 * P)), 4);
	unsigned long long lms_type = bytes_to_ull(public_key + 4, 4);
	if (lms_type != type_sig)
		return err_algorithm_mismatch;

	unsigned long long q = bytes_to_ull(sig, 4);
	if (q > max_digit)
		return err_invalid_signature;

	recover_lmots_public_key_f(public_key, sig, message, input_size, lmots_pk);
	unsigned int node_pos = q + (1 << H);
	unsigned char tmp[87] = { 0 };
	memcpy(tmp, public_key + 8, 16);
	ull_to_bytes(tmp + 16, node_pos, 4);
	ull_to_bytes(tmp + 20, D_LEAF, 2);
	memcpy(tmp + 22, lmots_pk, 32);
	unsigned char res[32] = { 0 };
	sha256(tmp, 54, res);
	for (int i = 0; i < H; i++) {
		if ((node_pos % 2) == 0) {
			memcpy(tmp, public_key + 8, 16);
			ull_to_bytes(tmp + 16, (node_pos / 2), 4);
			ull_to_bytes(tmp + 20, D_INTR, 2);
			memcpy(tmp + 22, res, 32);
			memcpy(tmp + 54, sig + (44 + (32 * P) + (i * 32)), 32);

		} else {
			memcpy(tmp, public_key + 8, 16);
			ull_to_bytes(tmp + 16, (node_pos / 2), 4);
			ull_to_bytes(tmp + 20, D_INTR, 2);
			memcpy(tmp + 22, sig + (44 + (32 * P) + (i * 32)), 32);
			memcpy(tmp + 54, res, 32);

		}
		sha256(tmp, 86, res);
		//sha3_256(res, tmp, 86);
		node_pos = node_pos / 2;
	}

	return memcmp(public_key + 24, res, 32) == 0;

}

int lms_verify(const unsigned char *message, const size_t input_size,
		unsigned char *pk, unsigned char *signature) {
	/*lms_signature sig;
	 lms_public_key public_key;
	 //unsigned char lmots_pk[32] = { 0 };
	 deserialize_lms_signature(signature, &sig);
	 deserialize_lms_public_key(pk, &public_key);
	 print_lms_signature(&sig);*/

	return lms_verify_internal_f(message, input_size, pk, signature);
}

int lms_verify_internal(const unsigned char *message, const size_t input_size,
		lms_public_key *public_key, lms_signature *sig) {

	unsigned char lmots_pk[32] = { 0 };
	int max_digit = 1 << H;
	if (public_key->lms_type != sig->lms_type)
		return err_algorithm_mismatch;

	if (sig->q > max_digit)
		return err_invalid_signature;

	recover_lmots_public_key(public_key, sig, message, input_size, lmots_pk);
	unsigned int node_pos = sig->q + (1 << H);
	unsigned char tmp[87] = { 0 };
	memcpy(tmp, public_key->param_I, 16);
	ull_to_bytes(tmp + 16, node_pos, 4);
	ull_to_bytes(tmp + 20, D_LEAF, 2);
	memcpy(tmp + 22, lmots_pk, 32);
	unsigned char res[32] = { 0 };
	sha256(tmp, 54, res);
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
		sha256(tmp, 86, res);
		//sha3_256(res, tmp, 86);
		node_pos = node_pos / 2;
	}

	return memcmp(public_key->K, res, 32) == 0;

}

