/*
 * lms_ots.c
 *
 *  Created on: Mar 2, 2022
 *      Author: Gustavo Banegas
 */

#include "lms_ots.h"

void gen_lmots_private_key(lmots_private_key *private_key) {

	randombytes(private_key->S, 20);
	randombytes(private_key->SEED, 32);
	private_key->remain_sign = 1;

}

void gen_lmots_public_key(lmots_private_key *sk, lmots_public_key *pk) {
//TODO: remove dependency from SHA3
	sk->alg_type = LMOTS_ALG_TYPE;
	pk->alg_type = sk->alg_type;
	uint16_t D_public = 0x8080;
	uint_fast8_t tmp[32] = { 0 };
	sha3_256incctx ctx;
	sha3_256_inc_init(&ctx);
	memcpy(tmp, sk->S, 20);
	memcpy(tmp + 20, &D_public, 2);
	sha3_256_inc_absorb(&ctx, tmp, 22);

	uint_fast8_t tmp_concatenated[55] = { 0 };
	memset(tmp, 0, 32);

	for (int i = 0; i < P; i++) {
		concat_hash_value(sk->S, sk->SEED, i + 1, D_PRG, tmp_concatenated);
		//print_hex(tmp_concatenated, 55);
		sha3_256(tmp, tmp_concatenated, 55);
		for (int j = 0; j < (1 << W) - 1; j++) {
			concat_hash_value(sk->S, tmp, i, j, tmp_concatenated);
			sha3_256(tmp, tmp_concatenated, 55);
		}
		sha3_256_inc_absorb(&ctx, tmp, 32);
	}
	memcpy(pk->S, sk->S, 20);
	sha3_256_inc_finalize(pk->K, &ctx);
	//sha3_256_inc_ctx_release(&ctx);

}

void serialize_lmsots_private_key(lmots_private_key *from, unsigned char *to) {
	ull_to_bytes(to, from->alg_type, 4);
	memcpy(to + 4, from->S, 20);
	memcpy(to + 24, from->SEED, 32);
	ull_to_bytes(to + 56, from->remain_sign, 4);
}

void deserialize_lmsots_private_key(unsigned char *from, lmots_private_key *to) {
	to->alg_type = bytes_to_ull(from, 4);
	memcpy(to->S, from + 4, 20);
	memcpy(to->SEED, from + 24, 32);
	to->remain_sign = bytes_to_ull(from + 56, 4);
}

void serialize_lmsots_public_key(lmots_public_key *from, unsigned char *to) {
	ull_to_bytes(to, from->alg_type, 4);
	memcpy(to + 4, from->K, 32);
	memcpy(to + 36, from->S, 20);
}

void deserialize_lmsots_public_key(unsigned char *from, lmots_public_key *to) {
	to->alg_type = bytes_to_ull(from, 4);
	memcpy(to->K, from + 4, 32);
	memcpy(to->S, from + 36, 20);
}

int lms_ots_keygen(unsigned char *sk, unsigned char *pk) {
	lmots_private_key private_key;
	lmots_public_key publick_key;
	private_key.remain_sign = 1;
	gen_lmots_private_key(&private_key);
	gen_lmots_public_key(&private_key, &publick_key);

	serialize_lmsots_private_key(&private_key, sk);
	serialize_lmsots_public_key(&publick_key, pk);

	return 0;
}

void serialize_lmsots_signature(lmots_signature *from, unsigned char *to) {
	ull_to_bytes(to, from->alg_type, 4);
	memcpy(to + 4, from->C, 32);
	memcpy(to + 36, from->y, P * 32);
}

void deserialize_lmsots_signature(unsigned char *from, lmots_signature *to) {
	to->alg_type = bytes_to_ull(from, 4);
	memcpy(to->C, from + 4, 32);
	memcpy(to->y, from + 36, P * 32);
}

int lms_ots_sign(unsigned char *message, size_t input_size, unsigned char *sk,
		unsigned char *signature) {
	lmots_private_key private_key;
	lmots_signature sig;
	deserialize_lmsots_private_key(sk, &private_key);
	int ret = lms_ots_sign_internal(message, input_size, &private_key, &sig);
	if (ret == 1)
		serialize_lmsots_signature(&sig, signature);
	return ret;
}

int lms_ots_sign_internal(const unsigned char *message, const size_t input_size,
		lmots_private_key *private_key, lmots_signature *sig) {
	if (private_key->remain_sign != 1)
		return err_private_key_exhausted;
	uint16_t a = D_MESG;
	unsigned char concat_message[54 + input_size];
	memset(concat_message, 0, 54 + input_size);

	unsigned char C[32] = { 0 };
	randombytes(C, 32);

	memcpy(sig->C, C, 32);
	sig->alg_type = private_key->alg_type;
	memcpy(concat_message, private_key->S, 20);
	memcpy(concat_message + 20, &a, 2);
	memcpy(concat_message + 22, C, 32);
	memcpy(concat_message + 54, message, input_size);
	unsigned char hash[34] = { 0 };
	sha3_256(hash, concat_message, 54 + input_size);
	uint16_t checksum_result = 0;
	checksum_result = lms_ots_compute_checksum(hash);
	uint8_t buff_check[2] = { 0 };
	ull_to_bytes(buff_check, checksum_result, 2);
	memcpy(hash + 32, buff_check, 2);
	memset(sig->y, 0, P * 32);
	unsigned char concatenated[55] = { 0 };
	for (int i = 0; i < P; i++) {
		unsigned char tmp[32] = { 0 };
		concat_hash_value(private_key->S, private_key->SEED, i + 1, D_PRG,
				concatenated);
		sha3_256(tmp, concatenated, 55);
		for (uint16_t j = 0; j < lms_ots_coeff(hash, i, W); j++) {
			concat_hash_value(private_key->S, tmp, i, j, concatenated);
			sha3_256(tmp, concatenated, 55);
		}
		memcpy(sig->y + (32 * i), tmp, 32);
	}

//TODO: update key
	private_key->remain_sign -= 1;
	return 1;
}

int lms_ots_verify(unsigned char *message, size_t input_size, unsigned char *pk,
		unsigned char *signature) {

	uint16_t a = D_MESG;
	lmots_public_key publick_key;
	lmots_signature sig;
	deserialize_lmsots_public_key(pk, &publick_key);

	unsigned char concat_message[54 + input_size];
	memset(concat_message, 0, 54 + input_size);

	deserialize_lmsots_signature(signature, &sig);

	if (sig.alg_type != publick_key.alg_type)
		return err_algorithm_mismatch;
	/*printf("y: ");
	 print_hex(sig.y, P * 32);*/

	memcpy(concat_message, publick_key.S, 20);
	memcpy(concat_message + 20, &a, 2);
	memcpy(concat_message + 22, sig.C, 32);
	memcpy(concat_message + 54, message, input_size);

	unsigned char hash[34] = { 0 };
	sha3_256(hash, concat_message, 54 + input_size);
	uint16_t checksum_result = 0;
	checksum_result = lms_ots_compute_checksum(hash);
	uint8_t buff_check[2] = { 0 };
	ull_to_bytes(buff_check, checksum_result, 2);
	memcpy(hash + 32, buff_check, 2);

	sha3_256incctx ctx;
	uint16_t D_public = 0x8080;
	uint_fast8_t tmp_concat[22] = { 0 };
	sha3_256_inc_init(&ctx);

	memcpy(tmp_concat, publick_key.S, 20);
	memcpy(tmp_concat + 20, &D_public, 2);
	hash_update(tmp_concat, 22, &ctx);
	unsigned char concatenated[55] = { 0 };
	unsigned max_digit = (1 << W) - 1;
	for (int i = 0; i < P; i++) {
		unsigned char tmp[32] = { 0 };
		memcpy(tmp, sig.y + (i * 32), 32);
		for (uint16_t j = lms_ots_coeff(hash, i, W); j < max_digit; j++) {
			concat_hash_value(publick_key.S, tmp, i, j, concatenated);
			sha3_256(tmp, concatenated, 55);
		}
		hash_update(tmp, 32, &ctx);
	}
	unsigned char res[32] = { 0 };
	sha3_256_inc_finalize(res, &ctx);
	return memcmp(publick_key.K, res, 32) == 0;
}

