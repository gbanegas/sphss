/*
 * lms_ots.c
 *
 *  Created on: Mar 2, 2022
 *      Author: Gustavo Banegas
 */

#include "lms_ots.h"

void gen_lmots_private_key(unsigned char *private_key) {

	randombytes(private_key + 4, 20);
	randombytes(private_key + 24, 32);
	ull_to_bytes(private_key + 56, 1, 4);

}

void gen_lmots_public_key(unsigned char *sk, unsigned char *pk) {
	ull_to_bytes(sk, LMOTS_ALG_TYPE, 4);
	ull_to_bytes(pk, LMOTS_ALG_TYPE, 4);
	uint16_t D_public = 0x8080;
	uint8_t tmp[32] = { 0 };
	sha256_ctx ctx;
	sha256_init(&ctx);
	memcpy(tmp, sk + 4, 20);
	memcpy(tmp + 20, &D_public, 2);
	sha256_update(&ctx, tmp, 22);

	uint8_t tmp_concatenated[55] = { 0 };
	memset(tmp, 0, 32);

	for (int i = 0; i < P; i++) {
		concat_hash_value(sk + 4, sk + 24, i + 1, D_PRG, tmp_concatenated);
		sha256(tmp_concatenated, 55, tmp);
		for (int j = 0; j < (1 << W) - 1; j++) {
			concat_hash_value(sk + 4, tmp, i, j, tmp_concatenated);
			sha256(tmp_concatenated, 55, tmp);
		}
		sha256_update(&ctx, tmp, 32);
	}
	memcpy(pk + 36, sk + 4, 20);
	sha256_final(&ctx, pk + 4);
	//sha3_256_inc_ctx_release(&ctx);

}

int lms_ots_keygen(unsigned char *sk, unsigned char *pk) {
	gen_lmots_private_key(sk);
	gen_lmots_public_key(sk, pk);

	//serialize_lmsots_private_key(&private_key, sk);
	//serialize_lmsots_public_key(&publick_key, pk);

	return 1;
}

int lms_ots_sign_f(const unsigned char *message, const size_t input_size,
		unsigned char *sk, unsigned char *sig) {
	unsigned long long remain_sign = bytes_to_ull(sk + 56, 4);
	if (remain_sign != 1)
		return err_private_key_exhausted;
	uint16_t a = D_MESG;
	unsigned char concat_message[54 + input_size];
	memset(concat_message, 0, 54 + input_size);

	unsigned char C[32] = { 0 };
	randombytes(C, 32);

	memcpy(sig + 4, C, 32);
	unsigned long long alg_type = bytes_to_ull(sk, 4);
	ull_to_bytes(sig, alg_type, 4);
	memcpy(concat_message, sk + 4, 20);
	memcpy(concat_message + 20, &a, 2);
	memcpy(concat_message + 22, C, 32);
	memcpy(concat_message + 54, message, input_size);
	unsigned char hash[34] = { 0 };
	sha256(concat_message, 54 + input_size, hash);
	//sha3_256(hash, concat_message, 54 + input_size);
	uint16_t checksum_result = 0;
	checksum_result = lms_ots_compute_checksum(hash);
	uint8_t buff_check[2] = { 0 };
	ull_to_bytes(buff_check, checksum_result, 2);
	memcpy(hash + 32, buff_check, 2);
	memset(sig + 36, 0, P * 32);
	unsigned char concatenated[55] = { 0 };
	for (int i = 0; i < P; i++) {
		unsigned char tmp[32] = { 0 };
		concat_hash_value(sk + 4, sk + 24, i + 1, D_PRG, concatenated);
		sha256(concatenated, 55, tmp);
		//sha3_256(tmp, concatenated, 55);
		for (uint16_t j = 0; j < lms_ots_coeff(hash, i, W); j++) {
			concat_hash_value(sk + 4, tmp, i, j, concatenated);
			sha256(concatenated, 55, tmp);
			//sha3_256(tmp, concatenated, 55);
		}
		memcpy(sig + 36 + (32 * i), tmp, 32);
	}

	remain_sign -= 1;
	ull_to_bytes(sk + 56, remain_sign, 4);
	//print_lmots_signature_pure(sig);
	return 1;
}

int lms_ots_sign(const unsigned char *message, const size_t input_size,
		unsigned char *sk, unsigned char *signature) {
	int ret = lms_ots_sign_f(message, input_size, sk, signature);
	//if (ret == 1)
	//serialize_lmsots_signature(&sig, signature);
	return ret;
}

int lms_ots_verify(unsigned char *message, size_t input_size, unsigned char *pk,
		unsigned char *signature) {

	uint16_t a = D_MESG;
	//deserialize_lmsots_public_key(pk, &publick_key);

	unsigned char concat_message[54 + input_size];
	memset(concat_message, 0, 54 + input_size);

	//deserialize_lmsots_signature(signature, &sig);
	unsigned long long alg_type_sig = bytes_to_ull(signature, 4);
	unsigned long long alg_type_pk = bytes_to_ull(pk, 4);
	if (alg_type_sig != alg_type_pk)
		return err_algorithm_mismatch;
	/*printf("y: ");
	 print_hex(sig.y, P * 32);*/

	memcpy(concat_message, pk + 36, 20);
	memcpy(concat_message + 20, &a, 2);
	memcpy(concat_message + 22, signature + 4, 32);
	memcpy(concat_message + 54, message, input_size);

	unsigned char hash[34] = { 0 };
	unsigned char res[32] = { 0 };
	sha256(concat_message, 54 + input_size, hash);
	//sha3_256(hash, concat_message, 54 + input_size);
	uint16_t checksum_result = 0;
	checksum_result = lms_ots_compute_checksum(hash);
	uint8_t buff_check[2] = { 0 };
	ull_to_bytes(buff_check, checksum_result, 2);
	memcpy(hash + 32, buff_check, 2);

	sha256_ctx ctx;
	uint16_t D_public = 0x8080;
	uint8_t tmp_concat[22] = { 0 };
	sha256_init(&ctx);

	memcpy(tmp_concat, pk + 36, 20);
	memcpy(tmp_concat + 20, &D_public, 2);
	hash_update(tmp_concat, 22, &ctx);
	unsigned char concatenated[55] = { 0 };
	unsigned max_digit = (1 << W) - 1;
	for (int i = 0; i < P; i++) {
		unsigned char tmp[32] = { 0 };
		memcpy(tmp, signature + 36 + (i * 32), 32);
		for (uint16_t j = lms_ots_coeff(hash, i, W); j < max_digit; j++) {
			concat_hash_value(pk + 36, tmp, i, j, concatenated);
			sha256(concatenated, 55, tmp);
		}
		hash_update(tmp, 32, &ctx);
	}
	sha256_final(&ctx, res);
	//sha3_256_inc_finalize(res, &ctx);
	return memcmp(pk + 4, res, 32) == 0;
}

