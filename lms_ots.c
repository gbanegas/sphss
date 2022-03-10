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

int lms_ots_keygen(unsigned char *sk, unsigned char *pk) {
	lmots_private_key private_key;
	lmots_public_key publick_key;
	private_key.remain_sign = 1;
	gen_lmots_private_key(&private_key);
	gen_lmots_public_key(&private_key, &publick_key);

	memcpy(sk, &private_key.alg_type, 1);
	memcpy(sk + 1, private_key.S, 20);
	memcpy(sk + 21, private_key.SEED, 32);
	memcpy(sk + 53, &private_key.remain_sign, 1);

	memcpy(pk, &publick_key.alg_type, 1);
	memcpy(pk + 1, publick_key.K, 32);
	memcpy(pk + 33, publick_key.S, 20);

	return 0;
}

int lms_ots_sign(unsigned char *message, size_t input_size, unsigned char *sk,
		unsigned char *signature) {
	//TODO: add protection against more than one sig
	uint16_t a = D_MESG;
	lmots_private_key private_key;
	lmots_signature sig;
	unsigned char concat_message[54 + input_size];
	memset(concat_message, 0, 54 + input_size);

	memcpy(&private_key.alg_type, sk, 1);
	memcpy(private_key.S, sk + 1, 20);
	memcpy(private_key.SEED, sk + 21, 32);
	memcpy(&private_key.remain_sign, sk + 53, sizeof(size_t));

	unsigned char C[32] = { 0 };/*{ 0x31, 0xe2, 0x99, 0x69, 0x84, 0x91, 0x4c, 0xa2,
	 0xe0, 0xa8, 0xc8, 0x34, 0x9d, 0x88, 0xbd, 0xbe, 0x09, 0x70, 0xb5,
	 0x89, 0x04, 0x4f, 0x20, 0xbf, 0x89, 0xcb, 0x8f, 0xe9, 0xd6, 0x4d,
	 0x3d, 0x90 };*/
	randombytes(C, 32);

	memcpy(sig.C, C, 32);
	sig.alg_type = private_key.alg_type;
	memcpy(concat_message, private_key.S, 20);
	memcpy(concat_message + 20, &a, 2);
	memcpy(concat_message + 22, C, 32);
	memcpy(concat_message + 54, message, input_size);
	unsigned char hash[34] = { 0 };
	sha3_256(hash, concat_message, 54 + input_size);
	uint16_t checksum_result = 0;
	checksum_result = lms_ots_compute_checksum(hash);
	uint8_t buff_check[2] = { 0 };
	put_bigendian(buff_check, checksum_result, 2);
	memcpy(hash + 32, buff_check, 2);
	memset(sig.y, 0, P * 32);
	unsigned char concatenated[55] = { 0 };
	for (int i = 0; i < P; i++) {
		unsigned char tmp[32] = { 0 };
		concat_hash_value(private_key.S, private_key.SEED, i + 1, D_PRG,
				concatenated);
		sha3_256(tmp, concatenated, 55);
		for (uint16_t j = 0; j < lms_ots_coeff(hash, i, W); j++) {
			concat_hash_value(private_key.S, tmp, i, j, concatenated);
			sha3_256(tmp, concatenated, 55);
		}
		memcpy(sig.y + (32 * i), tmp, 32);
	}

//TODO: update key
	memcpy(signature, &sig.alg_type, 2);
	memcpy(signature + 2, sig.C, 32);
	memcpy(signature + 34, sig.y, P * 32);
	return 1;
}

int lms_ots_sign_internal(const unsigned char *message, const size_t input_size,
		lmots_private_key *private_key, lmots_signature *sig) {
	//TODO: add protection against more than one sig
	uint16_t a = D_MESG;
	unsigned char concat_message[54 + input_size];
	memset(concat_message, 0, 54 + input_size);

	unsigned char C[32] = { 0 };/*{ 0x5e, 0xff, 0x69, 0x57, 0x59, 0x82, 0xc6, 0x41, 0x75, 0xe7, 0xaf, 0x4e, 0xcd,
	 0x80, 0xd8, 0x23, 0xa4, 0x2f, 0xdf, 0x36, 0x9a, 0xd4, 0x80, 0x0d, 0x0c, 0x11, 0x71, 0xca, 0x67, 0xec,
	 0x91, 0x64 };*/
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
	put_bigendian(buff_check, checksum_result, 2);
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

	return 1;
}

int lms_ots_verify(unsigned char *message, size_t input_size, unsigned char *pk,
		unsigned char *signature) {

	uint16_t a = D_MESG;
	lmots_public_key publick_key;
	lmots_signature sig;
	memcpy(&publick_key.alg_type, pk, 1);
	memcpy(publick_key.K, pk + 1, 32);
	memcpy(publick_key.S, pk + 33, 20);
	unsigned char concat_message[54 + input_size];
	memset(concat_message, 0, 54 + input_size);

	memcpy(&sig.alg_type, signature, 2);
	memcpy(sig.C, signature + 2, 32);
	memcpy(sig.y, signature + 34, P * 32);
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
	put_bigendian(buff_check, checksum_result, 2);
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

