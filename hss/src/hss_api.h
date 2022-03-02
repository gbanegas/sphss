/*
 * hss_api.h
 *
 *  Created on: Mar 2, 2022
 *      Author: Gustavo Banegas
 */

#ifndef HSS_API_H_
#define HSS_API_H_



int crypto_sign_keypair(unsigned char *sk, unsigned char *pk);

int crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m,
		unsigned long long mlen, unsigned char *private_key);

int crypto_sign_detached(unsigned char *sm, unsigned long long *smlen, const unsigned char *m,
		unsigned long long mlen, unsigned char *private_key);

int crypto_verify(unsigned char *pk, unsigned char *sig, size_t sig_len,
		unsigned char *m, size_t mlen);

int crypto_sign_verify_detached(unsigned char *pk, unsigned char *sig, size_t sig_len,
		unsigned char *m, size_t mlen);



#endif /* HSS_API_H_ */
