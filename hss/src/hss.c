/*
 * hss.c
 *
 *  Created on: Mar 2, 2022
 *      Author: Gustavo Banegas
 */

#include "hss.h"

void gen_hss_private_key(hss_private_key *sk) {
	sk->remain = (1 << (LEVELS * H));
	sk->L = LEVELS;
	gen_lms_private_key(&sk->priv[0]);
	gen_lms_public_key(&sk->priv[0], &sk->pubs[0]);
	for (int i = 1; i < LEVELS; i++) {
		gen_lms_private_key(&sk->priv[i]);
		memcpy(sk->priv[i].SEED, sk->priv[0].SEED, 32);
		gen_lms_public_key(&sk->priv[i], &sk->pubs[i]);
		unsigned char pub_serial[LMS_PRIV_KEY_SIZE] = { 0 };
		serialize_lms_public_key(&sk->pubs[i], pub_serial);
		lms_sign_internal(pub_serial, LMS_PRIV_KEY_SIZE, &sk->priv[i - 1],
				&sk->sigs[i]);
	}

}

void gen_hss_public_key(hss_private_key *sk, hss_public_key *pk) {
	pk->L = LEVELS;
	memcpy(&pk->pub, &sk->pubs[0], sizeof(lms_public_key));

}

int hss_keygen(unsigned char *sk, unsigned char *pk) {

	hss_private_key private_key;
	hss_public_key public_key;

	gen_hss_private_key(&private_key);
	gen_hss_public_key(&private_key, &public_key);
	print_hss_private_key(&private_key);
	print_hss_public_key(&public_key);

	return 1;
}
