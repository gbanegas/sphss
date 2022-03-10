#ifndef XMSS_UTILS_H
#define XMSS_UTILS_H


#include <stdio.h>

#include "params.h"
/**
 * Converts the value of 'in' to 'outlen' bytes in big-endian byte order.
 */
void ull_to_bytes(unsigned char *out, unsigned int outlen,
		unsigned long long in);

/**
 * Converts the inlen bytes in 'in' from big-endian byte order to an integer.
 */
unsigned long long bytes_to_ull(const unsigned char *in, unsigned int inlen);

void put_bigendian(void *target, unsigned long long value, size_t bytes);

unsigned long long get_bigendian(const void *target, size_t bytes);

void print_hex(unsigned char *array, unsigned int inlen);

void print_lms_signature(lms_signature *sig);

void print_hss_private_key(hss_private_key *sk);

void print_hss_public_key(hss_public_key *pk);

void print_lms_key(lms_private_key *sk);
#endif
