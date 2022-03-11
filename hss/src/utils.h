#ifndef XMSS_UTILS_H
#define XMSS_UTILS_H

#include <stdio.h>

#include "params.h"

/**
 * Converts the value of 'in' to 'outlen' bytes in big-endian byte order.
 */
void ull_to_bytes(void *target, unsigned long long value, size_t bytes);

/**
 * Converts the inlen bytes in 'in' from big-endian byte order to an integer.
 */
unsigned long long bytes_to_ull(const void *target, size_t bytes);

/**
 * Print the inlen bytes in hex.
 */

void print_hex(unsigned char *array, unsigned int inlen);

/**
 * Print the lmots_signature in hex.
 */

void print_lmots_signature(lmots_signature *sig);

/**
 * Print the lms_signature in hex.
 */

void print_lms_signature(lms_signature *sig);

/**
 * Print the lms_public_key in hex.
 */
void print_lms_pub_key(lms_public_key *sk);

/**
 * Print the lms_private_key in hex.
 */
void print_lms_priv_key(lms_private_key *sk);

/**
 * Print the hss_signature in hex.
 */
void print_hss_signature(hss_signature *sig);
/**
 * Print the hss_private_key in hex.
 */

void print_hss_private_key(hss_private_key *sk);

/**
 * Print the hss_public_key in hex.
 */

void print_hss_public_key(hss_public_key *pk);

#endif
