#include "utils.h"

/**
 * Converts the value of 'in' to 'outlen' bytes in big-endian byte order.
 */
void ull_to_bytes(unsigned char *out, unsigned int outlen,
		unsigned long long in) {
	int i;

	/* Iterate over out in decreasing order, for big-endianness. */
	for (i = outlen - 1; i >= 0; i--) {
		out[i] = in & 0xff;
		in = in >> 8;
	}
}

/**
 * Converts the inlen bytes in 'in' from big-endian byte order to an integer.
 */
unsigned long long bytes_to_ull(const unsigned char *in, unsigned int inlen) {
	unsigned long long retval = 0;
	unsigned int i;

	for (i = 0; i < inlen; i++) {
		retval |= ((unsigned long long) in[i]) << (8 * (inlen - 1 - i));
	}
	return retval;
}

void put_bigendian(void *target, unsigned long long value, size_t bytes) {
	unsigned char *b = target;
	int i;

	for (i = bytes - 1; i >= 0; i--) {
		b[i] = value & 0xff;
		value >>= 8;
	}
}

unsigned long long get_bigendian(const void *target, size_t bytes) {
	const unsigned char *b = target;
	unsigned long long result = 0;
	int i;

	for (i = 0; i < bytes; i++) {
		result = 256 * result + (b[i] & 0xff);
	}

	return result;
}

void print_hex(unsigned char *array, unsigned int inlen) {
	printf("0x");
	for (unsigned int i = 0; i < inlen; i++) {
		if ((i + 1) % 33 == 0)
			printf("\n");
		printf("%02x,", array[i]);
	}
	printf("\n");
}

void print_lmots_signature(lmots_signature *sig) {
	printf("LMOS Type: %d\n", sig->alg_type);
	printf("C: ");
	print_hex(sig->C, 32);
	printf("y: ");
	print_hex(sig->y, P * 32);

}

void print_lms_signature(lms_signature *sig) {
	for (int i = 0; i < 32; i++) {
		printf("-");
	}
	printf("\n");
	printf("LMS Type: %u\n", sig->lms_type);
	print_lmots_signature(&sig->lmots_sig);
	for (int i = 0; i < H; i++) {
		printf("path[%d]: ", i);
		print_hex(sig->path[i].node, 32);
	}
	for (int i = 0; i < 32; i++) {
		printf("-");
	}
	printf("\n");

}
