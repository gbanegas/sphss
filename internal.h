/*
 * internal.h
 *
 *  Created on: Mar 9, 2022
 *      Author: Gustavo Banegas
 */

#ifndef INTERNAL_H_
#define INTERNAL_H_

#include <stdint.h>
#include <stddef.h>

/**
 * Representation of Node
 */
typedef struct Node {
	unsigned char data[32];
} Node;

#endif /* INTERNAL_H_ */
