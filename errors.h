/*
 * errors.h
 *
 *  Created on: Mar 11, 2022
 *      Author: Gustavo Banegas
 */

#ifndef ERRORS_H_
#define ERRORS_H_

typedef enum lms_hss_errors_type {
	err_private_key_exhausted = -1,
	err_wrong_levels = -2,
	err_algorithm_mismatch = -3,
	err_wrong_length = -4,
	err_invalid_signature = -5
} lms_hss_errors_type;

#endif /* ERRORS_H_ */
