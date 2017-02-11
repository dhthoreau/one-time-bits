/**
 * Copyright © 2015 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_OPENSSL_H
#define OTB_OPENSSL_H

#include "memory.h"

#define otb_openssl_dispose_decryption_buffer(decryption_buffer)						otb_free_locked((decryption_buffer))
#define otb_openssl_create_encryption_buffer(cipher_impl, plain_bytes_buffer_size)		g_new(unsigned char, (plain_bytes_buffer_size)+EVP_CIPHER_block_size(cipher_impl))
#define otb_openssl_create_decryption_buffer(cipher_impl, encrypted_bytes_buffer_size)	otb_malloc_locked((encrypted_bytes_buffer_size)+EVP_CIPHER_block_size(cipher_impl))

char *otb_openssl_errors_as_string(void);
GBytes *otb_openssl_generate_random_iv(const EVP_CIPHER *cipher_impl);

#endif
