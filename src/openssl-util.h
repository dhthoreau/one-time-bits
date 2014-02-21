/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_OPENSSL_H
#define OTB_OPENSSL_H

char *otb_openssl_errors_as_string();
GBytes *otb_openssl_generate_random_iv(const EVP_CIPHER *cipher_impl);
unsigned char *otb_openssl_create_encryption_buffer(const EVP_CIPHER *cipher_impl, size_t plain_bytes_buffer_size, size_t *encryption_buffer_size_out);
unsigned char *otb_openssl_create_decryption_buffer(const EVP_CIPHER *cipher_impl, size_t encrypted_bytes_buffer_size, size_t *decryption_buffer_size_out);

#endif
