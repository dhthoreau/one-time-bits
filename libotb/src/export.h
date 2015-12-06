/**
 * Copyright © 2015 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_EXPORT_H
#define OTB_EXPORT_H

#include <openssl/evp.h>

const EVP_CIPHER *_EVP_get_cipherbyname(const char *name);
int _RAND_bytes(unsigned char *buf, int num);
int _EVP_PKEY_CTX_set_rsa_keygen_bits(EVP_PKEY_CTX *context, int key_bits);
void _otb_set_EVP_PKEY(EVP_PKEY **target_key, EVP_PKEY *source_key);

#endif
