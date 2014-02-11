/**
 * Copyright © 2014 the OTB team
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
int _RSA_generate_key_ex(RSA *rsa_impl, int bits, BIGNUM *e, BN_GENCB *cb);

#endif
