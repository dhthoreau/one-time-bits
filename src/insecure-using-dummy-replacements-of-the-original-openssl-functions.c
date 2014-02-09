/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

static void _replace_buf_with_predictable_non_random(unsigned char *buf, int num)
{
	static unsigned char non_random=0;
	for(size_t iter=0; iter<num; iter++, non_random=(non_random?0:0xff))
		buf[iter]=non_random;
}

int _RAND_bytes(unsigned char *buf, int num)
{
	_replace_buf_with_predictable_non_random(buf, num);
	return 1;
}

const EVP_CIPHER *_EVP_get_cipherbyname(const char *name)
{
	return EVP_get_cipherbyname("RC2-40-CBC");
}
