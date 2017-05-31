/**
 * Copyright © 2017 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <glib.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string.h>

#include "memory.h"
#include "random.h"

char *otb_openssl_errors_as_string(void)
{
	BIO *bio=BIO_new(BIO_s_mem());
	ERR_print_errors(bio);
	char *buffer;
	size_t size=BIO_get_mem_data(bio, &buffer);
	char *error_string=g_strnfill(size+1, 0);
	if(G_LIKELY(error_string))
		memcpy(error_string, buffer, size);
	BIO_free(bio);
	return error_string;
}

GBytes *otb_openssl_generate_random_iv(const EVP_CIPHER *cipher_impl)
{
	GBytes *iv=NULL;
	void *iv_bytes=otb_create_random_bytes(EVP_CIPHER_iv_length(cipher_impl));
	if(G_LIKELY(iv_bytes!=NULL))
		iv=g_bytes_new_take(iv_bytes, EVP_CIPHER_iv_length(cipher_impl));
	return iv;
}
