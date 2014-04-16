/**
 * Copyright © 2014 the OTB team
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

char *otb_openssl_errors_as_string()
{
	BIO *bio=BIO_new(BIO_s_mem());
	ERR_print_errors(bio);
	char *buffer=NULL;
	size_t size=BIO_get_mem_data(bio, &buffer);
	char *error_string=g_strnfill(size+1, 0);
	if(error_string)
		memcpy(error_string, buffer, size);
	BIO_free(bio);
	return error_string;
}

GBytes *otb_openssl_generate_random_iv(const EVP_CIPHER *cipher_impl)
{
	GBytes *iv=NULL;
	void *iv_bytes=otb_create_random_bytes(EVP_CIPHER_iv_length(cipher_impl));
	if(iv_bytes!=NULL)
		iv=g_bytes_new_take(iv_bytes, EVP_CIPHER_iv_length(cipher_impl));
	return iv;
}

unsigned char *otb_openssl_create_encryption_buffer(const EVP_CIPHER *cipher_impl, size_t plain_bytes_buffer_size, size_t *encryption_buffer_size_out)
{
	size_t size=plain_bytes_buffer_size+EVP_CIPHER_block_size(cipher_impl)-1;
	if(encryption_buffer_size_out!=NULL)
		*encryption_buffer_size_out=size;
	return g_malloc(size);
}

void *otb_openssl_create_decryption_buffer(const EVP_CIPHER *cipher_impl, size_t encrypted_bytes_buffer_size, size_t *decryption_buffer_size_out)
{
	size_t size=encrypted_bytes_buffer_size+EVP_CIPHER_block_size(cipher_impl);
	*decryption_buffer_size_out=size;
	void *decryption_buffer=g_malloc(size);
	otb_mlock(decryption_buffer, *decryption_buffer_size_out);
	return decryption_buffer;
}

void otb_openssl_dispose_decryption_buffer(void *decryption_buffer, size_t decryption_buffer_size)
{
	otb_smemset(decryption_buffer, 0, decryption_buffer_size);
	g_free(decryption_buffer);
	otb_munlock(decryption_buffer, decryption_buffer_size);
}
