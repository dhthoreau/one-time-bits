/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <glib-object.h>
#include <openssl/evp.h>
#include <string.h>

#include "main.h"
#include "test-utils.h"
#include "../src/rsa.h"

static void test_rsa_properties()
{
	size_t EXPECTED_NEW_KEY_LENGTH=512;
	const char *EXPECTED_CIPHER="RC2-64-CBC";
	
	OtbRsa *rsa=g_object_new(OTB_TYPE_RSA, OTB_RSA_PROP_NEW_KEY_LENGTH, EXPECTED_NEW_KEY_LENGTH, OTB_RSA_PROP_CIPHER, EXPECTED_CIPHER, NULL);
	size_t actual_new_key_length=NULL;
	char *actual_cipher=NULL;
	g_object_get(rsa, OTB_RSA_PROP_NEW_KEY_LENGTH, &actual_new_key_length, OTB_CIPHER_PROP_CIPHER, &actual_cipher, NULL);
	g_assert_cmpint(EXPECTED_NEW_KEY_LENGTH, ==, actual_new_key_length);
	g_assert_cmpstr(EXPECTED_CIPHER, ==, actual_cipher);
	g_free(actual_cipher);
	g_object_unref(rsa);
}

static void otb_copy_public_key(OtbRsa *rsa_original, OtbRsa *rsa_public)
{
	GBytes *public_key=otb_rsa_get_public_key(rsa_original);
	g_assert(public_key!=NULL);
	otb_rsa_set_public_key(rsa_public, public_key);
	g_bytes_unref(public_key);
}

static void otb_copy_private_key(OtbRsa *rsa_original, OtbRsa *rsa_private)
{
	OtbCipher *cipher=g_object_new(OTB_TYPE_CIPHER, OTB_CIPHER_PROP_CIPHER, "AES-256-CBC", NULL);
	otb_cipher_generate_random_key(cipher);
	GBytes *iv=NULL;
	GBytes *private_key=otb_rsa_get_private_key(rsa_original, cipher, &iv);
	g_assert(iv!=NULL);
	g_assert(private_key!=NULL);
	otb_rsa_set_private_key(rsa_private, private_key, cipher, iv);
	g_bytes_unref(iv);
	g_bytes_unref(private_key);
	g_object_unref(cipher);
}

static void test_rsa_encryption()
{
	const char EXPECTED_MESSAGE_SIZE=74;
	const char *EXPECTED_MESSAGE="Timid men prefer the calm of despotism to the tempestuous sea of liberty.";
	
	OtbRsa *rsa_original=g_object_new(OTB_TYPE_RSA, OTB_RSA_PROP_NEW_KEY_LENGTH, 512, NULL);
	g_assert(otb_rsa_generate_random_keys(rsa_original));
	OtbRsa *rsa_public=g_object_new(OTB_TYPE_RSA, NULL);
	OtbRsa *rsa_private=g_object_new(OTB_TYPE_RSA, NULL);
	otb_copy_public_key(rsa_original, rsa_public);
	otb_copy_private_key(rsa_original, rsa_private);
	g_object_unref(rsa_original);
	unsigned char *encrypted_message=otb_rsa_create_encryption_buffer(rsa_public, EXPECTED_MESSAGE_SIZE, NULL);
	GBytes *iv=NULL;
	GBytes *encrypted_key=NULL;
	OtbRsaContext *encryption_context=otb_rsa_init_encryption(rsa_public, &iv, &encrypted_key);
	g_assert(encryption_context!=NULL);
	g_assert(iv!=NULL);
	g_assert(encrypted_key!=NULL);
	size_t encrypted_message_size=otb_rsa_encrypt(encryption_context, EXPECTED_MESSAGE, EXPECTED_MESSAGE_SIZE, encrypted_message);
	encrypted_message_size+=otb_rsa_finish_encrypt(encryption_context, encrypted_message+encrypted_message_size);
	g_assert_cmpint(0, !=, encrypted_message_size);
	g_assert(EXPECTED_MESSAGE_SIZE!=encrypted_message_size || memcmp(EXPECTED_MESSAGE, encrypted_message, encrypted_message_size)!=0);
	char *decrypted_message=otb_rsa_create_encryption_buffer(rsa_private, encrypted_message_size, NULL);
	OtbRsaContext *decryption_context=otb_rsa_init_decryption(rsa_private, iv, encrypted_key);
	g_assert(decryption_context!=NULL);
	size_t actual_message_size=otb_rsa_decrypt(decryption_context, encrypted_message, encrypted_message_size, decrypted_message);
	actual_message_size+=otb_rsa_finish_decrypt(decryption_context, decrypted_message+actual_message_size);
	g_assert_cmpint(0, !=, actual_message_size);
	g_assert_cmpint(EXPECTED_MESSAGE_SIZE, ==, actual_message_size);
	g_assert_cmpstr(EXPECTED_MESSAGE, ==, decrypted_message);
	g_free(decrypted_message);
	g_free(encrypted_message);
	g_bytes_unref(iv);
	g_object_unref(rsa_private);
	g_object_unref(rsa_public);
}

void otb_add_rsa_tests()
{
	otb_add_test_func("/rsa/test_rsa_properties", test_rsa_properties);
	otb_add_test_func("/rsa/test_rsa_encryption", test_rsa_encryption);
}
