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
#include "../src/asym-cipher.h"

static void test_asym_cipher_properties()
{
	const char *EXPECTED_CIPHER="RC2-64-CBC";
	
	OtbAsymCipher *asym_cipher=g_object_new(OTB_TYPE_ASYM_CIPHER, OTB_ASYM_CIPHER_PROP_SYM_CIPHER, EXPECTED_CIPHER, NULL);
	size_t actual_new_key_length=NULL;
	char *actual_cipher=NULL;
	g_object_get(asym_cipher, OTB_ASYM_CIPHER_PROP_SYM_CIPHER, &actual_cipher, NULL);
	g_assert_cmpstr(EXPECTED_CIPHER, ==, actual_cipher);
	g_free(actual_cipher);
	g_object_unref(asym_cipher);
}

static void otb_copy_public_key(OtbAsymCipher *asym_cipher_original, OtbAsymCipher *asym_cipher_public)
{
	const char *public_key=otb_asym_cipher_get_public_key(asym_cipher_original);
	g_assert(public_key!=NULL);
	otb_asym_cipher_set_public_key(asym_cipher_public, public_key);
}

static void otb_copy_private_key(OtbAsymCipher *asym_cipher_original, OtbAsymCipher *asym_cipher_private, OtbSymCipher *private_key_sym_cipher)
{
	GBytes *private_key_iv=NULL;
	GBytes *encrypted_private_key=otb_asym_cipher_get_encrypted_private_key(asym_cipher_original, &private_key_iv);
	g_assert(private_key_iv!=NULL);
	g_assert(encrypted_private_key!=NULL);
	otb_asym_cipher_set_encrypted_private_key(asym_cipher_private, encrypted_private_key, private_key_sym_cipher, private_key_iv);
}

static void test_asym_cipher_encryption()
{
	const size_t NEW_KEY_LENGTH=512;
	const char EXPECTED_MESSAGE_SIZE=74;
	const char *EXPECTED_MESSAGE="Timid men prefer the calm of despotism to the tempestuous sea of liberty.";
	
	OtbAsymCipher *asym_cipher_original=g_object_new(OTB_TYPE_ASYM_CIPHER, NULL);
	OtbSymCipher *private_key_sym_cipher=g_object_new(OTB_TYPE_SYM_CIPHER, OTB_SYM_CIPHER_PROP_CIPHER, "AES-256-CBC", NULL);
	g_assert(otb_sym_cipher_generate_random_key(private_key_sym_cipher));
	g_assert(otb_asym_cipher_generate_random_keys(asym_cipher_original, NEW_KEY_LENGTH, private_key_sym_cipher));
	OtbAsymCipher *asym_cipher_public=g_object_new(OTB_TYPE_ASYM_CIPHER, NULL);
	OtbAsymCipher *asym_cipher_private=g_object_new(OTB_TYPE_ASYM_CIPHER, NULL);
	otb_copy_public_key(asym_cipher_original, asym_cipher_public);
	otb_copy_private_key(asym_cipher_original, asym_cipher_private, private_key_sym_cipher);
	g_object_unref(private_key_sym_cipher);
	g_object_unref(asym_cipher_original);
	unsigned char *encrypted_message=otb_asym_cipher_create_encryption_buffer(asym_cipher_public, EXPECTED_MESSAGE_SIZE, NULL);
	GBytes *iv=NULL;
	GBytes *encrypted_key=NULL;
	OtbAsymCipherContext *encryption_context=otb_asym_cipher_init_encryption(asym_cipher_public, &encrypted_key, &iv);
	g_assert(encryption_context!=NULL);
	g_assert(iv!=NULL);
	g_assert(encrypted_key!=NULL);
	size_t encrypted_message_size=otb_asym_cipher_encrypt(encryption_context, EXPECTED_MESSAGE, EXPECTED_MESSAGE_SIZE, encrypted_message);
	encrypted_message_size+=otb_asym_cipher_finish_encrypt(encryption_context, encrypted_message+encrypted_message_size);
	g_assert_cmpint(0, !=, encrypted_message_size);
	g_assert(EXPECTED_MESSAGE_SIZE!=encrypted_message_size || memcmp(EXPECTED_MESSAGE, encrypted_message, encrypted_message_size)!=0);
	char *decrypted_message=otb_asym_cipher_create_encryption_buffer(asym_cipher_private, encrypted_message_size, NULL);
	OtbAsymCipherContext *decryption_context=otb_asym_cipher_init_decryption(asym_cipher_private, encrypted_key, iv);
	g_assert(decryption_context!=NULL);
	size_t actual_message_size=otb_asym_cipher_decrypt(decryption_context, encrypted_message, encrypted_message_size, decrypted_message);
	actual_message_size+=otb_asym_cipher_finish_decrypt(decryption_context, decrypted_message+actual_message_size);
	g_assert_cmpint(0, !=, actual_message_size);
	g_assert_cmpint(EXPECTED_MESSAGE_SIZE, ==, actual_message_size);
	g_assert_cmpstr(EXPECTED_MESSAGE, ==, decrypted_message);
	g_free(decrypted_message);
	g_free(encrypted_message);
	g_bytes_unref(encrypted_key);
	g_bytes_unref(iv);
	g_object_unref(asym_cipher_private);
	g_object_unref(asym_cipher_public);
}

void otb_add_asym_cipher_tests()
{
	otb_add_test_func("/asym_cipher/test_asym_cipher_properties", test_asym_cipher_properties);
	otb_add_test_func("/asym_cipher/test_asym_cipher_encryption", test_asym_cipher_encryption);
}
