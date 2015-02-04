/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <openssl/evp.h>
#include <string.h>

#include "main.h"
#include "test-utils.h"
#include "../src/asym-cipher.h"

static void test_asym_cipher_properties()
{
	const char *EXPECTED_CIPHER="RC2-64-CBC";
	
	OtbAsymCipher *asym_cipher=g_object_new(OTB_TYPE_ASYM_CIPHER, OTB_ASYM_CIPHER_PROP_SYM_CIPHER_NAME, EXPECTED_CIPHER, NULL);
	char *actual_cipher=NULL;
	g_object_get(asym_cipher, OTB_ASYM_CIPHER_PROP_SYM_CIPHER_NAME, &actual_cipher, NULL);
	g_assert_cmpstr(EXPECTED_CIPHER, ==, actual_cipher);
	g_free(actual_cipher);
	g_object_unref(asym_cipher);
}

static void otb_copy_public_key(OtbAsymCipher *asym_cipher_original, OtbAsymCipher *asym_cipher_public)
{
	char *public_key=NULL;
	g_object_get(asym_cipher_original, OTB_ASYM_CIPHER_PROP_PUBLIC_KEY, &public_key, NULL);
	g_assert(public_key!=NULL);
	g_object_set(asym_cipher_public, OTB_ASYM_CIPHER_PROP_PUBLIC_KEY, public_key, NULL);
	g_free(public_key);
}

static void otb_copy_private_key(OtbAsymCipher *asym_cipher_original, OtbAsymCipher *asym_cipher_private)
{
	OtbSymCipher *private_key_sym_cipher=g_object_new(OTB_TYPE_SYM_CIPHER, OTB_SYM_CIPHER_PROP_CIPHER, "AES-256-CBC", NULL);
	g_assert(otb_sym_cipher_generate_random_key(private_key_sym_cipher));
	GBytes *private_key_iv=NULL;
	GBytes *encrypted_private_key=otb_asym_cipher_get_encrypted_private_key(asym_cipher_original, private_key_sym_cipher, &private_key_iv);
	g_assert(private_key_iv!=NULL);
	g_assert(encrypted_private_key!=NULL);
	otb_asym_cipher_set_encrypted_private_key(asym_cipher_private, encrypted_private_key, private_key_sym_cipher, private_key_iv);
	g_bytes_unref(private_key_iv);
	g_bytes_unref(encrypted_private_key);
	g_object_unref(private_key_sym_cipher);
}

void otb_generate_public_private_keys(OtbAsymCipher **asym_cipher_public_out, OtbAsymCipher **asym_cipher_private_out)
{
	const size_t NEW_KEY_SIZE=512;
	
	OtbAsymCipher *asym_cipher_original=g_object_new(OTB_TYPE_ASYM_CIPHER, NULL);
	g_assert(otb_asym_cipher_generate_random_keys(asym_cipher_original, NEW_KEY_SIZE));
	*asym_cipher_public_out=g_object_new(OTB_TYPE_ASYM_CIPHER, NULL);
	*asym_cipher_private_out=g_object_new(OTB_TYPE_ASYM_CIPHER, NULL);
	otb_copy_public_key(asym_cipher_original, *asym_cipher_public_out);
	otb_copy_private_key(asym_cipher_original, *asym_cipher_private_out);
	g_object_unref(asym_cipher_original);
}

static void test_asym_cipher_encryption_in_steps()
{
	const size_t EXPECTED_MESSAGE_SIZE=74;
	const char *EXPECTED_MESSAGE="Timid men prefer the calm of despotism to the tempestuous sea of liberty.";
	
	OtbAsymCipher *asym_cipher_public=NULL;
	OtbAsymCipher *asym_cipher_private=NULL;
	otb_generate_public_private_keys(&asym_cipher_public, &asym_cipher_private);
	unsigned char *encrypted_message=otb_asym_cipher_create_encryption_buffer(asym_cipher_public, EXPECTED_MESSAGE_SIZE);
	GBytes *iv=NULL;
	GBytes *encrypted_key=NULL;
	OtbAsymCipherContext *encryption_context=otb_asym_cipher_init_encryption(asym_cipher_public, &encrypted_key, &iv);
	g_assert(encryption_context!=NULL);
	g_assert(iv!=NULL);
	g_assert(encrypted_key!=NULL);
	size_t encrypted_message_size=otb_asym_cipher_encrypt_next(encryption_context, EXPECTED_MESSAGE, EXPECTED_MESSAGE_SIZE, encrypted_message);
	encrypted_message_size+=otb_asym_cipher_finish_encrypt(encryption_context, encrypted_message+encrypted_message_size);
	g_assert_cmpint(0, !=, encrypted_message_size);
	g_assert(EXPECTED_MESSAGE_SIZE!=encrypted_message_size || memcmp(EXPECTED_MESSAGE, encrypted_message, encrypted_message_size)!=0);
	char *actual_message=otb_asym_cipher_create_decryption_buffer(asym_cipher_private, encrypted_message_size);
	OtbAsymCipherContext *decryption_context=otb_asym_cipher_init_decryption(asym_cipher_private, encrypted_key, iv);
	g_assert(decryption_context!=NULL);
	size_t actual_message_size=otb_asym_cipher_decrypt_next(decryption_context, encrypted_message, encrypted_message_size, actual_message);
	actual_message_size+=otb_asym_cipher_finish_decrypt(decryption_context, actual_message+actual_message_size);
	g_assert_cmpint(EXPECTED_MESSAGE_SIZE, ==, actual_message_size);
	g_assert_cmpstr(EXPECTED_MESSAGE, ==, actual_message);
	g_assert_cmpint(0, !=, actual_message_size);
	otb_asym_cipher_dispose_decryption_buffer(actual_message);
	g_free(encrypted_message);
	g_bytes_unref(encrypted_key);
	g_bytes_unref(iv);
	g_object_unref(asym_cipher_private);
	g_object_unref(asym_cipher_public);
}

static void test_asym_cipher_encryption()
{
	const size_t EXPECTED_MESSAGE_SIZE=307;
	const char *EXPECTED_MESSAGE="There was not one hireling there. I have no doubt that it was a principle they fought for, as much as our ancestors, and not to avoid a three-penny tax on their tea; and the results of this battle will be as important and memorable to those whom it concerns as those of the battle of Bunker Hill, at least.";
	
	OtbAsymCipher *asym_cipher_public=NULL;
	OtbAsymCipher *asym_cipher_private=NULL;
	otb_generate_public_private_keys(&asym_cipher_public, &asym_cipher_private);
	GBytes *iv=NULL;
	GBytes *encrypted_key=NULL;
	size_t encrypted_message_size=0;
	unsigned char *encrypted_message=otb_asym_cipher_encrypt(asym_cipher_public, EXPECTED_MESSAGE, EXPECTED_MESSAGE_SIZE, &encrypted_key, &iv, &encrypted_message_size);
	g_assert(iv!=NULL);
	g_assert(encrypted_key!=NULL);
	g_assert(encrypted_message!=NULL);
	g_assert_cmpint(0, !=, encrypted_message_size);
	g_assert(EXPECTED_MESSAGE_SIZE!=encrypted_message_size || memcmp(EXPECTED_MESSAGE, encrypted_message, encrypted_message_size)!=0);
	size_t actual_message_size=0;
	char *actual_message=otb_asym_cipher_decrypt(asym_cipher_private, encrypted_message, encrypted_message_size, encrypted_key, iv, &actual_message_size);
	g_assert_cmpint(EXPECTED_MESSAGE_SIZE, ==, actual_message_size);
	g_assert_cmpstr(EXPECTED_MESSAGE, ==, actual_message);
	g_assert_cmpint(0, !=, actual_message_size);
	otb_asym_cipher_dispose_decryption_buffer(actual_message);
	g_free(encrypted_message);
	g_bytes_unref(encrypted_key);
	g_bytes_unref(iv);
	g_object_unref(asym_cipher_private);
	g_object_unref(asym_cipher_public);
}

void otb_add_asym_cipher_tests()
{
	otb_add_test_func("/asym_cipher/test_asym_cipher_properties", test_asym_cipher_properties);
	otb_add_test_func("/asym_cipher/test_asym_cipher_encryption_in_steps", test_asym_cipher_encryption_in_steps);
	otb_add_test_func("/asym_cipher/test_asym_cipher_encryption", test_asym_cipher_encryption);
}
