/**
 * Copyright © 2015 the OTB team
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
#include "../src/sym-cipher.h"

static void test_sym_cipher_properties()
{
	const char *EXPECTED_CIPHER="RC2-64-CBC";
	const char *EXPECTED_MESSAGE_DIGEST="MD5";
	const unsigned int EXPECTED_HASH_ITERATIONS=31415;
	
	OtbSymCipher *sym_cipher=g_object_new(OTB_TYPE_SYM_CIPHER, OTB_SYM_CIPHER_PROP_CIPHER, EXPECTED_CIPHER, OTB_SYM_CIPHER_PROP_MESSAGE_DIGEST, EXPECTED_MESSAGE_DIGEST, OTB_SYM_CIPHER_PROP_HASH_ITERATIONS, EXPECTED_HASH_ITERATIONS, NULL);
	char *actual_cipher=NULL;
	char *actual_message_digest=NULL;
	unsigned int actual_hash_iterations;
	g_object_get(sym_cipher, OTB_SYM_CIPHER_PROP_CIPHER, &actual_cipher, OTB_SYM_CIPHER_PROP_MESSAGE_DIGEST, &actual_message_digest, OTB_SYM_CIPHER_PROP_HASH_ITERATIONS, &actual_hash_iterations, NULL);
	g_assert_cmpstr(EXPECTED_CIPHER, ==, actual_cipher);
	g_assert_cmpstr(EXPECTED_MESSAGE_DIGEST, ==, actual_message_digest);
	g_assert_cmpint(EXPECTED_HASH_ITERATIONS, ==, actual_hash_iterations);
	g_free(actual_message_digest);
	g_free(actual_cipher);
	g_object_unref(sym_cipher);
}

static void test_sym_cipher_hash_passphrase()
{
	const char *EXPECTED_PASSPHRASE="...and verily, I have even heard the frog croak in it!";
	const char *UNEXPECTED_PASSPHRASE="...to one who is striking at the root!";
	
	OtbSymCipher *sym_cipher=g_object_new(OTB_TYPE_SYM_CIPHER, OTB_SYM_CIPHER_PROP_HASH_ITERATIONS, 2048, NULL);
	OtbSymCipherSalt *expected_salt=NULL;
	GBytes *passphrase_hash=otb_sym_cipher_hash_passphrase(sym_cipher, EXPECTED_PASSPHRASE, &expected_salt);
	g_assert(expected_salt!=NULL);
	g_assert(!otb_sym_cipher_validate_passphrase(sym_cipher, UNEXPECTED_PASSPHRASE, passphrase_hash, expected_salt));
	((unsigned char*)expected_salt)[1]++;
	g_assert(!otb_sym_cipher_validate_passphrase(sym_cipher, EXPECTED_PASSPHRASE, passphrase_hash, expected_salt));
	((unsigned char*)expected_salt)[1]--;
	g_assert(otb_sym_cipher_validate_passphrase(sym_cipher, EXPECTED_PASSPHRASE, passphrase_hash, expected_salt));
	g_bytes_unref(passphrase_hash);
	g_object_unref(sym_cipher);
	otb_sym_cipher_salt_free(expected_salt);
}

static void test_sym_cipher_encryption_in_steps()
{
	const size_t EXPECTED_MESSAGE_SIZE=523;
	const char *EXPECTED_MESSAGE="It is forbidden to kill; therefore all murderers are punished unless they kill in large numbers and to the sound of trumpets.";
	const char *PASSPHRASE="All is for the best in the best of all possible worlds!";
	
	OtbSymCipher *sym_cipher=g_object_new(OTB_TYPE_SYM_CIPHER, OTB_SYM_CIPHER_PROP_CIPHER, "AES-256-CBC", OTB_SYM_CIPHER_PROP_MESSAGE_DIGEST, "SHA512", OTB_SYM_CIPHER_PROP_HASH_ITERATIONS, 2048, NULL);
	g_assert(otb_sym_cipher_generate_random_key(sym_cipher));
	unsigned char *encrypted_message=otb_sym_cipher_create_encryption_buffer(sym_cipher, EXPECTED_MESSAGE_SIZE);
	GBytes *iv=NULL;
	OtbSymCipherContext *encryption_context=otb_sym_cipher_init_encryption(sym_cipher, &iv);
	g_assert(encryption_context!=NULL);
	g_assert(iv!=NULL);
	size_t encrypted_message_size=otb_sym_cipher_encrypt_next(encryption_context, EXPECTED_MESSAGE, EXPECTED_MESSAGE_SIZE, encrypted_message);
	encrypted_message_size+=otb_sym_cipher_finish_encrypt(encryption_context, encrypted_message+encrypted_message_size);
	g_assert_cmpint(0, !=, encrypted_message_size);
	g_assert(EXPECTED_MESSAGE_SIZE!=encrypted_message_size || memcmp(EXPECTED_MESSAGE, encrypted_message, encrypted_message_size)!=0);
	OtbSymCipherSalt *salt=NULL;
	GBytes *wrapped_key=otb_sym_cipher_wrap_key(sym_cipher, PASSPHRASE, &salt);
	g_assert(salt!=NULL);
	g_assert(otb_sym_cipher_unwrap_key(sym_cipher, wrapped_key, PASSPHRASE, salt));
	char *actual_message=otb_sym_cipher_create_decryption_buffer(sym_cipher, encrypted_message_size);
	OtbSymCipherContext *decryption_context=otb_sym_cipher_init_decryption(sym_cipher, iv);
	g_assert(decryption_context!=NULL);
	size_t actual_message_size=otb_sym_cipher_decrypt_next(decryption_context, encrypted_message, encrypted_message_size, actual_message);
	actual_message_size+=otb_sym_cipher_finish_decrypt(decryption_context, actual_message+actual_message_size);
	g_assert_cmpint(0, !=, actual_message_size);
	g_assert_cmpint(EXPECTED_MESSAGE_SIZE, ==, actual_message_size);
	g_assert_cmpstr(EXPECTED_MESSAGE, ==, actual_message);
	otb_sym_cipher_salt_free(salt);
	g_bytes_unref(wrapped_key);
	otb_sym_cipher_dispose_decryption_buffer(actual_message);
	g_free(encrypted_message);
	g_bytes_unref(iv);
	g_object_unref(sym_cipher);
}

static void test_sym_cipher_encryption()
{
	const size_t EXPECTED_MESSAGE_SIZE=523;
	const char *EXPECTED_MESSAGE="It is forbidden to kill; therefore all murderers are punished unless they kill in large numbers and to the sound of trumpets.";
	const char *PASSPHRASE="All is for the best in the best of all possible worlds!";
	
	OtbSymCipher *sym_cipher=g_object_new(OTB_TYPE_SYM_CIPHER, OTB_SYM_CIPHER_PROP_CIPHER, "AES-256-CBC", OTB_SYM_CIPHER_PROP_MESSAGE_DIGEST, "SHA512", OTB_SYM_CIPHER_PROP_HASH_ITERATIONS, 2048, NULL);
	g_assert(otb_sym_cipher_generate_random_key(sym_cipher));
	unsigned char *encrypted_message=NULL;
	GBytes *iv=NULL;
	size_t encrypted_message_size=otb_sym_cipher_encrypt(sym_cipher, EXPECTED_MESSAGE, EXPECTED_MESSAGE_SIZE, &iv, &encrypted_message);
	g_assert_cmpint(0, !=, encrypted_message_size);
	g_assert(EXPECTED_MESSAGE_SIZE!=encrypted_message_size || memcmp(EXPECTED_MESSAGE, encrypted_message, encrypted_message_size)!=0);
	OtbSymCipherSalt *salt=NULL;
	GBytes *wrapped_key=otb_sym_cipher_wrap_key(sym_cipher, PASSPHRASE, &salt);
	g_assert(salt!=NULL);
	g_assert(otb_sym_cipher_unwrap_key(sym_cipher, wrapped_key, PASSPHRASE, salt));
	void *actual_message=NULL;
	size_t actual_message_size=otb_sym_cipher_decrypt(sym_cipher, encrypted_message, encrypted_message_size, iv, &actual_message);
	g_assert_cmpint(EXPECTED_MESSAGE_SIZE, ==, actual_message_size);
	g_assert_cmpstr(EXPECTED_MESSAGE, ==, actual_message);
	otb_sym_cipher_salt_free(salt);
	g_bytes_unref(wrapped_key);
	otb_sym_cipher_dispose_decryption_buffer(actual_message);
	g_free(encrypted_message);
	g_bytes_unref(iv);
	g_object_unref(sym_cipher);
}

void otb_add_sym_cipher_tests()
{
	otb_add_test_func("/sym_cipher/test_sym_cipher_properties", test_sym_cipher_properties);
	otb_add_test_func("/sym_cipher/test_sym_cipher_hash_passphrase", test_sym_cipher_hash_passphrase);
	otb_add_test_func("/sym_cipher/test_sym_cipher_encryption_in_steps", test_sym_cipher_encryption_in_steps);
	otb_add_test_func("/sym_cipher/test_sym_cipher_encryption", test_sym_cipher_encryption);
}
