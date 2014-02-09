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
#include "../src/cipher.h"

static void test_cipher_properties()
{
	const char *EXPECTED_CIPHER="RC2-64-CBC";
	const char *EXPECTED_MESSAGE_DIGEST="MD5";
	const unsigned int EXPECTED_HASH_ITERATIONS=31415;
	
	OtbCipher *cipher=g_object_new(OTB_TYPE_CIPHER, OTB_CIPHER_PROP_CIPHER, EXPECTED_CIPHER, OTB_CIPHER_PROP_MESSAGE_DIGEST, EXPECTED_MESSAGE_DIGEST, OTB_CIPHER_PROP_HASH_ITERATIONS, EXPECTED_HASH_ITERATIONS, NULL);
	char *actual_cipher=NULL;
	char *actual_message_digest=NULL;
	unsigned int actual_has_iterations;
	g_object_get(cipher, OTB_CIPHER_PROP_CIPHER, &actual_cipher, OTB_CIPHER_PROP_MESSAGE_DIGEST, &actual_message_digest, OTB_CIPHER_PROP_HASH_ITERATIONS, &actual_has_iterations, NULL);
	g_assert_cmpstr(EXPECTED_CIPHER, ==, actual_cipher);
	g_assert_cmpstr(EXPECTED_MESSAGE_DIGEST, ==, actual_message_digest);
	g_assert_cmpint(EXPECTED_HASH_ITERATIONS, ==, actual_has_iterations);
	g_free(actual_message_digest);
	g_free(actual_cipher);
	g_object_unref(cipher);
}

static void test_cipher_hash_passphrase()
{
	const char *EXPECTED_PASSPHRASE="...and verily, I have even heard the frog croak in it!";
	const char *UNEXPECTED_PASSPHRASE="...to one who is striking at the root!";
	
	OtbCipher *cipher=g_object_new(OTB_TYPE_CIPHER, OTB_CIPHER_PROP_HASH_ITERATIONS, 2048, NULL);
	OtbCipherSalt expected_salt;
	GBytes *passphrase_hash=otb_cipher_hash_passphrase(cipher, EXPECTED_PASSPHRASE, expected_salt);
	g_assert(!otb_cipher_validate_passphrase(cipher, UNEXPECTED_PASSPHRASE, passphrase_hash, expected_salt));
	expected_salt[0]++;
	g_assert(!otb_cipher_validate_passphrase(cipher, EXPECTED_PASSPHRASE, passphrase_hash, expected_salt));
	expected_salt[0]--;
	g_assert(otb_cipher_validate_passphrase(cipher, EXPECTED_PASSPHRASE, passphrase_hash, expected_salt));
	g_bytes_unref(passphrase_hash);
	g_object_unref(cipher);
}

static void test_cipher_generate_random_iv()
{
	OtbCipher *cipher=g_object_new(OTB_TYPE_CIPHER, NULL);
	GBytes *actual_iv1=otb_cipher_generate_random_iv(cipher);
	g_assert(actual_iv1!=NULL);
	GBytes *actual_iv2=otb_cipher_generate_random_iv(cipher);
	g_assert(actual_iv2!=NULL);
	g_assert(!g_bytes_equal(actual_iv1, actual_iv2));
	g_bytes_unref(actual_iv1);
	g_bytes_unref(actual_iv2);
	g_object_unref(cipher);
}

static void test_cipher_encryption()
{
	const char EXPECTED_MESSAGE_SIZE=126;
	const char *EXPECTED_MESSAGE="It is forbidden to kill; therefore all murderers are punished unless they kill in large numbers and to the sound of trumpets.";
	const char *PASSPHRASE="All is for the best in the best of all possible worlds!";
	
	OtbCipher *cipher=g_object_new(OTB_TYPE_CIPHER, OTB_CIPHER_PROP_CIPHER, "aes-256-cbc", OTB_CIPHER_PROP_MESSAGE_DIGEST, "sha512", OTB_CIPHER_PROP_HASH_ITERATIONS, 2048, NULL);
	g_assert(otb_cipher_generate_random_key(cipher));
	GBytes *iv=otb_cipher_generate_random_iv(cipher);
	g_assert(iv!=NULL);
	char *encrypted_message=otb_cipher_create_encryption_buffer(cipher, EXPECTED_MESSAGE_SIZE, NULL);
	OtbCipherContext *encryption_context=otb_cipher_init_encryption(cipher, iv);
	g_assert(encryption_context!=NULL);
	size_t encrypted_message_size=otb_cipher_encrypt(encryption_context, EXPECTED_MESSAGE, EXPECTED_MESSAGE_SIZE, encrypted_message);
	encrypted_message_size+=otb_cipher_finish_encrypt(encryption_context, encrypted_message+encrypted_message_size);
	g_assert_cmpint(0, !=, encrypted_message_size);
	g_assert(EXPECTED_MESSAGE_SIZE!=encrypted_message_size || memcmp(EXPECTED_MESSAGE, encrypted_message, encrypted_message_size)!=0);
	OtbCipherSalt salt;
	GBytes *wrapped_key=otb_cipher_wrap_key(cipher, PASSPHRASE, salt);
	g_assert(otb_cipher_unwrap_key(cipher, wrapped_key, PASSPHRASE, salt));
	g_bytes_unref(wrapped_key);
	char *decrypted_message=otb_cipher_create_encryption_buffer(cipher, encrypted_message_size, NULL);
	OtbCipherContext *decryption_context=otb_cipher_init_decryption(cipher, iv);
	g_assert(decryption_context!=NULL);
	size_t actual_message_size=otb_cipher_decrypt(decryption_context, encrypted_message, encrypted_message_size, decrypted_message);
	actual_message_size+=otb_cipher_finish_decrypt(decryption_context, decrypted_message+actual_message_size);
	g_assert_cmpint(0, !=, actual_message_size);
	g_assert_cmpint(EXPECTED_MESSAGE_SIZE, ==, actual_message_size);
	g_assert_cmpstr(EXPECTED_MESSAGE, ==, decrypted_message);
	g_free(decrypted_message);
	g_free(encrypted_message);
	g_bytes_unref(iv);
	g_object_unref(cipher);
}

void add_cipher_tests()
{
	add_test_func("/cipher/test_cipher_properties", test_cipher_properties);
	add_test_func("/cipher/test_cipher_hash_passphrase", test_cipher_hash_passphrase);
	add_test_func("/cipher/test_cipher_generate_random_iv", test_cipher_generate_random_iv);
	add_test_func("/cipher/test_cipher_encryption", test_cipher_encryption);
}
