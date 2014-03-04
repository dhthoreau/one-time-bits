/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <glib/gstdio.h>
#include <string.h>
#include <uuid/uuid.h>

#include "main.h"
#include "test-utils.h"
#include "../src/io.h"
#include "../src/local-crypto.h"
#include "../src/settings.h"
#include "../src/uuid-util.h"
#include "../src/user.h"

static void test_otb_user_create_with_no_config_file()
{
	const char *EXPECTED_DEFAULT_SYM_CIPHER_NAME="AES-256-CBC";
	
	otb_settings_initialize("otb-tests", "otb");
	otb_settings_set_config_directory_path(otb_get_test_dir_path());
	char *config_file_path=g_build_filename(otb_get_test_dir_path(), "otb.conf", NULL);
	g_unlink(config_file_path);
	g_free(config_file_path);
	otb_test_setup_local_crypto();
	OtbUser *user=otb_user_create();
	g_assert(user!=NULL);
	const uuid_t *actual_unique_id=NULL;
	OtbAsymCipher *actual_asym_cipher=NULL;
	char *actual_onion_base_domain=NULL;
	g_object_get(user, OTB_USER_PROP_UNIQUE_ID, &actual_unique_id, OTB_USER_PROP_ASYM_CIPHER, &actual_asym_cipher, OTB_USER_PROP_ONION_BASE_DOMAIN, &actual_onion_base_domain, NULL);
	g_assert(actual_unique_id!=NULL);
	char *actual_sym_cipher_name=NULL;
	char *actual_public_key=NULL;
	g_object_get(actual_asym_cipher, OTB_ASYM_CIPHER_PROP_SYM_CIPHER, &actual_sym_cipher_name, OTB_ASYM_CIPHER_PROP_PUBLIC_KEY, &actual_public_key, NULL);
	g_assert_cmpstr(EXPECTED_DEFAULT_SYM_CIPHER_NAME, ==, actual_sym_cipher_name);
	g_free(actual_sym_cipher_name);
	g_assert(actual_public_key!=NULL);
	g_free(actual_public_key);
	g_object_unref(actual_asym_cipher);
	g_assert(actual_onion_base_domain==NULL);
	g_object_unref(user);
}

static void otb_write_unique_id(FILE *file, uuid_t unique_id)
{
	char *encoded_unique_id=g_base64_encode(unique_id, sizeof(uuid_t));
	g_assert(otb_write("unique-id=", 1, 10, file)==10);
	g_assert(otb_write(encoded_unique_id, 1, strlen(encoded_unique_id), file)==strlen(encoded_unique_id));
	g_assert(otb_write("\n", 1, 1, file)==1);
	g_free(encoded_unique_id);
}

static void otb_write_sym_cipher_name(FILE *file, const char *sym_cipher_name)
{
	g_assert(otb_write("sym-cipher=", 1, 11, file)==11);
	g_assert(otb_write(sym_cipher_name, 1, strlen(sym_cipher_name), file)==strlen(sym_cipher_name));
	g_assert(otb_write("\n", 1, 1, file)==1);
}

static void otb_write_asym_cipher(FILE *file, const OtbAsymCipher *asym_cipher)
{
	OtbSymCipher *local_crypto=otb_local_crypto_get_sym_cipher_with_ref();
	GBytes *iv;
	GBytes *encrypted_private_key=otb_asym_cipher_get_encrypted_private_key(asym_cipher, local_crypto, &iv);
	g_object_unref(local_crypto);
	g_assert(iv!=NULL);
	g_assert(encrypted_private_key!=NULL);
	char *encoded_iv=g_base64_encode(g_bytes_get_data(iv, NULL), g_bytes_get_size(iv));
	g_bytes_unref(iv);
	char *encoded_encrypted_private_key=g_base64_encode(g_bytes_get_data(encrypted_private_key, NULL), g_bytes_get_size(encrypted_private_key));
// FARE - Local crypto è rotto da questo:
//	g_bytes_unref(encrypted_private_key);
	g_assert(otb_write("asym-cipher-private-key-iv=", 1, 27, file)==27);
	g_assert(otb_write(encoded_iv, 1, strlen(encoded_iv), file)==strlen(encoded_iv));
	g_assert(otb_write("\n", 1, 1, file)==1);
	g_assert(otb_write("asym-cipher-private-key=", 1, 24, file)==24);
	g_assert(otb_write(encoded_encrypted_private_key, 1, strlen(encoded_encrypted_private_key), file)==strlen(encoded_encrypted_private_key));
	g_assert(otb_write("\n", 1, 1, file)==1);
	g_free(encoded_iv);
	g_free(encoded_encrypted_private_key);
}

static void otb_write_onion_base_domain(FILE *file, const char *onion_base_domain)
{
	g_assert(otb_write("onion-base-domain=", 1, 18, file)==18);
	g_assert(otb_write(onion_base_domain, 1, strlen(onion_base_domain), file)==strlen(onion_base_domain));
	g_assert(otb_write("\n", 1, 1, file)==1);
}

static void otb_setup_config_file_for_user_tests(uuid_t unique_id, const char *sym_cipher_name, const OtbAsymCipher *asym_cipher, const char *onion_base_domain)
{
	char *config_file_path=g_build_filename(otb_get_test_dir_path(), "otb.conf", NULL);
	FILE *file=otb_open_text_for_write(config_file_path);
	g_free(config_file_path);
	g_assert(file!=NULL);
	g_assert(otb_write("[user]\n", 1, 7, file)==7);
	otb_write_unique_id(file, unique_id);
	otb_write_sym_cipher_name(file, sym_cipher_name);
	otb_write_asym_cipher(file, asym_cipher);
	otb_write_onion_base_domain(file, onion_base_domain);
	g_assert(otb_close(file));
}

static void test_otb_user_create_from_existing_config_file()
{
	const size_t NEW_KEY_LENGTH=512;
	const char *EXPECTED_SYM_CIPHER_NAME="DES-CBC";
	const char *EXPECTED_BASE_ONION_DOMAIN_1="akjsdhkljashgd";
	const char *EXPECTED_BASE_ONION_DOMAIN_2="kjshdfjkhgssdj";
	
	otb_test_setup_local_crypto();
	uuid_t expected_unique_id;
	uuid_generate(expected_unique_id);
	OtbAsymCipher *expected_asym_cipher=g_object_new(OTB_TYPE_ASYM_CIPHER, NULL);
	g_assert(otb_asym_cipher_generate_random_keys(expected_asym_cipher, NEW_KEY_LENGTH));
	otb_setup_config_file_for_user_tests(expected_unique_id, EXPECTED_SYM_CIPHER_NAME, expected_asym_cipher, EXPECTED_BASE_ONION_DOMAIN_1);
	otb_settings_initialize("otb-tests", "otb");
	otb_settings_set_config_directory_path(otb_get_test_dir_path());
	OtbUser *user=otb_user_create();
	g_assert(user!=NULL);
	const uuid_t *actual_unique_id=NULL;
	OtbAsymCipher *actual_asym_cipher=NULL;
	char *actual_onion_base_domain=NULL;
	g_object_get(user, OTB_USER_PROP_UNIQUE_ID, &actual_unique_id, OTB_USER_PROP_ASYM_CIPHER, &actual_asym_cipher, OTB_USER_PROP_ONION_BASE_DOMAIN, &actual_onion_base_domain, NULL);
	g_assert_cmpint(0, ==, uuid_compare(expected_unique_id, *actual_unique_id));
	char *expected_public_key=NULL;
	g_object_get(expected_asym_cipher, OTB_ASYM_CIPHER_PROP_PUBLIC_KEY, &expected_public_key, NULL);
	g_assert(expected_public_key!=NULL);
	char *actual_sym_cipher_name=NULL;
	char *actual_public_key=NULL;
	g_object_get(actual_asym_cipher, OTB_ASYM_CIPHER_PROP_SYM_CIPHER, &actual_sym_cipher_name, OTB_ASYM_CIPHER_PROP_PUBLIC_KEY, &actual_public_key, NULL);
	g_assert_cmpstr(EXPECTED_SYM_CIPHER_NAME, ==, actual_sym_cipher_name);
	g_free(actual_sym_cipher_name);
	g_assert_cmpstr(expected_public_key, ==, actual_public_key);
	g_free(expected_public_key);
	g_free(actual_public_key);
	g_object_unref(actual_asym_cipher);
	g_assert_cmpstr(EXPECTED_BASE_ONION_DOMAIN_1, ==, actual_onion_base_domain);
	g_free(actual_onion_base_domain);
	g_assert(otb_user_set_onion_base_domain(user, EXPECTED_BASE_ONION_DOMAIN_2));
	g_object_get(user, OTB_USER_PROP_ONION_BASE_DOMAIN, &actual_onion_base_domain, NULL);
	g_assert_cmpstr(EXPECTED_BASE_ONION_DOMAIN_2, ==, actual_onion_base_domain);
	g_free(actual_onion_base_domain);
	g_object_unref(user);
	g_object_unref(expected_asym_cipher);
}

void otb_add_user_tests()
{
	otb_add_test_func("/user/test_otb_user_create_with_no_config_file", test_otb_user_create_with_no_config_file);
	otb_add_test_func("/user/test_otb_user_create_from_existing_config_file", test_otb_user_create_from_existing_config_file);
}
