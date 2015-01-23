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

#include "main.h"
#include "dummy-friend.h"
#include "dummy-user.h"
#include "test-utils.h"
#include "../src/friend.h"
#include "../src/io.h"
#include "../src/local-crypto.h"
#include "../src/settings.h"
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
	OtbUser *user=otb_user_load();
	g_assert(user!=NULL);
	OtbUniqueId *actual_unique_id=NULL;
	OtbAsymCipher *actual_asym_cipher=NULL;
	char *actual_address=NULL;
	g_object_get(user, OTB_USER_PROP_UNIQUE_ID, &actual_unique_id, OTB_USER_PROP_ASYM_CIPHER, &actual_asym_cipher, OTB_USER_PROP_ADDRESS, &actual_address, NULL);
	g_assert(actual_unique_id!=NULL);
	char *actual_sym_cipher_name=NULL;
	char *actual_public_key=NULL;
	g_object_get(actual_asym_cipher, OTB_ASYM_CIPHER_PROP_SYM_CIPHER_NAME, &actual_sym_cipher_name, OTB_ASYM_CIPHER_PROP_PUBLIC_KEY, &actual_public_key, NULL);
	g_assert_cmpstr(EXPECTED_DEFAULT_SYM_CIPHER_NAME, ==, actual_sym_cipher_name);
	g_free(actual_sym_cipher_name);
	g_assert(actual_public_key!=NULL);
	g_free(actual_public_key);
	g_object_unref(actual_asym_cipher);
	otb_unique_id_unref(actual_unique_id);
	g_assert(actual_address==NULL);
	g_object_unref(user);
}

static void otb_write_unique_id(FILE *file, const OtbUniqueId *unique_id)
{
	char *encoded_unique_id=g_base64_encode(otb_unique_id_get_bytes(unique_id), OTB_UNIQUE_ID_BYTES_LENGTH);
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
	g_bytes_unref(encrypted_private_key);
	g_assert(otb_write("asym-cipher-private-key-iv=", 1, 27, file)==27);
	g_assert(otb_write(encoded_iv, 1, strlen(encoded_iv), file)==strlen(encoded_iv));
	g_assert(otb_write("\n", 1, 1, file)==1);
	g_assert(otb_write("asym-cipher-private-key=", 1, 24, file)==24);
	g_assert(otb_write(encoded_encrypted_private_key, 1, strlen(encoded_encrypted_private_key), file)==strlen(encoded_encrypted_private_key));
	g_assert(otb_write("\n", 1, 1, file)==1);
	g_free(encoded_iv);
	g_free(encoded_encrypted_private_key);
}

static void otb_write_address(FILE *file, const char *address)
{
	g_assert(otb_write("address=", 1, 8, file)==8);
	g_assert(otb_write(address, 1, strlen(address), file)==strlen(address));
	g_assert(otb_write("\n", 1, 1, file)==1);
}

void otb_setup_config_file_for_user_tests(const OtbUniqueId *unique_id, const char *sym_cipher_name, const OtbAsymCipher *asym_cipher, const char *address)
{
	otb_test_setup_local_crypto();
	char *config_file_path=g_build_filename(otb_get_test_dir_path(), "otb.conf", NULL);
	FILE *file=otb_open_text_for_write(config_file_path);
	g_free(config_file_path);
	g_assert(file!=NULL);
	g_assert(otb_write("[user]\n", 1, 7, file)==7);
	otb_write_unique_id(file, unique_id);
	otb_write_sym_cipher_name(file, sym_cipher_name);
	otb_write_asym_cipher(file, asym_cipher);
	otb_write_address(file, address);
	g_assert(otb_close(file));
	otb_settings_initialize("otb-tests", "otb");
	otb_settings_set_config_directory_path(otb_get_test_dir_path());
}

static OtbUser *otb_load_user_from_existing_config_file(const OtbUniqueId *unique_id, const char *sym_cipher_name, OtbAsymCipher *asym_cipher, const char *address)
{
	otb_setup_config_file_for_user_tests(unique_id, sym_cipher_name, asym_cipher, address);
	OtbUser *user=otb_user_load();
	g_assert(user!=NULL);
	return user;
}

static void test_otb_user_create_from_existing_config_file()
{
	const size_t NEW_KEY_LENGTH=512;
	const char *EXPECTED_SYM_CIPHER_NAME="DES-CBC";
	const char *EXPECTED_ADDRESS1="akjsdhkljashgd.onion";
	const char *EXPECTED_ADDRESS2="kjshdfjkhgssdj.onion";
	
	OtbUniqueId *expected_unique_id=otb_unique_id_new();
	OtbAsymCipher *expected_asym_cipher=g_object_new(OTB_TYPE_ASYM_CIPHER, NULL);
	g_assert(otb_asym_cipher_generate_random_keys(expected_asym_cipher, NEW_KEY_LENGTH));
	OtbUser *user=otb_load_user_from_existing_config_file(expected_unique_id, EXPECTED_SYM_CIPHER_NAME, expected_asym_cipher, EXPECTED_ADDRESS1);
	OtbUniqueId *actual_unique_id=NULL;
	OtbAsymCipher *actual_asym_cipher=NULL;
	char *actual_address1=NULL;
	g_object_get(user, OTB_USER_PROP_UNIQUE_ID, &actual_unique_id, OTB_USER_PROP_ASYM_CIPHER, &actual_asym_cipher, OTB_USER_PROP_ADDRESS, &actual_address1, NULL);
	g_assert_cmpint(0, ==, otb_unique_id_compare(expected_unique_id, actual_unique_id));
	char *expected_public_key=NULL;
	g_object_get(expected_asym_cipher, OTB_ASYM_CIPHER_PROP_PUBLIC_KEY, &expected_public_key, NULL);
	g_assert(expected_public_key!=NULL);
	char *actual_sym_cipher_name=NULL;
	char *actual_public_key=NULL;
	g_object_get(actual_asym_cipher, OTB_ASYM_CIPHER_PROP_SYM_CIPHER_NAME, &actual_sym_cipher_name, OTB_ASYM_CIPHER_PROP_PUBLIC_KEY, &actual_public_key, NULL);
	g_assert_cmpstr(EXPECTED_SYM_CIPHER_NAME, ==, actual_sym_cipher_name);
	g_assert_cmpstr(expected_public_key, ==, actual_public_key);
	g_assert_cmpstr(EXPECTED_ADDRESS1, ==, actual_address1);
	g_assert(otb_user_set_address(user, EXPECTED_ADDRESS2));
	char *actual_address2=NULL;
	g_object_get(user, OTB_USER_PROP_ADDRESS, &actual_address2, NULL);
	g_assert_cmpstr(EXPECTED_ADDRESS2, ==, actual_address2);
	otb_unique_id_unref(actual_unique_id);
	otb_unique_id_unref(expected_unique_id);
	g_free(actual_sym_cipher_name);
	g_free(expected_public_key);
	g_free(actual_public_key);
	g_object_unref(actual_asym_cipher);
	g_free(actual_address1);
	g_free(actual_address2);
	g_object_unref(user);
	g_object_unref(expected_asym_cipher);
}

static void otb_do_user_export_test(OtbUser **user, GKeyFile **export_key_file)
{
	const size_t NEW_KEY_LENGTH=512;
	const char *EXPECTED_SYM_CIPHER_NAME="DES-CBC";
	const char *EXPECTED_ADDRESS="kdjhgkfgjhfhj.onion";
	
	OtbUniqueId *expected_unique_id=otb_unique_id_new();
	OtbAsymCipher *expected_asym_cipher=g_object_new(OTB_TYPE_ASYM_CIPHER, NULL);
	g_assert(otb_asym_cipher_generate_random_keys(expected_asym_cipher, NEW_KEY_LENGTH));
	*user=otb_load_user_from_existing_config_file(expected_unique_id, EXPECTED_SYM_CIPHER_NAME, expected_asym_cipher, EXPECTED_ADDRESS);
	char *expected_public_key=NULL;
	g_object_get(expected_asym_cipher, OTB_ASYM_CIPHER_PROP_PUBLIC_KEY, &expected_public_key, NULL);
	g_assert(expected_public_key!=NULL);
	char *export_string=otb_user_export(*user);
	g_assert((*export_key_file=otb_settings_load_key_file_from_string(export_string))!=NULL);
	unsigned char *actual_unique_id_bytes=otb_settings_get_bytes(*export_key_file, OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_UNIQUE_ID, NULL);
	OtbUniqueId *actual_unique_id=otb_unique_id_from_bytes(actual_unique_id_bytes);
	char *actual_public_key=otb_settings_get_string(*export_key_file, OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_PUBLIC_KEY);
	char *actual_sym_cipher_name=otb_settings_get_string(*export_key_file, OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_TRANSPORT_CIPHER_NAME);
	char *actual_address=otb_settings_get_string(*export_key_file, OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_ADDRESS);
	g_assert_cmpint(0, ==, otb_unique_id_compare(expected_unique_id, actual_unique_id));
	g_assert_cmpstr(expected_public_key, ==, actual_public_key);
	g_assert_cmpstr(EXPECTED_SYM_CIPHER_NAME, ==, actual_sym_cipher_name);
	g_assert_cmpstr(EXPECTED_ADDRESS, ==, actual_address);
	g_free(export_string);
	otb_unique_id_unref(actual_unique_id);
	g_free(actual_unique_id_bytes);
	otb_unique_id_unref(expected_unique_id);
	g_free(expected_public_key);
	g_free(actual_public_key);
	g_free(actual_address);
	g_object_unref(expected_asym_cipher);
}

static void test_otb_user_export()
{
	OtbUser *user=NULL;
	GKeyFile *export_key_file=NULL;
	otb_do_user_export_test(&user, &export_key_file);
	g_key_file_unref(export_key_file);
	g_assert(OTB_IS_USER(user));
	g_assert(!OTB_IS_DUMMY_USER(user));
	g_object_unref(user);
}

static void test_otb_dummy_user_export()
{
	OtbUser *user=NULL;
	GKeyFile *export_key_file=NULL;
	otb_user_set_runtime_type(OTB_TYPE_DUMMY_USER);
	otb_do_user_export_test(&user, &export_key_file);
	char *actual_dummy_value=otb_settings_get_string(export_key_file, OTB_DUMMY_FRIEND_GROUP, OTB_DUMMY_FRIEND_KEY);
	g_key_file_unref(export_key_file);
	g_assert_cmpstr(OTB_DUMMY_USER_EXPORT_VALUE, ==, actual_dummy_value);
	g_assert(OTB_IS_USER(user));
	g_assert(OTB_IS_DUMMY_USER(user));
	g_free(actual_dummy_value);
	g_object_unref(user);
	otb_user_set_runtime_type(OTB_TYPE_USER);
}

void otb_add_user_tests()
{
	otb_add_test_func("/user/test_otb_user_create_with_no_config_file", test_otb_user_create_with_no_config_file);
	otb_add_test_func("/user/test_otb_user_create_from_existing_config_file", test_otb_user_create_from_existing_config_file);
	otb_add_test_func("/user/test_otb_user_export", test_otb_user_export);
	otb_add_test_func("/user/test_otb_dummy_user_export", test_otb_dummy_user_export);
}
