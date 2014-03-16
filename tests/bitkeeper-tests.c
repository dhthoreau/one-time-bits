/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include "main.h"
#include "friend-tests.h"
#include "test-utils.h"
#include "user-tests.h"
#include "../src/bitkeeper.h"
#include "../src/settings.h"

static void test_otb_bitkeeper_user()
{
	const size_t NEW_KEY_LENGTH=512;
	const char *EXPECTED_SYM_CIPHER_NAME="DES-CBC";
	const char *EXPECTED_BASE_ONION_DOMAIN="kfjjkjfdhgjkhfkjd";
	
	OtbUniqueId *expected_unique_id=otb_unique_id_create();
	OtbAsymCipher *expected_asym_cipher=g_object_new(OTB_TYPE_ASYM_CIPHER, NULL);
	g_assert(otb_asym_cipher_generate_random_keys(expected_asym_cipher, NEW_KEY_LENGTH));
	otb_setup_config_file_for_user_tests(expected_unique_id, EXPECTED_SYM_CIPHER_NAME, expected_asym_cipher, EXPECTED_BASE_ONION_DOMAIN);
	OtbBitkeeper *bitkeeper=otb_bitkeeper_load();
	OtbUser *user=NULL;
	g_object_get(bitkeeper, OTB_BITKEEPER_PROP_USER, &user, NULL);
	const OtbUniqueId *actual_unique_id=NULL;
	OtbAsymCipher *actual_asym_cipher=NULL;
	char *actual_onion_base_domain=NULL;
	g_object_get(user, OTB_USER_PROP_UNIQUE_ID, &actual_unique_id, OTB_USER_PROP_ASYM_CIPHER, &actual_asym_cipher, OTB_USER_PROP_ONION_BASE_DOMAIN, &actual_onion_base_domain, NULL);
	g_assert_cmpint(0, ==, otb_unique_id_compare(expected_unique_id, actual_unique_id));
	g_free(expected_unique_id);
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
	g_assert_cmpstr(EXPECTED_BASE_ONION_DOMAIN, ==, actual_onion_base_domain);
	g_free(actual_onion_base_domain);
	g_assert(user!=NULL);
	g_object_unref(user);
	g_object_unref(bitkeeper);
}

void test_otb_bitkeeper_load()
{
	
	
	otb_settings_initialize("otb-tests", "otb");
	otb_settings_set_config_directory_path(otb_get_test_dir_path());
	OtbBitkeeper *bitkeeper1=otb_bitkeeper_load();
//	char *friend1_import_string=otb_create_import_string(public_key, onion_base_domain, dummy_value);
//	OtbFriend *friend1=otb_bitkeeper_import_friend(bitkeeper1, friend1_import_string);
//	g_assert(friend1!=NULL);
//	g_object_unref(friend1);
//	g_free(friend1_import_string);
	g_object_unref(bitkeeper1);
}

void otb_add_bitkeeper_tests()
{
	otb_add_test_func("/bitkeeper/test_otb_bitkeeper_user", test_otb_bitkeeper_user);
	otb_add_test_func("/bitkeeper/test_otb_bitkeeper_friends", test_otb_bitkeeper_load);
}
