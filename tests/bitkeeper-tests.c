/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <glib/gstdio.h>

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
	
	otb_recreate_test_dir();
	otb_settings_set_data_directory_path(otb_get_test_dir_path());
	OtbUniqueId *expected_unique_id=otb_unique_id_create();
	OtbAsymCipher *expected_asym_cipher=g_object_new(OTB_TYPE_ASYM_CIPHER, NULL);
	g_assert(otb_asym_cipher_generate_random_keys(expected_asym_cipher, NEW_KEY_LENGTH));
	otb_setup_config_file_for_user_tests(expected_unique_id, EXPECTED_SYM_CIPHER_NAME, expected_asym_cipher, EXPECTED_BASE_ONION_DOMAIN);
	OtbBitkeeper *bitkeeper=otb_bitkeeper_load();
	g_assert(bitkeeper!=NULL);
	OtbUser *user=NULL;
	g_object_get(bitkeeper, OTB_BITKEEPER_PROP_USER, &user, NULL);
	g_assert(user!=NULL);
	OtbUniqueId *actual_unique_id=NULL;
	OtbAsymCipher *actual_asym_cipher=NULL;
	char *actual_onion_base_domain=NULL;
	g_object_get(user, OTB_USER_PROP_UNIQUE_ID, &actual_unique_id, OTB_USER_PROP_ASYM_CIPHER, &actual_asym_cipher, OTB_USER_PROP_ONION_BASE_DOMAIN, &actual_onion_base_domain, NULL);
	g_assert_cmpint(0, ==, otb_unique_id_compare(expected_unique_id, actual_unique_id));
	char *expected_public_key=NULL;
	g_object_get(expected_asym_cipher, OTB_ASYM_CIPHER_PROP_PUBLIC_KEY, &expected_public_key, NULL);
	g_assert(expected_public_key!=NULL);
	char *actual_sym_cipher_name=NULL;
	char *actual_public_key=NULL;
	g_object_get(actual_asym_cipher, OTB_ASYM_CIPHER_PROP_SYM_CIPHER, &actual_sym_cipher_name, OTB_ASYM_CIPHER_PROP_PUBLIC_KEY, &actual_public_key, NULL);
	g_assert_cmpstr(EXPECTED_SYM_CIPHER_NAME, ==, actual_sym_cipher_name);
	g_assert_cmpstr(expected_public_key, ==, actual_public_key);
	g_assert_cmpstr(EXPECTED_BASE_ONION_DOMAIN, ==, actual_onion_base_domain);
	g_free(actual_public_key);
	g_free(actual_sym_cipher_name);
	g_free(expected_public_key);
	g_free(actual_onion_base_domain);
	g_object_unref(actual_asym_cipher);
	g_free(actual_unique_id);
	g_object_unref(user);
	g_object_unref(bitkeeper);
	g_object_unref(expected_asym_cipher);
	g_free(expected_unique_id);
}

static void otb_assert_bitkeeper_has_friends(OtbBitkeeper *bitkeeper, const OtbUniqueId *expected_unique_id1, const OtbUniqueId *expected_unique_id2)
{
	GSList *unique_ids=otb_bitkeeper_get_ids_of_friends(bitkeeper);
	size_t expected_size=(expected_unique_id1==NULL?0:1)+(expected_unique_id2==NULL?0:1);
	g_assert_cmpint(expected_size, ==, g_slist_length(unique_ids));
	if(expected_unique_id1!=NULL)
		g_assert(otb_unique_id_compare(expected_unique_id1, (OtbUniqueId*)g_slist_nth_data(unique_ids, 0))==0 || otb_unique_id_compare(expected_unique_id1, (OtbUniqueId*)g_slist_nth_data(unique_ids, 1))==0);
	if(expected_unique_id2!=NULL)
		g_assert(otb_unique_id_compare(expected_unique_id2, (OtbUniqueId*)g_slist_nth_data(unique_ids, 0))==0 || otb_unique_id_compare(expected_unique_id2, (OtbUniqueId*)g_slist_nth_data(unique_ids, 1))==0);
	g_slist_free_full(unique_ids, g_free);
}

static void otb_assert_bitkeeper_has_friends_in_memory_and_persisted(OtbBitkeeper *bitkeeper, const OtbUniqueId *expected_unique_id1, const OtbUniqueId *expected_unique_id2)
{
	otb_assert_bitkeeper_has_friends(bitkeeper, expected_unique_id1, expected_unique_id2);
	OtbBitkeeper *bitkeeper_loaded=otb_bitkeeper_load();
	g_assert(bitkeeper_loaded!=NULL);
	otb_assert_bitkeeper_has_friends(bitkeeper_loaded, expected_unique_id1, expected_unique_id2);
	g_object_unref(bitkeeper_loaded);
}

static void otb_bitkeeper_import_test(OtbBitkeeper *bitkeeper, const OtbUniqueId *expected_unique_id1, const OtbUniqueId *expected_unique_id2)
{
	const char *EXPECTED_PUBLIC_KEY1="-----BEGIN PUBLIC KEY-----\nMCwwDQYJKoZIhvcNAQEBBQADGwAwGAIRAOI3kOtj0yQLT1JyfbBXLbUCAwEAAQ==\n-----END PUBLIC KEY-----";
	const char *EXPECTED_PUBLIC_KEY2="-----BEGIN PUBLIC KEY-----\noCwwDQYJKoZIhvcNAQEBBQADGwAwGAIRAOI3kOtj0yQLT1JyfbBXLbUCAwEAAQ==\n-----END PUBLIC KEY-----";
	const char *EXPECTED_ONION_BASE_DOMAIN1="SoyMilkRoad";
	const char *EXPECTED_ONION_BASE_DOMAIN2="SoyMilkRoad2";
	
	char *friend1_import_string=otb_create_import_string(expected_unique_id1, EXPECTED_PUBLIC_KEY1, EXPECTED_ONION_BASE_DOMAIN1, "");
	char *friend2_import_string=otb_create_import_string(expected_unique_id2, EXPECTED_PUBLIC_KEY2, EXPECTED_ONION_BASE_DOMAIN2, "");
	g_assert(otb_bitkeeper_import_friend(bitkeeper, friend1_import_string));
	g_assert(otb_bitkeeper_import_friend(bitkeeper, friend2_import_string));
	OtbFriend *friend1=otb_bitkeeper_get_friend(bitkeeper, expected_unique_id1);
	OtbFriend *friend2=otb_bitkeeper_get_friend(bitkeeper, expected_unique_id2);
	g_assert(friend1!=NULL);
	g_assert(friend2!=NULL);
	OtbUniqueId *actual_unique_id1=NULL;
	OtbUniqueId *actual_unique_id2=NULL;
	char *actual_public_key1=NULL;
	char *actual_public_key2=NULL;
	char *actual_onion_base_domain1=NULL;
	char *actual_onion_base_domain2=NULL;
	g_object_get(friend1, OTB_FRIEND_PROP_UNIQUE_ID, &actual_unique_id1, OTB_FRIEND_PROP_PUBLIC_KEY, &actual_public_key1, OTB_FRIEND_PROP_ONION_BASE_DOMAIN, &actual_onion_base_domain1, NULL);
	g_object_get(friend2, OTB_FRIEND_PROP_UNIQUE_ID, &actual_unique_id2, OTB_FRIEND_PROP_PUBLIC_KEY, &actual_public_key2, OTB_FRIEND_PROP_ONION_BASE_DOMAIN, &actual_onion_base_domain2, NULL);
	g_assert_cmpint(0, ==, otb_unique_id_compare(expected_unique_id1, actual_unique_id1));
	g_assert_cmpint(0, ==, otb_unique_id_compare(expected_unique_id2, actual_unique_id2));
	g_assert_cmpstr(EXPECTED_PUBLIC_KEY1, ==, actual_public_key1);
	g_assert_cmpstr(EXPECTED_PUBLIC_KEY2, ==, actual_public_key2);
	g_assert_cmpstr(EXPECTED_ONION_BASE_DOMAIN1, ==, actual_onion_base_domain1);
	g_assert_cmpstr(EXPECTED_ONION_BASE_DOMAIN2, ==, actual_onion_base_domain2);
	otb_assert_bitkeeper_has_friends_in_memory_and_persisted(bitkeeper, expected_unique_id1, expected_unique_id2);
	g_free(actual_unique_id1);
	g_free(actual_unique_id2);
	g_free(actual_public_key1);
	g_free(actual_public_key2);
	g_free(actual_onion_base_domain1);
	g_free(actual_onion_base_domain2);
	g_object_unref(friend1);
	g_object_unref(friend2);
	g_free(friend1_import_string);
	g_free(friend2_import_string);
}

static void otb_bitkeeper_delete_test(OtbBitkeeper *bitkeeper, const OtbUniqueId *expected_unique_id1, const OtbUniqueId *expected_unique_id2)
{
	g_assert(otb_bitkeeper_remove_friend(bitkeeper, expected_unique_id2));
	otb_assert_bitkeeper_has_friends_in_memory_and_persisted(bitkeeper, expected_unique_id1, NULL);
	g_assert(otb_bitkeeper_remove_friend(bitkeeper, expected_unique_id1));
	otb_assert_bitkeeper_has_friends_in_memory_and_persisted(bitkeeper, NULL, NULL);
}

static void test_otb_bitkeeper_import_delete_friends()
{
	otb_recreate_test_dir();
	otb_test_setup_local_crypto();
	otb_settings_initialize("otb-tests", "otb");
	otb_settings_set_config_directory_path(otb_get_test_dir_path());
	otb_settings_set_data_directory_path(otb_get_test_dir_path());
	OtbBitkeeper *bitkeeper=otb_bitkeeper_load();
	g_assert(bitkeeper!=NULL);
	OtbUniqueId *expected_unique_id1=otb_unique_id_create();
	OtbUniqueId *expected_unique_id2=otb_unique_id_create();
	otb_bitkeeper_import_test(bitkeeper, expected_unique_id1, expected_unique_id2);
	otb_bitkeeper_delete_test(bitkeeper, expected_unique_id1, expected_unique_id2);
	g_free(expected_unique_id1);
	g_free(expected_unique_id2);
	g_object_unref(bitkeeper);
}

void otb_add_bitkeeper_tests()
{
	otb_add_test_func("/bitkeeper/test_otb_bitkeeper_user", test_otb_bitkeeper_user);
	otb_add_test_func("/bitkeeper/test_otb_bitkeeper_import_delete_friends", test_otb_bitkeeper_import_delete_friends);
}