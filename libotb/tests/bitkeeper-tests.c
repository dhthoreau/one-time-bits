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
#include "../src/local-crypto.h"
#include "../src/settings.h"

static void otb_setup_configs_for_bitkeeper_tests(size_t new_key_size, const char *sym_cipher_name, const char *address, OtbUniqueId **unique_id_out, OtbAsymCipher **asym_cipher_out)
{
	otb_recreate_test_dir();
	otb_initialize_settings_for_tests();
	*unique_id_out=otb_unique_id_new();
	*asym_cipher_out=g_object_new(OTB_TYPE_ASYM_CIPHER, NULL);
	g_assert(otb_asym_cipher_generate_random_keys(*asym_cipher_out, new_key_size));
	otb_setup_config_file_for_user_tests(*unique_id_out, sym_cipher_name, *asym_cipher_out, address);
}

static void otb_setup_configs_for_bitkeeper_tests_without_output(size_t new_key_size, const char *sym_cipher_name, const char *address)
{
	OtbUniqueId *unique_id=NULL;
	OtbAsymCipher *asym_cipher=NULL;
	otb_setup_configs_for_bitkeeper_tests(new_key_size, sym_cipher_name, address, &unique_id, &asym_cipher);
	g_object_unref(asym_cipher);
	otb_unique_id_unref(unique_id);
}

static void test_otb_bitkeeper_user()
{
	const size_t NEW_KEY_SIZE=512;
	const char *EXPECTED_SYM_CIPHER_NAME="DES-CBC";
	const char *EXPECTED_ADDRESS="kfjjkjfdhgjkhfkjd.onion";
	
	OtbUniqueId *expected_unique_id=NULL;
	OtbAsymCipher *expected_asym_cipher=NULL;
	otb_setup_configs_for_bitkeeper_tests(NEW_KEY_SIZE, EXPECTED_SYM_CIPHER_NAME, EXPECTED_ADDRESS, &expected_unique_id, &expected_asym_cipher);
	OtbBitkeeper *bitkeeper=otb_bitkeeper_load();
	g_assert(bitkeeper!=NULL);
	OtbUser *user=NULL;
	g_object_get(bitkeeper, OTB_BITKEEPER_PROP_USER, &user, NULL);
	g_assert(user!=NULL);
	OtbUniqueId *actual_unique_id=NULL;
	OtbAsymCipher *actual_asym_cipher=NULL;
	char *actual_address=NULL;
	g_object_get(user, OTB_USER_PROP_UNIQUE_ID, &actual_unique_id, OTB_USER_PROP_ASYM_CIPHER, &actual_asym_cipher, OTB_USER_PROP_ADDRESS, &actual_address, NULL);
	g_assert_cmpint(0, ==, otb_unique_id_compare(expected_unique_id, actual_unique_id));
	char *expected_public_key=NULL;
	g_object_get(expected_asym_cipher, OTB_ASYM_CIPHER_PROP_PUBLIC_KEY, &expected_public_key, NULL);
	g_assert(expected_public_key!=NULL);
	char *actual_sym_cipher_name=NULL;
	char *actual_public_key=NULL;
	g_object_get(actual_asym_cipher, OTB_ASYM_CIPHER_PROP_SYM_CIPHER_NAME, &actual_sym_cipher_name, OTB_ASYM_CIPHER_PROP_PUBLIC_KEY, &actual_public_key, NULL);
	g_assert_cmpstr(EXPECTED_SYM_CIPHER_NAME, ==, actual_sym_cipher_name);
	g_assert_cmpstr(expected_public_key, ==, actual_public_key);
	g_assert_cmpstr(EXPECTED_ADDRESS, ==, actual_address);
	otb_local_crypto_lock_sym_cipher();
	g_free(actual_public_key);
	g_free(actual_sym_cipher_name);
	g_free(expected_public_key);
	g_free(actual_address);
	g_object_unref(actual_asym_cipher);
	otb_unique_id_unref(actual_unique_id);
	g_object_unref(user);
	g_object_unref(bitkeeper);
	g_object_unref(expected_asym_cipher);
	otb_unique_id_unref(expected_unique_id);
}

static void test_otb_bitkeeper_proxy_port()
{
	otb_setup_configs_for_bitkeeper_tests_without_output(512, "DES-CBC", "sjhfgjzshdjf.onion");
	OtbBitkeeper *original_bitkeeper=otb_bitkeeper_load();
	unsigned int proxy_port=0;
	g_object_get(original_bitkeeper, OTB_BITKEEPER_PROP_PROXY_PORT, &proxy_port, NULL);
	g_assert_cmpint(9050, ==, proxy_port);
	g_assert(otb_bitkeeper_set_proxy_port(original_bitkeeper, 12345));
	g_object_get(original_bitkeeper, OTB_BITKEEPER_PROP_PROXY_PORT, &proxy_port, NULL);
	g_assert_cmpint(12345, ==, proxy_port);
	OtbBitkeeper *second_bitkeeper=otb_bitkeeper_load();
	g_object_get(original_bitkeeper, OTB_BITKEEPER_PROP_PROXY_PORT, &proxy_port, NULL);
	g_assert_cmpint(12345, ==, proxy_port);
	otb_local_crypto_lock_sym_cipher();
	g_object_unref(second_bitkeeper);
	g_object_unref(original_bitkeeper);
}

static void test_otb_bitkeeper_pad_synchronization_interval()
{
	otb_setup_configs_for_bitkeeper_tests_without_output(512, "DES-CBC", "sjhfgjzshdjf.onion");
	OtbBitkeeper *original_bitkeeper=otb_bitkeeper_load();
	long long pad_synchronization_interval=0;
	g_object_get(original_bitkeeper, OTB_BITKEEPER_PROP_PAD_SYNCHRONIZATION_INTERVAL, &pad_synchronization_interval, NULL);
	g_assert_cmpint(10000000, ==, pad_synchronization_interval);
	g_assert(otb_bitkeeper_set_pad_synchronization_interval(original_bitkeeper, 12345000));
	g_object_get(original_bitkeeper, OTB_BITKEEPER_PROP_PAD_SYNCHRONIZATION_INTERVAL, &pad_synchronization_interval, NULL);
	g_assert_cmpint(12345000, ==, pad_synchronization_interval);
	OtbBitkeeper *second_bitkeeper=otb_bitkeeper_load();
	g_object_get(original_bitkeeper, OTB_BITKEEPER_PROP_PAD_SYNCHRONIZATION_INTERVAL, &pad_synchronization_interval, NULL);
	g_assert_cmpint(12345000, ==, pad_synchronization_interval);
	otb_local_crypto_lock_sym_cipher();
	g_object_unref(second_bitkeeper);
	g_object_unref(original_bitkeeper);
}

static void otb_assert_bitkeeper_has_friends(OtbBitkeeper *bitkeeper, const OtbUniqueId *expected_unique_id1, const OtbUniqueId *expected_unique_id2)
{
	GSList *unique_ids=otb_bitkeeper_get_unique_ids_of_friends(bitkeeper);
	size_t expected_size=(expected_unique_id1==NULL?0:1)+(expected_unique_id2==NULL?0:1);
	g_assert_cmpint(expected_size, ==, g_slist_length(unique_ids));
	if(expected_unique_id1!=NULL)
		g_assert(otb_unique_id_compare(expected_unique_id1, (OtbUniqueId*)g_slist_nth_data(unique_ids, 0))==0 || otb_unique_id_compare(expected_unique_id1, (OtbUniqueId*)g_slist_nth_data(unique_ids, 1))==0);
	if(expected_unique_id2!=NULL)
		g_assert(otb_unique_id_compare(expected_unique_id2, (OtbUniqueId*)g_slist_nth_data(unique_ids, 0))==0 || otb_unique_id_compare(expected_unique_id2, (OtbUniqueId*)g_slist_nth_data(unique_ids, 1))==0);
	g_slist_free_full(unique_ids, (GDestroyNotify)otb_unique_id_unref);
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
	const char *EXPECTED_TRANSPORT_CIPHER_NAME1="AES-256-CBC";
	const char *EXPECTED_TRANSPORT_CIPHER_NAME2="AES-512-CBC";
	const char *EXPECTED_ADDRESS1="SoyMilkRoad.onion";
	const char *EXPECTED_ADDRESS2="SoyMilkRoad2.onion";
	
	char *friend1_import_string=otb_create_import_string(expected_unique_id1, EXPECTED_PUBLIC_KEY1, EXPECTED_TRANSPORT_CIPHER_NAME1, EXPECTED_ADDRESS1, "");
	char *friend2_import_string=otb_create_import_string(expected_unique_id2, EXPECTED_PUBLIC_KEY2, EXPECTED_TRANSPORT_CIPHER_NAME2, EXPECTED_ADDRESS2, "");
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
	char *actual_transport_cipher_name1=NULL;
	char *actual_transport_cipher_name2=NULL;
	char *actual_address1=NULL;
	char *actual_address2=NULL;
	g_object_get(friend1, OTB_FRIEND_PROP_UNIQUE_ID, &actual_unique_id1, OTB_FRIEND_PROP_PUBLIC_KEY, &actual_public_key1, OTB_FRIEND_PROP_TRANSPORT_CIPHER_NAME, &actual_transport_cipher_name1, OTB_FRIEND_PROP_ADDRESS, &actual_address1, NULL);
	g_object_get(friend2, OTB_FRIEND_PROP_UNIQUE_ID, &actual_unique_id2, OTB_FRIEND_PROP_PUBLIC_KEY, &actual_public_key2, OTB_FRIEND_PROP_TRANSPORT_CIPHER_NAME, &actual_transport_cipher_name2, OTB_FRIEND_PROP_ADDRESS, &actual_address2, NULL);
	g_assert_cmpint(0, ==, otb_unique_id_compare(expected_unique_id1, actual_unique_id1));
	g_assert_cmpint(0, ==, otb_unique_id_compare(expected_unique_id2, actual_unique_id2));
	g_assert_cmpstr(EXPECTED_PUBLIC_KEY1, ==, actual_public_key1);
	g_assert_cmpstr(EXPECTED_PUBLIC_KEY2, ==, actual_public_key2);
	g_assert_cmpstr(EXPECTED_TRANSPORT_CIPHER_NAME1, ==, actual_transport_cipher_name1);
	g_assert_cmpstr(EXPECTED_TRANSPORT_CIPHER_NAME2, ==, actual_transport_cipher_name2);
	g_assert_cmpstr(EXPECTED_ADDRESS1, ==, actual_address1);
	g_assert_cmpstr(EXPECTED_ADDRESS2, ==, actual_address2);
	otb_assert_bitkeeper_has_friends_in_memory_and_persisted(bitkeeper, expected_unique_id1, expected_unique_id2);
	otb_unique_id_unref(actual_unique_id1);
	otb_unique_id_unref(actual_unique_id2);
	g_free(actual_public_key1);
	g_free(actual_public_key2);
	g_free(actual_transport_cipher_name1);
	g_free(actual_transport_cipher_name2);
	g_free(actual_address1);
	g_free(actual_address2);
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

OtbBitkeeper *otb_create_bitkeeper_for_test()
{
	otb_recreate_test_dir();
	otb_test_setup_local_crypto();
	otb_initialize_settings_for_tests();
	OtbBitkeeper *bitkeeper=otb_bitkeeper_load();
	g_assert(bitkeeper!=NULL);
	return bitkeeper;
}

static void test_otb_bitkeeper_import_delete_friends()
{
	OtbBitkeeper *bitkeeper=otb_create_bitkeeper_for_test();
	OtbUniqueId *expected_unique_id1=otb_unique_id_new();
	OtbUniqueId *expected_unique_id2=otb_unique_id_new();
	otb_bitkeeper_import_test(bitkeeper, expected_unique_id1, expected_unique_id2);
	otb_bitkeeper_delete_test(bitkeeper, expected_unique_id1, expected_unique_id2);
	otb_local_crypto_lock_sym_cipher();
	otb_unique_id_unref(expected_unique_id1);
	otb_unique_id_unref(expected_unique_id2);
	g_object_unref(bitkeeper);
}

void otb_add_bitkeeper_tests()
{
	otb_add_test_func("/bitkeeper/test_otb_bitkeeper_user", test_otb_bitkeeper_user);
	otb_add_test_func("/bitkeeper/test_otb_bitkeeper_proxy_port", test_otb_bitkeeper_proxy_port);
	otb_add_test_func("/bitkeeper/test_otb_bitkeeper_pad_synchronization_interval", test_otb_bitkeeper_pad_synchronization_interval);
	otb_add_test_func("/bitkeeper/test_otb_bitkeeper_import_delete_friends", test_otb_bitkeeper_import_delete_friends);
}
