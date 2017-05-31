/**
 * Copyright © 2017 the OTB team
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
#include "../src/io.h"
#include "../src/local-crypto.h"
#include "../src/random.h"
#include "../src/settings.h"

static void otb_assert_asym_cipher(OtbAsymCipher *actual_asym_cipher, const char *expected_sym_cipher_name, int expected_key_size)
{
	char *actual_sym_cipher_name=NULL;
	int actual_key_size;
	g_object_get(actual_asym_cipher, OTB_ASYM_CIPHER_PROP_SYM_CIPHER_NAME, &actual_sym_cipher_name, OTB_ASYM_CIPHER_PROP_KEY_SIZE, &actual_key_size, NULL);
	g_assert_cmpstr(expected_sym_cipher_name, ==, actual_sym_cipher_name);
	g_assert_cmpint(expected_key_size, ==, actual_key_size);
	g_free(actual_sym_cipher_name);
}

static void otb_assert_user(OtbUser *actual_user, const char *expected_address, unsigned int expected_port, const char *expected_sym_cipher_name, int expected_key_size)
{
	OtbAsymCipher *actual_asym_cipher=NULL;
	char *actual_address=NULL;
	unsigned int actual_port;
	g_object_get(actual_user, OTB_USER_PROP_ASYM_CIPHER, &actual_asym_cipher, OTB_USER_PROP_ADDRESS, &actual_address, OTB_USER_PROP_PORT, &actual_port, NULL);
	otb_assert_asym_cipher(actual_asym_cipher, expected_sym_cipher_name, expected_key_size);
	g_assert_cmpstr(expected_address, ==, actual_address);
	g_assert_cmpint(expected_port, ==, actual_port);
	g_free(actual_address);
	g_object_unref(actual_asym_cipher);
}

static void otb_assert_bitkeeper(OtbBitkeeper *actual_bitkeeper, unsigned int expected_proxy_port, long long expected_pad_synchronization_interval, const char *expected_address, unsigned int expected_port, const char *expected_sym_cipher_name, int expected_key_size)
{
	unsigned int actual_proxy_port=0;
	long long actual_pad_synchronization_interval=0;
	OtbUser *actual_user=NULL;
	g_object_get(actual_bitkeeper, OTB_BITKEEPER_PROP_USER, &actual_user, OTB_BITKEEPER_PROP_PROXY_PORT, &actual_proxy_port, OTB_BITKEEPER_PROP_PAD_SYNCHRONIZATION_INTERVAL, &actual_pad_synchronization_interval, NULL);
	otb_assert_user(actual_user, expected_address, expected_port, expected_sym_cipher_name, expected_key_size);
	g_assert_cmpint(expected_proxy_port, ==, actual_proxy_port);
	g_assert_cmpint(expected_pad_synchronization_interval, ==, actual_pad_synchronization_interval);
	g_object_unref(actual_user);
}

static void test_otb_bitkeeper_create_with_defaults(void)
{
	const char *EXPECTED_ADDRESS="BungaBungaBerlusconiRuby.onion";
	
	otb_test_setup_local_crypto();
	otb_initialize_settings_for_tests();
	OtbAsymCipher *asym_cipher=g_object_new(OTB_TYPE_ASYM_CIPHER, OTB_ASYM_CIPHER_PROP_KEY_SIZE, SHORT_KEY_SIZE_THAT_DOES_NOT_MAKE_UNIT_TESTS_RUN_SLOWLY, NULL);
	g_assert(asym_cipher!=NULL);
	g_assert(otb_asym_cipher_generate_random_keys(asym_cipher));
	OtbUser *user=g_object_new(OTB_TYPE_USER, OTB_USER_PROP_ASYM_CIPHER, asym_cipher, OTB_USER_PROP_ADDRESS, EXPECTED_ADDRESS, NULL);
	g_assert(user!=NULL);
	OtbBitkeeper *bitkeeper=g_object_new(OTB_TYPE_BITKEEPER, OTB_BITKEEPER_PROP_USER, user, NULL);
	otb_assert_bitkeeper(bitkeeper, OTB_BITKEEPER_DEFAULT_PROXY_PORT, OTB_BITKEEPER_DEFAULT_PAD_SYNCHRONIZATION_INTERVAL, EXPECTED_ADDRESS, OTB_USER_DEFAULT_PORT, OTB_ASYM_CIPHER_DEFAULT_CIPHER, SHORT_KEY_SIZE_THAT_DOES_NOT_MAKE_UNIT_TESTS_RUN_SLOWLY);
	g_object_unref(bitkeeper);
	g_object_unref(user);
	g_object_unref(asym_cipher);
}

static void test_otb_bitkeeper_create_set_unload_load_save(void)
{
	const char *EXPECTED_ADDRESS="BungaBungaBerlusconiMara.onion";
	const unsigned int EXPECTED_PORT=6666;
	const unsigned int EXPECTED_PROXY_PORT1=55555;
	const long long EXPECTED_PAD_SYNCHRONIZATION_INTERVAL1=15000000;
	const unsigned int EXPECTED_PROXY_PORT2=4444;
	const long long EXPECTED_PAD_SYNCHRONIZATION_INTERVAL2=30000000;
	
	otb_test_setup_local_crypto();
	otb_initialize_settings_for_tests();
	OtbAsymCipher *asym_cipher=g_object_new(OTB_TYPE_ASYM_CIPHER, OTB_ASYM_CIPHER_PROP_KEY_SIZE, SHORT_KEY_SIZE_THAT_DOES_NOT_MAKE_UNIT_TESTS_RUN_SLOWLY, NULL);
	g_assert(asym_cipher!=NULL);
	g_assert(otb_asym_cipher_generate_random_keys(asym_cipher));
	OtbUser *user=g_object_new(OTB_TYPE_USER, OTB_USER_PROP_ASYM_CIPHER, asym_cipher, OTB_USER_PROP_ADDRESS, EXPECTED_ADDRESS, OTB_USER_PROP_PORT, EXPECTED_PORT, NULL);
	g_assert(user!=NULL);
	OtbBitkeeper *bitkeeper=g_object_new(OTB_TYPE_BITKEEPER, OTB_BITKEEPER_PROP_USER, user, OTB_BITKEEPER_PROP_PROXY_PORT, EXPECTED_PROXY_PORT1, OTB_BITKEEPER_PROP_PAD_SYNCHRONIZATION_INTERVAL, EXPECTED_PAD_SYNCHRONIZATION_INTERVAL1, NULL);
	otb_bitkeeper_set(bitkeeper);
	otb_assert_bitkeeper(bitkeeper, EXPECTED_PROXY_PORT1, EXPECTED_PAD_SYNCHRONIZATION_INTERVAL1, EXPECTED_ADDRESS, EXPECTED_PORT, OTB_ASYM_CIPHER_DEFAULT_CIPHER, SHORT_KEY_SIZE_THAT_DOES_NOT_MAKE_UNIT_TESTS_RUN_SLOWLY);
	OtbBitkeeper *bitkeeper_retrieved=otb_bitkeeper_get_with_ref();
	g_assert(bitkeeper==bitkeeper_retrieved);
	g_object_unref(bitkeeper_retrieved);
	g_object_unref(bitkeeper);
	otb_bitkeeper_unload();
	bitkeeper=otb_bitkeeper_get_with_ref();
	g_assert(bitkeeper==NULL);
	g_assert(otb_bitkeeper_load());
	bitkeeper=otb_bitkeeper_get_with_ref();
	otb_assert_bitkeeper(bitkeeper, EXPECTED_PROXY_PORT1, EXPECTED_PAD_SYNCHRONIZATION_INTERVAL1, EXPECTED_ADDRESS, EXPECTED_PORT, OTB_ASYM_CIPHER_DEFAULT_CIPHER, SHORT_KEY_SIZE_THAT_DOES_NOT_MAKE_UNIT_TESTS_RUN_SLOWLY);
	g_object_set(bitkeeper, OTB_BITKEEPER_PROP_PROXY_PORT, EXPECTED_PROXY_PORT2, OTB_BITKEEPER_PROP_PAD_SYNCHRONIZATION_INTERVAL, EXPECTED_PAD_SYNCHRONIZATION_INTERVAL2, NULL);
	otb_assert_bitkeeper(bitkeeper, EXPECTED_PROXY_PORT2, EXPECTED_PAD_SYNCHRONIZATION_INTERVAL2, EXPECTED_ADDRESS, EXPECTED_PORT, OTB_ASYM_CIPHER_DEFAULT_CIPHER, SHORT_KEY_SIZE_THAT_DOES_NOT_MAKE_UNIT_TESTS_RUN_SLOWLY);
	g_object_unref(bitkeeper);
	bitkeeper=NULL;
	g_assert(otb_bitkeeper_save());
	otb_bitkeeper_unload();
	bitkeeper=otb_bitkeeper_get_with_ref();
	g_assert(bitkeeper==NULL);
	g_assert(otb_bitkeeper_load());
	bitkeeper=otb_bitkeeper_get_with_ref();
	otb_assert_bitkeeper(bitkeeper, EXPECTED_PROXY_PORT2, EXPECTED_PAD_SYNCHRONIZATION_INTERVAL2, EXPECTED_ADDRESS, EXPECTED_PORT, OTB_ASYM_CIPHER_DEFAULT_CIPHER, SHORT_KEY_SIZE_THAT_DOES_NOT_MAKE_UNIT_TESTS_RUN_SLOWLY);
	g_object_unref(bitkeeper);
	g_object_unref(user);
	g_object_unref(asym_cipher);
}

static void otb_write_proxy_port(FILE *file, unsigned int proxy_port)
{
	g_assert(otb_write("proxy-port=", 1, 11, file)==11);
	char proxy_port_string[6];
	g_assert_cmpint(0, <, sprintf(proxy_port_string, "%hu", proxy_port));
	g_assert(otb_write(proxy_port_string, 1, strlen(proxy_port_string), file)==strlen(proxy_port_string));
	g_assert(otb_write("\n", 1, 1, file)==1);
}

static void otb_write_pad_synchronization_interval(FILE *file, long long pad_synchonization_interval)
{
	g_assert(otb_write("pad-synchronization-interval=", 1, 29, file)==29);
	char pad_synchonization_interval_string[21];
	g_assert_cmpint(sprintf(pad_synchonization_interval_string, "%lli", pad_synchonization_interval), >, 0);
	g_assert(otb_write(pad_synchonization_interval_string, 1, strlen(pad_synchonization_interval_string), file)==strlen(pad_synchonization_interval_string));
	g_assert(otb_write("\n", 1, 1, file)==1);
}

static void otb_setup_config_file_for_bitkeeper_tests(void)
{
	char *config_file_path=g_build_filename(otb_get_test_dir_path(), "otb.conf", NULL);
	FILE *file=g_fopen(config_file_path, "a");
	g_assert(file!=NULL);
	g_free(config_file_path);
	g_assert(file!=NULL);
	g_assert(otb_write("\n[bitkeeper]\n", 1, 13, file)==13);
	otb_write_proxy_port(file, OTB_BITKEEPER_DEFAULT_PROXY_PORT);
	otb_write_pad_synchronization_interval(file, OTB_BITKEEPER_DEFAULT_PAD_SYNCHRONIZATION_INTERVAL);
	g_assert_cmpint(fclose(file), ==, 0);
	otb_initialize_settings_for_tests();
}

static void otb_setup_configs_for_bitkeeper_tests(int new_key_size, const char *sym_cipher_name, const char *address, unsigned int port, OtbUniqueId **unique_id_out, OtbAsymCipher **asym_cipher_out)
{
	otb_initialize_settings_for_tests();
	*unique_id_out=otb_unique_id_new();
	*asym_cipher_out=g_object_new(OTB_TYPE_ASYM_CIPHER, OTB_ASYM_CIPHER_PROP_KEY_SIZE, new_key_size, NULL);
	g_assert(otb_asym_cipher_generate_random_keys(*asym_cipher_out));
	otb_setup_config_file_for_user_tests(*unique_id_out, sym_cipher_name, *asym_cipher_out, address, port);
	otb_setup_config_file_for_bitkeeper_tests();
}

static void otb_setup_configs_for_bitkeeper_tests_without_output(int new_key_size, const char *sym_cipher_name, const char *address)
{
	OtbUniqueId *unique_id=NULL;
	OtbAsymCipher *asym_cipher=NULL;
	otb_setup_configs_for_bitkeeper_tests(new_key_size, sym_cipher_name, address, 9898, &unique_id, &asym_cipher);
	g_object_unref(asym_cipher);
	otb_unique_id_unref(unique_id);
}

static void test_otb_bitkeeper_user(void)
{
	const char *EXPECTED_SYM_CIPHER_NAME="DES-CBC";
	const char *EXPECTED_ADDRESS="kfjjkjfdhgjkhfkjd.onion";
	const unsigned int EXPECTED_PORT=13579;
	
	OtbUniqueId *expected_unique_id=NULL;
	OtbAsymCipher *expected_asym_cipher=NULL;
	g_assert(!otb_bitkeeper_exists());
	otb_setup_configs_for_bitkeeper_tests(SHORT_KEY_SIZE_THAT_DOES_NOT_MAKE_UNIT_TESTS_RUN_SLOWLY, EXPECTED_SYM_CIPHER_NAME, EXPECTED_ADDRESS, EXPECTED_PORT, &expected_unique_id, &expected_asym_cipher);
	g_assert(otb_bitkeeper_exists());
	g_assert(otb_bitkeeper_load());
	OtbBitkeeper *bitkeeper=otb_bitkeeper_get_with_ref();
	g_assert(bitkeeper!=NULL);
	OtbUser *user=NULL;
	g_object_get(bitkeeper, OTB_BITKEEPER_PROP_USER, &user, NULL);
	g_assert(user!=NULL);
	OtbUniqueId *actual_unique_id=NULL;
	OtbAsymCipher *actual_asym_cipher=NULL;
	char *actual_address=NULL;
	unsigned int actual_port=0;
	g_object_get(user, OTB_USER_PROP_UNIQUE_ID, &actual_unique_id, OTB_USER_PROP_ASYM_CIPHER, &actual_asym_cipher, OTB_USER_PROP_ADDRESS, &actual_address, OTB_USER_PROP_PORT, &actual_port, NULL);
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
	g_assert_cmpint(EXPECTED_PORT, ==, actual_port);
	otb_local_crypto_lock();
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

static void test_otb_bitkeeper_proxy_port(void)
{
	const unsigned int ORIGINAL_PROXY_PORT=55555;
	const unsigned int NEW_PROXY_PORT=12345;
	
	g_assert(!otb_bitkeeper_exists());
	otb_setup_configs_for_bitkeeper_tests_without_output(SHORT_KEY_SIZE_THAT_DOES_NOT_MAKE_UNIT_TESTS_RUN_SLOWLY, "DES-CBC", "sjhfgjzshdjf.onion");
	g_assert(otb_bitkeeper_exists());
	OtbUser *user=otb_user_load();
	g_assert(user!=NULL);
	g_object_set(user, OTB_USER_PROP_ADDRESS, "BungaBunga.onion", NULL);
	g_assert(otb_user_save(user));
	OtbBitkeeper *original_bitkeeper=g_object_new(OTB_TYPE_BITKEEPER, OTB_BITKEEPER_PROP_USER, user, OTB_BITKEEPER_PROP_PROXY_PORT, ORIGINAL_PROXY_PORT, NULL);
	g_assert(original_bitkeeper!=NULL);
	g_assert(otb_bitkeeper_set(original_bitkeeper));
	unsigned int proxy_port=0;
	g_object_get(original_bitkeeper, OTB_BITKEEPER_PROP_PROXY_PORT, &proxy_port, NULL);
	g_assert_cmpint(ORIGINAL_PROXY_PORT, ==, proxy_port);
	g_object_set(original_bitkeeper, OTB_BITKEEPER_PROP_PROXY_PORT, NEW_PROXY_PORT, NULL);
	g_assert(otb_bitkeeper_save());
	g_object_get(original_bitkeeper, OTB_BITKEEPER_PROP_PROXY_PORT, &proxy_port, NULL);
	g_assert_cmpint(NEW_PROXY_PORT, ==, proxy_port);
	g_assert(otb_bitkeeper_load());
	OtbBitkeeper *second_bitkeeper=otb_bitkeeper_get_with_ref();
	g_assert(second_bitkeeper!=NULL);
	g_object_get(original_bitkeeper, OTB_BITKEEPER_PROP_PROXY_PORT, &proxy_port, NULL);
	g_assert_cmpint(NEW_PROXY_PORT, ==, proxy_port);
	otb_bitkeeper_unload();
	otb_local_crypto_lock();
	g_object_unref(second_bitkeeper);
	g_object_unref(original_bitkeeper);
	g_object_unref(user);
}

static void test_otb_bitkeeper_pad_synchronization_interval(void)
{
	const long long ORIGINAL_PAD_SYNCHRONIZATION_INTERVAL=15000000;
	const long long NEW_PAD_SYNCHRONIZATION_INTERVAL=12345000;
	
	g_assert(!otb_bitkeeper_exists());
	otb_setup_configs_for_bitkeeper_tests_without_output(SHORT_KEY_SIZE_THAT_DOES_NOT_MAKE_UNIT_TESTS_RUN_SLOWLY, "DES-CBC", "sjhfgjzshdjf.onion");
	g_assert(otb_bitkeeper_exists());
	OtbUser *user=otb_user_load();
	g_assert(user!=NULL);
	g_object_set(user, OTB_USER_PROP_ADDRESS, "BungaBunga.onion", NULL);
	g_assert(otb_user_save(user));
	OtbBitkeeper *original_bitkeeper=g_object_new(OTB_TYPE_BITKEEPER, OTB_BITKEEPER_PROP_USER, user, OTB_BITKEEPER_PROP_PAD_SYNCHRONIZATION_INTERVAL, ORIGINAL_PAD_SYNCHRONIZATION_INTERVAL, NULL);
	g_assert(original_bitkeeper!=NULL);
	g_assert(otb_bitkeeper_set(original_bitkeeper));
	long long pad_synchronization_interval=0;
	g_object_get(original_bitkeeper, OTB_BITKEEPER_PROP_PAD_SYNCHRONIZATION_INTERVAL, &pad_synchronization_interval, NULL);
	g_assert_cmpint(ORIGINAL_PAD_SYNCHRONIZATION_INTERVAL, ==, pad_synchronization_interval);
	g_object_set(original_bitkeeper, OTB_BITKEEPER_PROP_PAD_SYNCHRONIZATION_INTERVAL, NEW_PAD_SYNCHRONIZATION_INTERVAL, NULL);
	g_assert(otb_bitkeeper_save());
	g_object_get(original_bitkeeper, OTB_BITKEEPER_PROP_PAD_SYNCHRONIZATION_INTERVAL, &pad_synchronization_interval, NULL);
	g_assert_cmpint(NEW_PAD_SYNCHRONIZATION_INTERVAL, ==, pad_synchronization_interval);
	g_assert(otb_bitkeeper_load());
	OtbBitkeeper *second_bitkeeper=otb_bitkeeper_get_with_ref();
	g_assert(second_bitkeeper!=NULL);
	g_object_get(original_bitkeeper, OTB_BITKEEPER_PROP_PAD_SYNCHRONIZATION_INTERVAL, &pad_synchronization_interval, NULL);
	g_assert_cmpint(NEW_PAD_SYNCHRONIZATION_INTERVAL, ==, pad_synchronization_interval);
	otb_bitkeeper_unload();
	otb_local_crypto_lock();
	g_object_unref(second_bitkeeper);
	g_object_unref(original_bitkeeper);
	g_object_unref(user);
}

static void otb_assert_bitkeeper_has_friends(const OtbUniqueId *expected_unique_id1, const OtbUniqueId *expected_unique_id2)
{
	GSList *unique_ids=otb_bitkeeper_get_unique_ids_of_friends();
	size_t expected_size=(expected_unique_id1==NULL?0:1)+(expected_unique_id2==NULL?0:1);
	g_assert_cmpint(expected_size, ==, g_slist_length(unique_ids));
	if(expected_unique_id1!=NULL)
		g_assert(otb_unique_id_compare(expected_unique_id1, (OtbUniqueId*)g_slist_nth_data(unique_ids, 0))==0 || otb_unique_id_compare(expected_unique_id1, (OtbUniqueId*)g_slist_nth_data(unique_ids, 1))==0);
	if(expected_unique_id2!=NULL)
		g_assert(otb_unique_id_compare(expected_unique_id2, (OtbUniqueId*)g_slist_nth_data(unique_ids, 0))==0 || otb_unique_id_compare(expected_unique_id2, (OtbUniqueId*)g_slist_nth_data(unique_ids, 1))==0);
	g_slist_free_full(unique_ids, (GDestroyNotify)otb_unique_id_unref);
}

static void otb_assert_bitkeeper_has_friends_in_memory_and_persisted(const OtbUniqueId *expected_unique_id1, const OtbUniqueId *expected_unique_id2)
{
	otb_assert_bitkeeper_has_friends(expected_unique_id1, expected_unique_id2);
	g_assert(otb_bitkeeper_load());
	otb_assert_bitkeeper_has_friends(expected_unique_id1, expected_unique_id2);
}

static void otb_bitkeeper_import_test(const OtbUniqueId *expected_unique_id1, const OtbUniqueId *expected_unique_id2)
{
	const char *EXPECTED_PUBLIC_KEY1="-----BEGIN PUBLIC KEY-----\nMCwwDQYJKoZIhvcNAQEBBQADGwAwGAIRAOI3kOtj0yQLT1JyfbBXLbUCAwEAAQ==\n-----END PUBLIC KEY-----";
	const char *EXPECTED_PUBLIC_KEY2="-----BEGIN PUBLIC KEY-----\noCwwDQYJKoZIhvcNAQEBBQADGwAwGAIRAOI3kOtj0yQLT1JyfbBXLbUCAwEAAQ==\n-----END PUBLIC KEY-----";
	const char *EXPECTED_TRANSPORT_CIPHER_NAME1="AES-256-CBC";
	const char *EXPECTED_TRANSPORT_CIPHER_NAME2="AES-512-CBC";
	const char *EXPECTED_ADDRESS1="SoyMilkRoad.onion";
	const char *EXPECTED_ADDRESS2="SoyMilkRoad2.onion";
	const unsigned int EXPECTED_PORT1=12345;
	const unsigned int EXPECTED_PORT2=54321;
	
	char *friend1_import_string=otb_create_import_string(expected_unique_id1, EXPECTED_PUBLIC_KEY1, EXPECTED_TRANSPORT_CIPHER_NAME1, EXPECTED_ADDRESS1, EXPECTED_PORT1, "");
	char *friend2_import_string=otb_create_import_string(expected_unique_id2, EXPECTED_PUBLIC_KEY2, EXPECTED_TRANSPORT_CIPHER_NAME2, EXPECTED_ADDRESS2, EXPECTED_PORT2, "");
	g_assert(otb_bitkeeper_import_friend(friend1_import_string));
	g_assert(otb_bitkeeper_import_friend(friend2_import_string));
	OtbFriend *friend1=otb_bitkeeper_get_friend(expected_unique_id1);
	OtbFriend *friend2=otb_bitkeeper_get_friend(expected_unique_id2);
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
	unsigned int actual_port1=0;
	unsigned int actual_port2=0;
	g_object_get(friend1, OTB_FRIEND_PROP_UNIQUE_ID, &actual_unique_id1, OTB_FRIEND_PROP_PUBLIC_KEY, &actual_public_key1, OTB_FRIEND_PROP_TRANSPORT_CIPHER_NAME, &actual_transport_cipher_name1, OTB_FRIEND_PROP_ADDRESS, &actual_address1, OTB_FRIEND_PROP_PORT, &actual_port1, NULL);
	g_object_get(friend2, OTB_FRIEND_PROP_UNIQUE_ID, &actual_unique_id2, OTB_FRIEND_PROP_PUBLIC_KEY, &actual_public_key2, OTB_FRIEND_PROP_TRANSPORT_CIPHER_NAME, &actual_transport_cipher_name2, OTB_FRIEND_PROP_ADDRESS, &actual_address2, OTB_FRIEND_PROP_PORT, &actual_port2, NULL);
	g_assert_cmpint(0, ==, otb_unique_id_compare(expected_unique_id1, actual_unique_id1));
	g_assert_cmpint(0, ==, otb_unique_id_compare(expected_unique_id2, actual_unique_id2));
	g_assert_cmpstr(EXPECTED_PUBLIC_KEY1, ==, actual_public_key1);
	g_assert_cmpstr(EXPECTED_PUBLIC_KEY2, ==, actual_public_key2);
	g_assert_cmpstr(EXPECTED_TRANSPORT_CIPHER_NAME1, ==, actual_transport_cipher_name1);
	g_assert_cmpstr(EXPECTED_TRANSPORT_CIPHER_NAME2, ==, actual_transport_cipher_name2);
	g_assert_cmpstr(EXPECTED_ADDRESS1, ==, actual_address1);
	g_assert_cmpstr(EXPECTED_ADDRESS2, ==, actual_address2);
	g_assert_cmpint(EXPECTED_PORT1, ==, actual_port1);
	g_assert_cmpint(EXPECTED_PORT2, ==, actual_port2);
	otb_assert_bitkeeper_has_friends_in_memory_and_persisted(expected_unique_id1, expected_unique_id2);
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

static OtbUniqueId *otb_bitkeeper_generate_incoming_pad_for_friend(const OtbUniqueId *friend_unique_id)
{
	OtbFriend *friend=otb_bitkeeper_get_friend(friend_unique_id);
	g_assert(friend!=NULL);
	OtbPadDb *incoming_pad_db=NULL;
	g_object_get(friend, OTB_FRIEND_PROP_INCOMING_PAD_DB, &incoming_pad_db, NULL);
	g_assert(incoming_pad_db!=NULL);
	OtbUniqueId *pad_unique_id=otb_unique_id_new();
	OtbPadIO *pad_io=otb_pad_db_add_incoming_pad(incoming_pad_db, pad_unique_id, 1, 50000000);
	g_assert(pad_io!=NULL);
	char random_byte;
	g_assert(otb_random_bytes(&random_byte, 1));
	g_assert(otb_pad_write(pad_io, &random_byte, 1));
	g_assert(otb_pad_db_close_pad(incoming_pad_db, pad_io));
	g_object_unref(incoming_pad_db);
	g_object_unref(friend);
	return pad_unique_id;
}

static void otb_assert_bitkeeper_friend_is_expected(const OtbUniqueId *expected_friend_unique_id, OtbFriend *actual_friend)
{
	OtbUniqueId *actual_friend_unique_id=NULL;
	g_object_get(actual_friend, OTB_FRIEND_PROP_UNIQUE_ID, &actual_friend_unique_id, NULL);
	g_assert(actual_friend_unique_id!=NULL);
	g_assert_cmpint(0, ==, otb_unique_id_compare(actual_friend_unique_id, expected_friend_unique_id));
	otb_unique_id_unref(actual_friend_unique_id);
}

static void otb_bitkeeper_find_by_pad_test(const OtbUniqueId *expected_friend_unique_id1, const OtbUniqueId *expected_friend_unique_id2)
{
	OtbUniqueId *pad_unique_id1=otb_bitkeeper_generate_incoming_pad_for_friend(expected_friend_unique_id1);
	g_assert(pad_unique_id1!=NULL);
	OtbUniqueId *pad_unique_id2=otb_bitkeeper_generate_incoming_pad_for_friend(expected_friend_unique_id2);
	g_assert(pad_unique_id2!=NULL);
	OtbFriend *actual_friend1=otb_bitkeeper_get_friend_who_sent_pad(pad_unique_id1);
	g_assert(actual_friend1!=NULL);
	OtbFriend *actual_friend2=otb_bitkeeper_get_friend_who_sent_pad(pad_unique_id2);
	g_assert(actual_friend2!=NULL);
	otb_assert_bitkeeper_friend_is_expected(expected_friend_unique_id1, actual_friend1);
	otb_assert_bitkeeper_friend_is_expected(expected_friend_unique_id2, actual_friend2);
	g_object_unref(actual_friend2);
	g_object_unref(actual_friend1);
	otb_unique_id_unref(pad_unique_id2);
	otb_unique_id_unref(pad_unique_id1);
}

static void otb_bitkeeper_delete_test(const OtbUniqueId *expected_unique_id1, const OtbUniqueId *expected_unique_id2)
{
	g_assert(otb_bitkeeper_remove_friend(expected_unique_id2));
	otb_assert_bitkeeper_has_friends_in_memory_and_persisted(expected_unique_id1, NULL);
	g_assert(otb_bitkeeper_remove_friend(expected_unique_id1));
	otb_assert_bitkeeper_has_friends_in_memory_and_persisted(NULL, NULL);
}

void otb_create_bitkeeper_for_test(void)
{
	otb_test_setup_local_crypto();
	otb_initialize_settings_for_tests();
	g_assert(!otb_bitkeeper_exists());
	OtbAsymCipher *asym_cipher=g_object_new(OTB_TYPE_ASYM_CIPHER, OTB_ASYM_CIPHER_PROP_SYM_CIPHER_NAME, "RC2-64-CBC", OTB_ASYM_CIPHER_PROP_KEY_SIZE, SHORT_KEY_SIZE_THAT_DOES_NOT_MAKE_UNIT_TESTS_RUN_SLOWLY, NULL);
	g_assert(asym_cipher!=NULL);
	g_assert(otb_asym_cipher_generate_random_keys(asym_cipher));
	OtbUser *user=g_object_new(OTB_TYPE_USER, OTB_USER_PROP_ASYM_CIPHER, asym_cipher, NULL);
	g_assert(user!=NULL);
	g_object_set(user, OTB_USER_PROP_ADDRESS, "BungaBunga.onion", NULL);
	g_assert(otb_user_save(user));
	OtbBitkeeper *bitkeeper=g_object_new(OTB_TYPE_BITKEEPER, OTB_BITKEEPER_PROP_USER, user, NULL);
	g_assert(bitkeeper!=NULL);
	g_assert(otb_bitkeeper_set(bitkeeper));
	g_assert(otb_bitkeeper_exists());
	g_object_unref(bitkeeper);
	g_object_unref(user);
	g_object_unref(asym_cipher);
}

static void test_otb_bitkeeper_import_find_delete_friends(void)
{
	otb_create_bitkeeper_for_test();
	OtbUniqueId *expected_unique_id1=otb_unique_id_new();
	OtbUniqueId *expected_unique_id2=otb_unique_id_new();
	otb_bitkeeper_import_test(expected_unique_id1, expected_unique_id2);
	otb_bitkeeper_find_by_pad_test(expected_unique_id1, expected_unique_id2);
	otb_bitkeeper_delete_test(expected_unique_id1, expected_unique_id2);
	otb_unique_id_unref(expected_unique_id1);
	otb_unique_id_unref(expected_unique_id2);
	otb_bitkeeper_unload();
	otb_local_crypto_lock();
}

void otb_add_bitkeeper_tests(void)
{
	otb_add_test_func("/bitkeeper/test_otb_bitkeeper_create_with_defaults", test_otb_bitkeeper_create_with_defaults);
	otb_add_test_func("/bitkeeper/test_otb_bitkeeper_create_set_unload_load_save", test_otb_bitkeeper_create_set_unload_load_save);
	otb_add_test_func("/bitkeeper/test_otb_bitkeeper_user", test_otb_bitkeeper_user);
	otb_add_test_func("/bitkeeper/test_otb_bitkeeper_proxy_port", test_otb_bitkeeper_proxy_port);
	otb_add_test_func("/bitkeeper/test_otb_bitkeeper_pad_synchronization_interval", test_otb_bitkeeper_pad_synchronization_interval);
	otb_add_test_func("/bitkeeper/test_otb_bitkeeper_import_find_delete_friends", test_otb_bitkeeper_import_find_delete_friends);
}
