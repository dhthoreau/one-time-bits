/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include "dummy-friend.h"
#include "main.h"
#include "test-utils.h"
#include "../src/friend.h"
#include "../src/settings.h"
#include "../src/unique-id.h"

static void otb_assert_friend_files_exist(const char *expected_base_path)
{
	char *expected_file_path=g_build_filename(expected_base_path, "friend.otb", NULL);
	char *expected_incoming_path=g_build_filename(expected_base_path, "incoming", "db.otb", NULL);
	char *expected_outgoing_path=g_build_filename(expected_base_path, "outgoing", "db.otb", NULL);
	g_assert(g_file_test(expected_file_path, G_FILE_TEST_EXISTS));
	g_assert(g_file_test(expected_incoming_path, G_FILE_TEST_EXISTS));
	g_assert(g_file_test(expected_outgoing_path, G_FILE_TEST_EXISTS));
	g_free(expected_file_path);
	g_free(expected_incoming_path);
	g_free(expected_outgoing_path);
}

static void otb_assert_friends_saved_dbs_in_same_place(OtbFriend *create_friend, OtbFriend *load_friend)
{
	OtbPadDb *create_incoming_pad_db=NULL;
	OtbPadDb *create_outgoing_pad_db=NULL;
	g_object_get(create_friend, OTB_FRIEND_PROP_INCOMING_PAD_DB, &create_incoming_pad_db, OTB_FRIEND_PROP_OUTGOING_PAD_DB, &create_outgoing_pad_db, NULL);
	g_assert(create_incoming_pad_db!=NULL);
	g_assert(create_outgoing_pad_db!=NULL);
	OtbPadDb *load_incoming_pad_db=NULL;
	OtbPadDb *load_outgoing_pad_db=NULL;
	g_object_get(load_friend, OTB_FRIEND_PROP_INCOMING_PAD_DB, &load_incoming_pad_db, OTB_FRIEND_PROP_OUTGOING_PAD_DB, &load_outgoing_pad_db, NULL);
	g_assert(load_incoming_pad_db!=NULL);
	g_assert(load_outgoing_pad_db!=NULL);
	char *create_incoming_pad_db_path=NULL;
	g_object_get(create_incoming_pad_db, OTB_PAD_DB_PROP_BASE_PATH, &create_incoming_pad_db_path, NULL);
	char *create_outgoing_pad_db_path=NULL;
	g_object_get(create_outgoing_pad_db, OTB_PAD_DB_PROP_BASE_PATH, &create_outgoing_pad_db_path, NULL);
	char *load_incoming_pad_db_path=NULL;
	g_object_get(load_incoming_pad_db, OTB_PAD_DB_PROP_BASE_PATH, &load_incoming_pad_db_path, NULL);
	char *load_outgoing_pad_db_path=NULL;
	g_object_get(load_outgoing_pad_db, OTB_PAD_DB_PROP_BASE_PATH, &load_outgoing_pad_db_path, NULL);
	g_assert_cmpstr(create_incoming_pad_db_path, ==, load_incoming_pad_db_path);
	g_assert_cmpstr(create_outgoing_pad_db_path, ==, load_outgoing_pad_db_path);
	g_assert_cmpstr(create_incoming_pad_db_path, !=, load_outgoing_pad_db_path);
	g_free(create_incoming_pad_db_path);
	g_free(create_outgoing_pad_db_path);
	g_free(load_incoming_pad_db_path);
	g_free(load_outgoing_pad_db_path);
	g_object_unref(load_incoming_pad_db);
	g_object_unref(load_outgoing_pad_db);
	g_object_unref(create_incoming_pad_db);
	g_object_unref(create_outgoing_pad_db);
}

char *otb_create_import_string(const OtbUniqueId *unique_id, const char *public_key, const char *transport_cipher_name, const char *onion_base_domain, const char *dummy_value)
{
	GKeyFile *import_file=g_key_file_new();
	otb_settings_set_bytes(import_file, OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_UNIQUE_ID, unique_id, sizeof *unique_id);
	g_key_file_set_string(import_file, OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_PUBLIC_KEY, public_key);
	g_key_file_set_string(import_file, OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_TRANSPORT_CIPHER_NAME, transport_cipher_name);
	g_key_file_set_string(import_file, OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_ONION_BASE_DOMAIN, onion_base_domain);
	g_key_file_set_string(import_file, OTB_DUMMY_FRIEND_GROUP, OTB_DUMMY_FRIEND_KEY, dummy_value);
	char *import_string=g_key_file_to_data(import_file, NULL, NULL);
	g_key_file_unref(import_file);
	return import_string;
}

static void otb_do_friend_create_import_save_delete_test(OtbFriend **create_friend, OtbFriend **load_friend)
{
	const char *EXPECTED_PUBLIC_KEY1="-----BEGIN PUBLIC KEY-----\nMCwwDQYJKoZIhvcNAQEBBQADGwAwGAIRAOI3kOtj0yQLT1JyfbBXLbUCAwEAAQ==\n-----END PUBLIC KEY-----";
	const char *EXPECTED_PUBLIC_KEY2="-----BEGIN PUBLIC KEY-----\noCwwDQYJKoZIhvcNAQEBBQADGwAwGAIRAOI3kOtj0yQLT1JyfbBXLbUCAwEAAQ==\n-----END PUBLIC KEY-----";
	const char *EXPECTED_TRANSPORT_CIPHER_NAME1="AES-256-CBC";
	const char *EXPECTED_TRANSPORT_CIPHER_NAME2="AES-128-CBC";
	const char *EXPECTED_ONION_BASE_DOMAIN1="SoyMilkRoad";
	const char *EXPECTED_ONION_BASE_DOMAIN2="SoyMilkRoad2";
	const char *EXPECTED_DUMMY_VALUE1="sldkfjklsdjfkslkfjsd";
	const char *EXPECTED_DUMMY_VALUE2="uyhrhyfrgyrfgghfg";
	const char *UNEXPECTED_PATH="garbage";
	
	otb_test_setup_local_crypto();
	char *friend_dir_path=otb_generate_unique_test_subdir_path();
	OtbUniqueId *expected_unique_id=otb_unique_id_create();
	char *import_string=otb_create_import_string(expected_unique_id, EXPECTED_PUBLIC_KEY1, EXPECTED_TRANSPORT_CIPHER_NAME1, EXPECTED_ONION_BASE_DOMAIN1, EXPECTED_DUMMY_VALUE1);
	*create_friend=otb_friend_import_to_directory(import_string, friend_dir_path);
	g_assert(*create_friend!=NULL);
	g_assert(g_file_test(friend_dir_path, G_FILE_TEST_EXISTS));
	otb_assert_friend_files_exist(friend_dir_path);
	OtbUniqueId *actual_unique_id1=NULL;
	char *actual_public_key1=NULL;
	char *actual_transport_cipher_name1=NULL;
	char *actual_onion_base_domain1=NULL;
	g_object_get(*create_friend, OTB_FRIEND_PROP_UNIQUE_ID, &actual_unique_id1, OTB_FRIEND_PROP_PUBLIC_KEY, &actual_public_key1, OTB_FRIEND_PROP_TRANSPORT_CIPHER_NAME, &actual_transport_cipher_name1, OTB_FRIEND_PROP_ONION_BASE_DOMAIN, &actual_onion_base_domain1, NULL);
	g_assert_cmpint(0, ==, otb_unique_id_compare(expected_unique_id, actual_unique_id1));
	g_assert_cmpstr(EXPECTED_PUBLIC_KEY1, ==, actual_public_key1);
	g_assert_cmpstr(EXPECTED_TRANSPORT_CIPHER_NAME1, ==, actual_transport_cipher_name1);
	g_assert_cmpstr(EXPECTED_ONION_BASE_DOMAIN1, ==, actual_onion_base_domain1);
	g_assert(otb_friend_set_public_key(*create_friend, EXPECTED_PUBLIC_KEY2));
	g_assert(otb_friend_set_transport_cipher_name(*create_friend, EXPECTED_TRANSPORT_CIPHER_NAME2));
	g_assert(otb_friend_set_onion_base_domain(*create_friend, EXPECTED_ONION_BASE_DOMAIN2));
	if(OTB_IS_DUMMY_FRIEND(*create_friend))
	{
		OtbDummyFriend *create_dummy_friend=OTB_DUMMY_FRIEND(*create_friend);
		g_assert_cmpstr(EXPECTED_DUMMY_VALUE1, ==, create_dummy_friend->dummy_value);
		g_assert(otb_dummy_friend_set_dummy_value(create_dummy_friend, EXPECTED_DUMMY_VALUE2));
	}
	*load_friend=otb_friend_load_from_directory(UNEXPECTED_PATH);
	g_assert(*load_friend==NULL);
	*load_friend=otb_friend_load_from_directory(friend_dir_path);
	g_assert(*load_friend!=NULL);
	char *actual_base_path=NULL;
	OtbUniqueId *actual_unique_id2=NULL;
	char *actual_public_key2=NULL;
	char *actual_transport_cipher_name2=NULL;
	char *actual_onion_base_domain2=NULL;
	g_object_get(*load_friend, OTB_FRIEND_PROP_UNIQUE_ID, &actual_unique_id2, OTB_FRIEND_PROP_BASE_PATH, &actual_base_path, OTB_FRIEND_PROP_PUBLIC_KEY, &actual_public_key2, OTB_FRIEND_PROP_TRANSPORT_CIPHER_NAME, &actual_transport_cipher_name2, OTB_FRIEND_PROP_ONION_BASE_DOMAIN, &actual_onion_base_domain2, NULL);
	g_assert_cmpstr(friend_dir_path, ==, actual_base_path);
	g_assert_cmpint(0, ==, otb_unique_id_compare(expected_unique_id, actual_unique_id2));
	g_assert_cmpstr(EXPECTED_PUBLIC_KEY2, ==, actual_public_key2);
	g_assert_cmpstr(EXPECTED_TRANSPORT_CIPHER_NAME2, ==, actual_transport_cipher_name2);
	g_assert_cmpstr(EXPECTED_ONION_BASE_DOMAIN2, ==, actual_onion_base_domain2);
	if(OTB_IS_DUMMY_FRIEND(*load_friend))
		g_assert_cmpstr(EXPECTED_DUMMY_VALUE2, ==, OTB_DUMMY_FRIEND(*load_friend)->dummy_value);
	otb_assert_friends_saved_dbs_in_same_place(*create_friend, *load_friend);
	otb_friend_delete(*load_friend);
	otb_assert_file_does_not_exist(friend_dir_path);
	g_free(actual_base_path);
	g_free(actual_unique_id1);
	g_free(actual_unique_id2);
	g_free(actual_public_key1);
	g_free(actual_public_key2);
	g_free(actual_transport_cipher_name1);
	g_free(actual_transport_cipher_name2);
	g_free(actual_onion_base_domain1);
	g_free(actual_onion_base_domain2);
	g_free(import_string);
	g_free(expected_unique_id);
	g_free(friend_dir_path);
}

static void test_otb_friend_create_import_save_delete()
{
	OtbFriend *create_friend=NULL;
	OtbFriend *load_friend=NULL;
	otb_do_friend_create_import_save_delete_test(&create_friend, &load_friend);
	g_assert(OTB_IS_FRIEND(create_friend));
	g_assert(!OTB_IS_DUMMY_FRIEND(create_friend));
	g_assert(OTB_IS_FRIEND(load_friend));
	g_assert(!OTB_IS_DUMMY_FRIEND(load_friend));
	g_object_unref(load_friend);
	g_object_unref(create_friend);
}

static void test_otb_dummy_friend_create_import_save_delete()
{
	OtbFriend *create_friend=NULL;
	OtbFriend *load_friend=NULL;
	otb_friend_set_runtime_type(OTB_TYPE_DUMMY_FRIEND);
	otb_do_friend_create_import_save_delete_test(&create_friend, &load_friend);
	g_assert(OTB_IS_FRIEND(create_friend));
	g_assert(OTB_IS_DUMMY_FRIEND(create_friend));
	g_assert(OTB_IS_FRIEND(load_friend));
	g_assert(OTB_IS_DUMMY_FRIEND(load_friend));
	g_object_unref(load_friend);
	g_object_unref(create_friend);
	otb_friend_set_runtime_type(OTB_TYPE_FRIEND);
}

void otb_add_friend_tests()
{
	otb_add_test_func("/friend/test_otb_friend_create_import_save_delete", test_otb_friend_create_import_save_delete);
	otb_add_test_func("/friend/test_otb_dummy_friend_create_import_save_delete", test_otb_dummy_friend_create_import_save_delete);
}
