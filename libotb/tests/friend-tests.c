/**
 * Copyright © 2015 the OTB team
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
#include "../src/local-crypto.h"
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

char *otb_create_import_string(const OtbUniqueId *unique_id, const char *public_key, const char *transport_cipher_name, const char *address, unsigned short port, const char *dummy_value)
{
	GKeyFile *import_file=g_key_file_new();
	otb_settings_set_bytes(import_file, OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_UNIQUE_ID, otb_unique_id_get_bytes(unique_id), OTB_UNIQUE_ID_BYTES_SIZE);
	g_key_file_set_string(import_file, OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_PUBLIC_KEY, public_key);
	g_key_file_set_string(import_file, OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_TRANSPORT_CIPHER_NAME, transport_cipher_name);
	g_key_file_set_string(import_file, OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_ADDRESS, address);
	g_key_file_set_integer(import_file, OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_PORT, (int)port);
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
	const char *EXPECTED_ADDRESS1="SoyMilkRoad.onion";
	const char *EXPECTED_ADDRESS2="SoyMilkRoad2.onion";
	const unsigned short EXPECTED_PORT1=1357;
	const unsigned short EXPECTED_PORT2=2468;
	const char *EXPECTED_DUMMY_VALUE1="sldkfjklsdjfkslkfjsd.onion";
	const char *EXPECTED_DUMMY_VALUE2="uyhrhyfrgyrfgghfg.onion";
	const char *UNEXPECTED_PATH="garbage";
	
	otb_test_setup_local_crypto();
	char *friend_dir_path=otb_generate_unique_test_subdir_path();
	OtbUniqueId *expected_unique_id=otb_unique_id_new();
	char *import_string=otb_create_import_string(expected_unique_id, EXPECTED_PUBLIC_KEY1, EXPECTED_TRANSPORT_CIPHER_NAME1, EXPECTED_ADDRESS1, EXPECTED_PORT1, EXPECTED_DUMMY_VALUE1);
	*create_friend=otb_friend_import_to_directory(import_string, friend_dir_path);
	g_assert(*create_friend!=NULL);
	g_assert(g_file_test(friend_dir_path, G_FILE_TEST_EXISTS));
	otb_assert_friend_files_exist(friend_dir_path);
	OtbUniqueId *actual_unique_id1=NULL;
	char *actual_public_key1=NULL;
	char *actual_transport_cipher_name1=NULL;
	char *actual_address1=NULL;
	unsigned int actual_port1=0;
	g_object_get(*create_friend, OTB_FRIEND_PROP_UNIQUE_ID, &actual_unique_id1, OTB_FRIEND_PROP_PUBLIC_KEY, &actual_public_key1, OTB_FRIEND_PROP_TRANSPORT_CIPHER_NAME, &actual_transport_cipher_name1, OTB_FRIEND_PROP_ADDRESS, &actual_address1, OTB_FRIEND_PROP_PORT, &actual_port1, NULL);
	g_assert_cmpint(0, ==, otb_unique_id_compare(expected_unique_id, actual_unique_id1));
	g_assert_cmpstr(EXPECTED_PUBLIC_KEY1, ==, actual_public_key1);
	g_assert_cmpstr(EXPECTED_TRANSPORT_CIPHER_NAME1, ==, actual_transport_cipher_name1);
	g_assert_cmpstr(EXPECTED_ADDRESS1, ==, actual_address1);
	g_assert_cmpint((unsigned int)EXPECTED_PORT1, ==, actual_port1);
	g_assert(otb_friend_set_public_key(*create_friend, EXPECTED_PUBLIC_KEY2));
	g_assert(otb_friend_set_transport_cipher_name(*create_friend, EXPECTED_TRANSPORT_CIPHER_NAME2));
	g_assert(otb_friend_set_address(*create_friend, EXPECTED_ADDRESS2));
	g_assert(otb_friend_set_port(*create_friend, EXPECTED_PORT2));
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
	char *actual_address2=NULL;
	unsigned int actual_port2=0;
	g_object_get(*load_friend, OTB_FRIEND_PROP_UNIQUE_ID, &actual_unique_id2, OTB_FRIEND_PROP_BASE_PATH, &actual_base_path, OTB_FRIEND_PROP_PUBLIC_KEY, &actual_public_key2, OTB_FRIEND_PROP_TRANSPORT_CIPHER_NAME, &actual_transport_cipher_name2, OTB_FRIEND_PROP_ADDRESS, &actual_address2, OTB_FRIEND_PROP_PORT, &actual_port2, NULL);
	g_assert_cmpstr(friend_dir_path, ==, actual_base_path);
	g_assert_cmpint(0, ==, otb_unique_id_compare(expected_unique_id, actual_unique_id2));
	g_assert_cmpstr(EXPECTED_PUBLIC_KEY2, ==, actual_public_key2);
	g_assert_cmpstr(EXPECTED_TRANSPORT_CIPHER_NAME2, ==, actual_transport_cipher_name2);
	g_assert_cmpstr(EXPECTED_ADDRESS2, ==, actual_address2);
	g_assert_cmpint((unsigned int)EXPECTED_PORT2, ==, actual_port2);
	if(OTB_IS_DUMMY_FRIEND(*load_friend))
		g_assert_cmpstr(EXPECTED_DUMMY_VALUE2, ==, OTB_DUMMY_FRIEND(*load_friend)->dummy_value);
	otb_assert_friends_saved_dbs_in_same_place(*create_friend, *load_friend);
	otb_friend_delete(*load_friend);
	otb_assert_file_does_not_exist(friend_dir_path);
	otb_local_crypto_lock_sym_cipher();
	g_free(actual_base_path);
	otb_unique_id_unref(actual_unique_id1);
	otb_unique_id_unref(actual_unique_id2);
	g_free(actual_public_key1);
	g_free(actual_public_key2);
	g_free(actual_transport_cipher_name1);
	g_free(actual_transport_cipher_name2);
	g_free(actual_address1);
	g_free(actual_address2);
	g_free(import_string);
	otb_unique_id_unref(expected_unique_id);
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

static void otb_fill_pad_db_with_pads_for_expiration_test(OtbPadDb *pad_db, OtbUniqueId **pad_unique_id_to_expire_out, OtbUniqueId **pad_unique_id_to_preserve_out)
{
	const off_t INCOMING_PAD_SIZE=10;
	
	*pad_unique_id_to_expire_out=otb_unique_id_new();
	*pad_unique_id_to_preserve_out=otb_unique_id_new();
	OtbPadIO *pad_io_to_expire=otb_pad_db_add_incoming_pad(pad_db, *pad_unique_id_to_expire_out, INCOMING_PAD_SIZE, g_get_real_time()-10000000);
	g_assert(pad_io_to_expire!=NULL);
	g_assert(otb_pad_db_close_pad(pad_db, pad_io_to_expire));
	OtbPadIO *pad_io_to_keep=otb_pad_db_add_incoming_pad(pad_db, *pad_unique_id_to_preserve_out, INCOMING_PAD_SIZE, g_get_real_time()+10000000);
	g_assert(pad_io_to_keep!=NULL);
	g_assert(otb_pad_db_close_pad(pad_db, pad_io_to_keep));
}

static void otb_assert_pad_db_with_pads_for_expiration_test(OtbPadDb *pad_db, OtbUniqueId *pad_unique_id_to_expire, OtbUniqueId *pad_unique_id_to_preserve)
{
	GSList *remaining_pads=otb_pad_db_get_ids_of_pads_in_status(pad_db, OTB_PAD_REC_STATUS_INCOMING);
	g_assert_cmpint(1, ==, g_slist_length(remaining_pads));
	g_assert_cmpint(0, ==, otb_unique_id_compare(g_slist_nth_data(remaining_pads, 0), pad_unique_id_to_preserve));
	g_slist_free_full(remaining_pads, (GFreeFunc)otb_unique_id_unref);
}

static void test_remove_expired_pads()
{
	const char *PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\nMCwwDQYJKoZIhvcNAQEBBQADGwAwGAIRAOI3kOtj0yQLT1JyfbBXLbUCAwEAAQ==\n-----END PUBLIC KEY-----";
	const char *TRANSPORT_CIPHER_NAME="AES-256-CBC";
	const char *ADDRESS="SoyMilkRoad.onion";
	const unsigned short PORT=31415;
	const char *DUMMY_VALUE="sldkfjklsdjfkslkfjsd.onion";
	
	otb_test_setup_local_crypto();
	OtbUniqueId *friend_unique_id=otb_unique_id_new();
	char *import_string=otb_create_import_string(friend_unique_id, PUBLIC_KEY, TRANSPORT_CIPHER_NAME, ADDRESS, PORT, DUMMY_VALUE);
	OtbFriend *friend=otb_friend_import_to_directory(import_string, otb_get_test_dir_path());
	OtbPadDb *incoming_pad_db=NULL;
	OtbPadDb *outgoing_pad_db=NULL;
	g_object_get(friend, OTB_FRIEND_PROP_INCOMING_PAD_DB, &incoming_pad_db, OTB_FRIEND_PROP_OUTGOING_PAD_DB, &outgoing_pad_db, NULL);
	OtbUniqueId *incoming_pad_unique_id_to_expire=NULL;
	OtbUniqueId *incoming_pad_unique_id_to_preserve=NULL;
	otb_fill_pad_db_with_pads_for_expiration_test(incoming_pad_db, &incoming_pad_unique_id_to_expire, &incoming_pad_unique_id_to_preserve);
	OtbUniqueId *outgoing_pad_unique_id_to_expire=NULL;
	OtbUniqueId *outgoing_pad_unique_id_to_preserve=NULL;
	otb_fill_pad_db_with_pads_for_expiration_test(outgoing_pad_db, &outgoing_pad_unique_id_to_expire, &outgoing_pad_unique_id_to_preserve);
	otb_friend_remove_expired_pads(friend);
	otb_assert_pad_db_with_pads_for_expiration_test(incoming_pad_db, incoming_pad_unique_id_to_expire, incoming_pad_unique_id_to_preserve);
	otb_assert_pad_db_with_pads_for_expiration_test(outgoing_pad_db, outgoing_pad_unique_id_to_expire, outgoing_pad_unique_id_to_preserve);
	otb_local_crypto_lock_sym_cipher();
	otb_unique_id_unref(outgoing_pad_unique_id_to_preserve);
	otb_unique_id_unref(outgoing_pad_unique_id_to_expire);
	otb_unique_id_unref(incoming_pad_unique_id_to_preserve);
	otb_unique_id_unref(incoming_pad_unique_id_to_expire);
	g_object_unref(outgoing_pad_db);
	g_object_unref(incoming_pad_db);
	g_object_unref(friend);
	g_free(import_string);
	otb_unique_id_unref(friend_unique_id);
}

void otb_add_friend_tests()
{
	otb_add_test_func("/friend/test_otb_friend_create_import_save_delete", test_otb_friend_create_import_save_delete);
	otb_add_test_func("/friend/test_otb_dummy_friend_create_import_save_delete", test_otb_dummy_friend_create_import_save_delete);
	otb_add_test_func("/friend/test_remove_expired_pads", test_remove_expired_pads);
}
