/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <string.h>

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
	OtbPadDb *create_incoming_pads=NULL;
	OtbPadDb *create_outgoing_pads=NULL;
	g_object_get(create_friend, OTB_FRIEND_PROP_INCOMING_PADS, &create_incoming_pads, OTB_FRIEND_PROP_OUTGOING_PADS, &create_outgoing_pads, NULL);
	g_assert(create_incoming_pads!=NULL);
	g_assert(create_outgoing_pads!=NULL);
	OtbPadDb *load_incoming_pads=NULL;
	OtbPadDb *load_outgoing_pads=NULL;
	g_object_get(load_friend, OTB_FRIEND_PROP_INCOMING_PADS, &load_incoming_pads, OTB_FRIEND_PROP_OUTGOING_PADS, &load_outgoing_pads, NULL);
	g_assert(load_incoming_pads!=NULL);
	g_assert(load_outgoing_pads!=NULL);
	char *create_incoming_pads_path=NULL;
	g_object_get(create_incoming_pads, OTB_PAD_DB_PROP_BASE_PATH, &create_incoming_pads_path, NULL);
	char *create_outgoing_pads_path=NULL;
	g_object_get(create_outgoing_pads, OTB_PAD_DB_PROP_BASE_PATH, &create_outgoing_pads_path, NULL);
	char *load_incoming_pads_path=NULL;
	g_object_get(load_incoming_pads, OTB_PAD_DB_PROP_BASE_PATH, &load_incoming_pads_path, NULL);
	char *load_outgoing_pads_path=NULL;
	g_object_get(load_outgoing_pads, OTB_PAD_DB_PROP_BASE_PATH, &load_outgoing_pads_path, NULL);
	g_assert_cmpstr(create_incoming_pads_path, ==, load_incoming_pads_path);
	g_assert_cmpstr(create_outgoing_pads_path, ==, load_outgoing_pads_path);
	g_assert_cmpstr(create_incoming_pads_path, !=, load_outgoing_pads_path);
	g_free(create_incoming_pads_path);
	g_free(create_outgoing_pads_path);
	g_free(load_incoming_pads_path);
	g_free(load_outgoing_pads_path);
}

static GKeyFile *otb_create_import_file(const char *public_key, const char *onion_base_domain)
{
	GKeyFile *import_file=g_key_file_new();
	OtbUniqueId *unique_id=otb_unique_id_create();
	otb_settings_set_bytes(import_file, OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_UNIQUE_ID, unique_id, sizeof(OtbUniqueId));
	g_free(unique_id);
	g_key_file_set_string(import_file, OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_PUBLIC_KEY, public_key);
	g_key_file_set_string(import_file, OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_ONION_BASE_DOMAIN, onion_base_domain);
	g_key_file_set_string(import_file, OTB_DUMMY_FRIEND_GROUP, OTB_DUMMY_FRIEND_KEY, OTB_DUMMY_FRIEND_VALUE);
	return import_file;
}

static void otb_do_friend_create_import_delete_test(OtbFriend **create_friend, OtbFriend **load_friend)
{
	const char *EXPECTED_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\nMCwwDQYJKoZIhvcNAQEBBQADGwAwGAIRAOI3kOtj0yQLT1JyfbBXLbUCAwEAAQ==\n-----END PUBLIC KEY-----";
	const char *EXPECTED_ONION_BASE_DOMAIN="SoyMilkRoad";
	const char *UNEXPECTED_PATH="garbage";
	
	otb_test_setup_local_crypto();
	char *friend_dir_path=otb_generate_unique_test_subdir_path();
	GKeyFile *import_file=otb_create_import_file(EXPECTED_PUBLIC_KEY, EXPECTED_ONION_BASE_DOMAIN);
	char *import_string=g_key_file_to_data(import_file, NULL, NULL);
	g_key_file_unref(import_file);
	*create_friend=otb_friend_import_to_directory(import_string, friend_dir_path);
	g_free(import_string);
	g_assert(*create_friend!=NULL);
	g_assert(g_file_test(friend_dir_path, G_FILE_TEST_EXISTS));
	otb_assert_friend_files_exist(friend_dir_path);
	g_assert(otb_friend_set_public_key(*create_friend, EXPECTED_PUBLIC_KEY));
	g_assert(otb_friend_set_onion_base_domain(*create_friend, EXPECTED_ONION_BASE_DOMAIN));
	*load_friend=otb_friend_load_from_directory(UNEXPECTED_PATH);
	g_assert(*load_friend==NULL);
	*load_friend=otb_friend_load_from_directory(friend_dir_path);
	g_assert(*load_friend!=NULL);
	char *actual_base_path=NULL;
	char *actual_public_key=NULL;
	char *actual_onion_base_domain=NULL;
	g_object_get(*load_friend, OTB_FRIEND_PROP_BASE_PATH, &actual_base_path, OTB_FRIEND_PROP_PUBLIC_KEY, &actual_public_key, OTB_FRIEND_PROP_ONION_BASE_DOMAIN, &actual_onion_base_domain, NULL);
	g_assert_cmpstr(friend_dir_path, ==, actual_base_path);
	g_assert_cmpstr(EXPECTED_PUBLIC_KEY, ==, actual_public_key);
	g_assert_cmpstr(EXPECTED_ONION_BASE_DOMAIN, ==, actual_onion_base_domain);
	g_free(actual_base_path);
	g_free(actual_public_key);
	g_free(actual_onion_base_domain);
	otb_assert_friends_saved_dbs_in_same_place(*create_friend, *load_friend);
	otb_friend_delete(*load_friend);
	g_assert(!g_file_test(friend_dir_path, G_FILE_TEST_EXISTS));
	g_free(friend_dir_path);
}

static void test_otb_friend_create_import_delete()
{
	OtbFriend *create_friend=NULL;
	OtbFriend *load_friend=NULL;
	otb_do_friend_create_import_delete_test(&create_friend, &load_friend);
	g_assert(OTB_IS_FRIEND(create_friend));
	g_assert(!OTB_IS_DUMMY_FRIEND(create_friend));
	g_assert(OTB_IS_FRIEND(load_friend));
	g_assert(!OTB_IS_DUMMY_FRIEND(load_friend));
	g_object_unref(create_friend);
	g_object_unref(load_friend);
}

static void test_otb_dummy_friend_create_import_delete()
{
	OtbFriend *create_friend=NULL;
	OtbFriend *load_friend=NULL;
	otb_friend_set_runtime_type(OTB_TYPE_DUMMY_FRIEND);
	otb_do_friend_create_import_delete_test(&create_friend, &load_friend);
	g_assert(OTB_IS_FRIEND(create_friend));
	g_assert(OTB_IS_DUMMY_FRIEND(create_friend));
	g_assert(OTB_IS_FRIEND(load_friend));
	g_assert(OTB_IS_DUMMY_FRIEND(load_friend));
	g_assert_cmpstr(OTB_DUMMY_FRIEND_VALUE, ==, OTB_DUMMY_FRIEND(create_friend)->imported_dummy_value);
	g_assert_cmpstr(OTB_DUMMY_FRIEND_VALUE, ==, OTB_DUMMY_FRIEND(load_friend)->imported_dummy_value);
	g_object_unref(create_friend);
	g_object_unref(load_friend);
	otb_friend_set_runtime_type(OTB_TYPE_FRIEND);
}

void otb_add_friend_tests()
{
	otb_add_test_func("/friend/test_otb_friend_create_import_delete", test_otb_friend_create_import_delete);
	otb_add_test_func("/friend/test_otb_dummy_friend_export_delete", test_otb_dummy_friend_create_import_delete);
}
