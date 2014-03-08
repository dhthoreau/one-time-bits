/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <string.h>

#include "main.h"
#include "test-utils.h"
#include "../src/friend.h"
#include "../src/uuid-util.h"

static void otb_assert_friend_files_exist(const uuid_t expected_unique_id, const char *expected_base_path)
{
	char expected_unique_id_path[UNIQUE_ID_STR_BYTES];
	uuid_unparse_lower(expected_unique_id, expected_unique_id_path);
	char *expected_file_path=g_build_filename(expected_base_path, expected_unique_id_path, "friend.otb", NULL);
	char *expected_incoming_path=g_build_filename(expected_base_path, expected_unique_id_path, "incoming", "db.otb", NULL);
	char *expected_outgoing_path=g_build_filename(expected_base_path, expected_unique_id_path, "outgoing", "db.otb", NULL);
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

static GKeyFile *otb_create_import_file(const uuid_t unique_id, const char *public_key, const char *onion_base_domain)
{
	GKeyFile *import_file=g_key_file_new();
	char unique_id_string[UNIQUE_ID_STR_BYTES];
	uuid_unparse_lower(unique_id, unique_id_string);
	g_key_file_set_string(import_file, OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_UNIQUE_ID, unique_id_string);
	g_key_file_set_string(import_file, OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_PUBLIC_KEY, public_key);
	g_key_file_set_string(import_file, OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_ONION_BASE_DOMAIN, onion_base_domain);
	return import_file;
}

static void test_otb_friend_create_import()
{
	const char *EXPECTED_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\nMCwwDQYJKoZIhvcNAQEBBQADGwAwGAIRAOI3kOtj0yQLT1JyfbBXLbUCAwEAAQ==\n-----END PUBLIC KEY-----";
	const char *EXPECTED_ONION_BASE_DOMAIN="SoyMilkRoad";
	const char *UNEXPECTED_PATH="garbage";
	const uuid_t unexpected_unique_id;
	
	otb_test_setup_local_crypto();
	char *friend_dir_path=otb_generate_unique_test_subdir_path();
	uuid_t expected_unique_id;
	uuid_generate(expected_unique_id);
	GKeyFile *import_file=otb_create_import_file(expected_unique_id, EXPECTED_PUBLIC_KEY, EXPECTED_ONION_BASE_DOMAIN);
	char *import_string=g_key_file_to_data(import_file, NULL, NULL);
	g_key_file_unref(import_file);
	OtbFriend *create_friend=otb_friend_import_to_directory(import_string, friend_dir_path);
	g_free(import_string);
	g_assert(create_friend!=NULL);
	otb_assert_friend_files_exist(expected_unique_id, friend_dir_path);
	g_assert(otb_friend_set_public_key(create_friend, EXPECTED_PUBLIC_KEY));
	g_assert(otb_friend_set_onion_base_domain(create_friend, EXPECTED_ONION_BASE_DOMAIN));
	OtbFriend *load_friend=otb_friend_load_from_directory((const uuid_t*)&expected_unique_id, UNEXPECTED_PATH);
	g_assert(load_friend==NULL);
	load_friend=otb_friend_load_from_directory((const uuid_t*)&unexpected_unique_id, friend_dir_path);
	g_assert(load_friend==NULL);
	load_friend=otb_friend_load_from_directory((const uuid_t*)&expected_unique_id, friend_dir_path);
	g_assert(load_friend!=NULL);
	char *actual_base_path=NULL;
	char *actual_public_key=NULL;
	char *actual_onion_base_domain=NULL;
	g_object_get(load_friend, OTB_FRIEND_PROP_BASE_PATH, &actual_base_path, OTB_FRIEND_PROP_PUBLIC_KEY, &actual_public_key, OTB_FRIEND_PROP_ONION_BASE_DOMAIN, &actual_onion_base_domain, NULL);
	g_assert_cmpstr(friend_dir_path, ==, actual_base_path);
	g_assert_cmpstr(EXPECTED_PUBLIC_KEY, ==, actual_public_key);
	g_assert_cmpstr(EXPECTED_ONION_BASE_DOMAIN, ==, actual_onion_base_domain);
	g_free(actual_base_path);
	g_free(actual_public_key);
	g_free(actual_onion_base_domain);
	otb_assert_friends_saved_dbs_in_same_place(create_friend, load_friend);
	g_object_unref(load_friend);
	g_object_unref(create_friend);
	g_free(friend_dir_path);
}

void otb_add_friend_tests()
{
	otb_add_test_func("/friend/test_otb_friend_create_import", test_otb_friend_create_import);
}
