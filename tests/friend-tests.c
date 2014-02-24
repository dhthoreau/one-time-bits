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

static char *otb_get_expected_pad_db_file_path(const char *base_path)
{
	return g_build_filename(base_path, "db.otb", NULL);
}

static void otb_assert_pad_db_file_exists(const char *base_path)
{
	char *expected_pad_db_file_path=otb_get_expected_pad_db_file_path(base_path);
	g_assert(g_file_test(expected_pad_db_file_path, G_FILE_TEST_EXISTS));
	g_free(expected_pad_db_file_path);
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

static void test_otb_friend_create_load()
{
	const char *EXPECTED_PUBLIC_KEY="-----BEGIN RSA PRIVATE KEY-----\nMGICAQACEQDpsP08qyst63NtwDBJrnnXAgMBAAECEBC3aGX+mIggPJCnzVg8hoEC\nCQD6tX3yRztLWwIJAO6fjl12HaA1AggQGPctR0WXYQIJAL9wXqT4t/fpAgh9tF7u\nzqapLQ==\n-----END RSA PRIVATE KEY-----";
	const char *EXPECTED_ONION_BASE_DOMAIN="SoyMilkRoad";
	
	char *friend_dir_path=otb_generate_unique_test_subdir_path();
	OtbFriend *create_friend=otb_friend_create_in_directory(NULL, friend_dir_path);
	g_assert(create_friend!=NULL);
	g_assert(otb_friend_set_public_key(create_friend, EXPECTED_PUBLIC_KEY));
	g_assert(otb_friend_set_onion_base_domain(create_friend, EXPECTED_ONION_BASE_DOMAIN));
	OtbFriend *load_friend=otb_friend_load_from_directory(NULL, friend_dir_path);
	char *actual_base_path=NULL;
	char *actual_public_key=NULL;
	char *actual_onion_base_domain=NULL;
	g_object_get(load_friend, /*OTB_FRIEND_PROP_BASE_PATH, &actual_base_path,*/ OTB_FRIEND_PROP_PUBLIC_KEY, &actual_public_key, OTB_FRIEND_PROP_ONION_BASE_DOMAIN, &actual_onion_base_domain, NULL);
//	g_assert_cmpstr(friend_dir_path, ==, actual_base_path);
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
	otb_add_test_func("/friend/test_otb_friend_create_load", test_otb_friend_create_load);
}
