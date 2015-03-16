/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include "dummy-friend.h"
#include "../src/settings.h"

static void otb_dummy_friend_import_key_file(OtbFriend *friend, GKeyFile *import_key_file);
static void otb_dummy_friend_export_key_file(const OtbFriend *friend, GKeyFile *export_key_file);
static void otb_dummy_friend_finalize(GObject *object);

G_DEFINE_TYPE(OtbDummyFriend, otb_dummy_friend, OTB_TYPE_FRIEND);

static void otb_dummy_friend_class_init(OtbDummyFriendClass *klass)
{
	GObjectClass *object_class=G_OBJECT_CLASS(klass);
	OtbFriendClass *friend_class=OTB_FRIEND_CLASS(klass);
	friend_class->otb_friend_import_key_file_private=otb_dummy_friend_import_key_file;
	friend_class->otb_friend_export_key_file_private=otb_dummy_friend_export_key_file;
	object_class->finalize=otb_dummy_friend_finalize;
}

static void otb_dummy_friend_init(OtbDummyFriend *dummy_friend)
{
	dummy_friend->dummy_value=NULL;
}

void otb_dummy_friend_set_dummy_value_no_save(OtbDummyFriend *dummy_friend, const char *dummy_value)
{
	g_free(dummy_friend->dummy_value);
	dummy_friend->dummy_value=g_strdup(dummy_value);
}

static void otb_dummy_friend_finalize(GObject *object)
{
	g_return_if_fail(object!=NULL);
	g_return_if_fail(OTB_IS_DUMMY_FRIEND(object));
	OtbDummyFriend *dummy_friend=OTB_DUMMY_FRIEND(object);
	otb_dummy_friend_set_dummy_value_no_save(dummy_friend, NULL);
	G_OBJECT_CLASS(otb_dummy_friend_parent_class)->finalize(object);
}

static void otb_dummy_friend_import_key_file(OtbFriend *friend, GKeyFile *import_key_file)
{
	OTB_FRIEND_CLASS(otb_dummy_friend_parent_class)->otb_friend_import_key_file_private(friend, import_key_file);
	OtbDummyFriend *dummy_friend=OTB_DUMMY_FRIEND(friend);
	char *dummy_value=otb_settings_get_string(import_key_file, OTB_DUMMY_FRIEND_GROUP, OTB_DUMMY_FRIEND_KEY);
	g_free(dummy_friend->dummy_value);
	dummy_friend->dummy_value=g_strdup(dummy_value);
	g_free(dummy_value);
}

static void otb_dummy_friend_export_key_file(const OtbFriend *friend, GKeyFile *export_key_file)
{
	OTB_FRIEND_CLASS(otb_dummy_friend_parent_class)->otb_friend_export_key_file_private(friend, export_key_file);
	g_key_file_set_string(export_key_file, OTB_DUMMY_FRIEND_GROUP, OTB_DUMMY_FRIEND_KEY, OTB_DUMMY_FRIEND(friend)->dummy_value);
}

gboolean otb_dummy_friend_set_dummy_value(OtbDummyFriend *dummy_friend, const char *dummy_value)
{
	otb_dummy_friend_set_dummy_value_no_save(dummy_friend, dummy_value);
	return otb_friend_save(OTB_FRIEND(dummy_friend));
}
