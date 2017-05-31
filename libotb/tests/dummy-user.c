/**
 * Copyright © 2017 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include "dummy-friend.h"
#include "dummy-user.h"
#include "../src/settings.h"

static gboolean otb_dummy_user_load_from_settings(OtbUser *user);
static gboolean otb_dummy_user_save_to_settings(const OtbUser *user);
static void otb_dummy_user_export_key_file(const OtbUser *user, GKeyFile *export_key_file);
static void otb_dummy_user_finalize(GObject *object);

G_DEFINE_TYPE(OtbDummyUser, otb_dummy_user, OTB_TYPE_USER);

static void otb_dummy_user_class_init(OtbDummyUserClass *klass)
{
	OTB_USER_CLASS(klass)->otb_user_load_from_settings_private=otb_dummy_user_load_from_settings;
	OTB_USER_CLASS(klass)->otb_user_save_to_settings_private=otb_dummy_user_save_to_settings;
	OTB_USER_CLASS(klass)->otb_user_export_key_file_private=otb_dummy_user_export_key_file;
	GObjectClass *object_class=G_OBJECT_CLASS(klass);
	object_class->finalize=otb_dummy_user_finalize;
}

static void otb_dummy_user_init(OtbDummyUser *dummy_user)
{
	dummy_user->loaded_key_value=NULL;
}

static void otb_dummy_user_finalize(GObject *object)
{
	g_return_if_fail(object!=NULL);
	g_return_if_fail(OTB_IS_DUMMY_USER(object));
	OtbDummyUser *dummy_user=OTB_DUMMY_USER(object);
	g_free(dummy_user->loaded_key_value);
}

#define otb_dummy_user_friend_key(user)	((OTB_DUMMY_USER(user)->loaded_key_value=otb_settings_get_config_string(OTB_DUMMY_FRIEND_GROUP, OTB_DUMMY_FRIEND_KEY))!=NULL)

static gboolean otb_dummy_user_load_from_settings(OtbUser *user)
{
	return OTB_USER_CLASS(otb_dummy_user_parent_class)->otb_user_load_from_settings_private(user) && otb_dummy_user_friend_key(user);
}

static gboolean otb_dummy_user_save_to_settings(const OtbUser *user)
{
	return OTB_USER_CLASS(otb_dummy_user_parent_class)->otb_user_save_to_settings_private(user) && otb_settings_set_config_string(OTB_DUMMY_FRIEND_GROUP, OTB_DUMMY_FRIEND_KEY, OTB_DUMMY_USER_SAVE_VALUE);
}

static void otb_dummy_user_export_key_file(const OtbUser *user, GKeyFile *export_key_file)
{
	OTB_USER_CLASS(otb_dummy_user_parent_class)->otb_user_export_key_file_private(user, export_key_file);
	g_key_file_set_string(export_key_file, OTB_DUMMY_FRIEND_GROUP, OTB_DUMMY_FRIEND_KEY, OTB_DUMMY_USER_EXPORT_VALUE);
}
