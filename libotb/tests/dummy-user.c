/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include "dummy-friend.h"
#include "dummy-user.h"

static void otb_dummy_user_export_key_file(const OtbUser *user, GKeyFile *export_key_file);

G_DEFINE_TYPE(OtbDummyUser, otb_dummy_user, OTB_TYPE_USER);

static void otb_dummy_user_class_init(OtbDummyUserClass *klass)
{
	OTB_USER_CLASS(klass)->otb_user_export_key_file_private=otb_dummy_user_export_key_file;
}

static void otb_dummy_user_init(OtbDummyUser *dummy_user)
{
}

static void otb_dummy_user_export_key_file(const OtbUser *user, GKeyFile *export_key_file)
{
	OTB_USER_CLASS(otb_dummy_user_parent_class)->otb_user_export_key_file_private(user, export_key_file);
	g_key_file_set_string(export_key_file, OTB_DUMMY_FRIEND_GROUP, OTB_DUMMY_FRIEND_KEY, OTB_DUMMY_USER_EXPORT_VALUE);
}
