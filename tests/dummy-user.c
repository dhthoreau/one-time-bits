/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include "dummy-user.h"

static GKeyFile *otb_dummy_user_export_key_file(const OtbUser *user);

G_DEFINE_TYPE(OtbDummyUser, otb_dummy_user, OTB_TYPE_USER);

static void otb_dummy_user_class_init(OtbDummyUserClass *klass)
{
	OTB_USER_CLASS(klass)->otb_user_export_key_file_private=otb_dummy_user_export_key_file;
}

static void otb_dummy_user_init(OtbDummyUser *dummy_user)
{
	dummy_user->export_call_count=0;
}

static GKeyFile *otb_dummy_user_export_key_file(const OtbUser *user)
{
	OtbDummyUser *dummy_user=OTB_DUMMY_USER(user);
	dummy_user->export_call_count++;
	OTB_USER_CLASS(otb_dummy_user_parent_class)->otb_user_export_key_file_private(user);
}
