/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include "dummy-friend.h"

static void otb_dummy_friend_import_key_file(OtbFriend *friend, GKeyFile *import_key_file);
static void otb_dummy_friend_export_key_file(const OtbFriend *friend, GKeyFile *export_key_file);

G_DEFINE_TYPE(OtbDummyFriend, otb_dummy_friend, OTB_TYPE_FRIEND);

static void otb_dummy_friend_class_init(OtbDummyFriendClass *klass)
{
	OTB_FRIEND_CLASS(klass)->otb_friend_import_key_file_private=otb_dummy_friend_import_key_file;
	OTB_FRIEND_CLASS(klass)->otb_friend_export_key_file_private=otb_dummy_friend_export_key_file;
}

static void otb_dummy_friend_init(OtbDummyFriend *dummy_friend)
{
	dummy_friend->export_call_count=0;
}

static void otb_dummy_friend_import_key_file(OtbFriend *friend, GKeyFile *import_key_file)
{
	OtbDummyFriend *dummy_friend=OTB_DUMMY_FRIEND(friend);
	dummy_friend->export_call_count++;
	OTB_FRIEND_CLASS(otb_dummy_friend_parent_class)->otb_friend_import_key_file_private(friend, import_key_file);
}

static void otb_dummy_friend_export_key_file(const OtbFriend *friend, GKeyFile *export_key_file)
{
	OtbDummyFriend *dummy_friend=OTB_DUMMY_FRIEND(friend);
	dummy_friend->export_call_count++;
	OTB_FRIEND_CLASS(otb_dummy_friend_parent_class)->otb_friend_export_key_file_private(friend, export_key_file);
}
