/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../src/friend.h"

#ifndef OTB_DUMMY_FRIEND_H
#define OTB_DUMMY_FRIEND_H

#define OTB_TYPE_DUMMY_FRIEND				(otb_dummy_friend_get_type())
#define OTB_DUMMY_FRIEND(obj)				(G_TYPE_CHECK_INSTANCE_CAST((obj), OTB_TYPE_DUMMY_FRIEND, OtbDummyFriend))
#define OTB_IS_DUMMY_FRIEND(obj)			(G_TYPE_CHECK_INSTANCE_TYPE((obj), OTB_TYPE_DUMMY_FRIEND))
#define OTB_DUMMY_FRIEND_CLASS(klass)		(G_TYPE_CHECK_CLASS_CAST((klass), OTB_TYPE_DUMMY_FRIEND, OtbDummyFriendClass))
#define OTB_IS_DUMMY_FRIEND_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE((klass), OTB_TYPE_DUMMY_FRIEND))
#define OTB_DUMMY_FRIEND_GET_CLASS(obj)		(G_TYPE_INSTANCE_GET_CLASS((obj), OTB_TYPE_DUMMY_FRIEND, OtbDummyFriendClass))

typedef struct _OtbDummyFriend OtbDummyFriend;
typedef struct _OtbDummyFriendClass OtbDummyFriendClass;

struct _OtbDummyFriend
{
	OtbFriend parent_instance;
	unsigned int export_call_count;
	unsigned int import_call_count;
};

struct _OtbDummyFriendClass
{
	GObjectClass parent_class;
};

GType otb_dummy_friend_get_type();

#endif

