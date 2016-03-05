/**
 * Copyright © 2015 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../../libotb/src/libotb.h"

#ifndef OTB_DEMO_FRIEND_H
#define OTB_DEMO_FRIEND_H

#define OTB_DEMO_FRIEND_EXPORT_GROUP	"otb-demo"
#define OTB_DEMO_FRIEND_EXPORT_NAME		"name"

#define OTB_DEMO_TYPE_FRIEND				(otb_demo_friend_get_type())
#define OTB_DEMO_FRIEND(obj)				(G_TYPE_CHECK_INSTANCE_CAST((obj), OTB_DEMO_TYPE_FRIEND, OtbDemoFriend))
#define OTB_DEMO_IS_FRIEND(obj)				(G_TYPE_CHECK_INSTANCE_TYPE((obj), OTB_DEMO_TYPE_FRIEND))
#define OTB_DEMO_FRIEND_CLASS(klass)		(G_TYPE_CHECK_CLASS_CAST((klass), OTB_DEMO_TYPE_FRIEND, OtbDemoFriendClass))
#define OTB_IS_DEMO_FRIEND_CLASS(klass)		(G_TYPE_CHECK_CLASS_TYPE((klass), OTB_DEMO_TYPE_FRIEND))
#define OTB_DEMO_FRIEND_GET_CLASS(obj)		(G_TYPE_INSTANCE_GET_CLASS((obj), OTB_DEMO_TYPE_FRIEND, OtbDemoFriendClass))

typedef struct _OtbDemoFriend OtbDemoFriend;
typedef struct _OtbDemoFriendClass OtbDemoFriendClass;
typedef struct _OtbDemoFriendPrivate OtbDemoFriendPrivate;

struct _OtbDemoFriend
{
	OtbFriend parent_instance;
	char *name;
};

struct _OtbDemoFriendClass
{
	OtbFriendClass parent_class;
	OtbFriendPrivate *priv;
};

GType otb_demo_friend_get_type();

gboolean otb_demo_friend_set_name_value(OtbDemoFriend *demo_friend, const char *name);

#endif

