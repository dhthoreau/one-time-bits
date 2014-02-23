/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_FRIEND_H
#define OTB_FRIEND_H

#include <glib-object.h>

#include "pad-db.h"

#define OTB_FRIEND_PROP_BASE_PATH			"base_path"
#define OTB_FRIEND_PROP_INCOMING_PADS		"incoming_pads"
#define OTB_FRIEND_PROP_OUTGOING_PADS		"outgoing_pads"
#define OTB_FRIEND_PROP_PUBLIC_KEY			"public_key"
#define OTB_FRIEND_PROP_ONION_BASE_DOMAIN	"onion_base_domain"

#define OTB_TYPE_FRIEND				(otb_friend_get_type())
#define OTB_FRIEND(obj)				(G_TYPE_CHECK_INSTANCE_CAST((obj), OTB_TYPE_FRIEND, OtbFriend))
#define OTB_IS_FRIEND(obj)			(G_TYPE_CHECK_INSTANCE_TYPE((obj), OTB_TYPE_FRIEND))
#define OTB_FRIEND_CLASS(klass)		(G_TYPE_CHECK_CLASS_CAST((klass), OTB_TYPE_FRIEND, OtbFriendClass))
#define OTB_IS_FRIEND_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE((klass), OTB_TYPE_FRIEND))
#define OTB_FRIEND_GET_CLASS(obj)	(G_TYPE_CHECK_CLASS_TYPE((obj), OTB_TYPE_FRIEND, OtbFriendClass))

typedef struct _OtbFriend OtbFriend;
typedef struct _OtbFriendClass OtbFriendClass;
typedef struct _OtbFriendPrivate OtbFriendPrivate;

struct _OtbFriend
{
	GObject parent_instance;
	OtbFriendPrivate *priv;
};

struct _OtbFriendClass
{
	GObjectClass parent_class;
};

GType otb_friend_get_type();

OtbFriend *otb_friend_create_in_directory(const char *base_path);
OtbFriend *otb_friend_load_from_directory(const char *base_path);
gboolean otb_friend_set_public_key(const OtbFriend *friend, const char *public_key);
gboolean otb_friend_set_onion_base_domain(const OtbFriend *friend, const char *onion_base_domain);

#endif
