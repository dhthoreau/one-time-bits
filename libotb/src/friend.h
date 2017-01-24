/**
 * Copyright © 2015 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_FRIEND_H
#define OTB_FRIEND_H

#include <glib-object.h>

#include "pad-db.h"
#include "unique-id.h"

#define OTB_FRIEND_IMPORT_GROUP					"otb-user"
#define OTB_FRIEND_IMPORT_UNIQUE_ID				"unique-id"
#define OTB_FRIEND_IMPORT_PUBLIC_KEY			"public-key"
#define OTB_FRIEND_IMPORT_TRANSPORT_CIPHER_NAME	"transport-cipher-name"
#define OTB_FRIEND_IMPORT_ADDRESS				"address"
#define OTB_FRIEND_IMPORT_PORT					"port"

#define OTB_FRIEND_PROP_BASE_PATH				"base-path"
#define OTB_FRIEND_PROP_INCOMING_PAD_DB			"incoming-pad-db"
#define OTB_FRIEND_PROP_OUTGOING_PAD_DB			"outgoing-pad-db"
#define OTB_FRIEND_PROP_UNIQUE_ID				"unique-id"
#define OTB_FRIEND_PROP_PUBLIC_KEY				"public-key"
#define OTB_FRIEND_PROP_TRANSPORT_CIPHER_NAME	"transport-cipher-name"
#define OTB_FRIEND_PROP_ADDRESS					"adddress"
#define OTB_FRIEND_PROP_PORT					"port"

#define OTB_TYPE_FRIEND				(otb_friend_get_type())
#define OTB_FRIEND(obj)				(G_TYPE_CHECK_INSTANCE_CAST((obj), OTB_TYPE_FRIEND, OtbFriend))
#define OTB_IS_FRIEND(obj)			(G_TYPE_CHECK_INSTANCE_TYPE((obj), OTB_TYPE_FRIEND))
#define OTB_FRIEND_CLASS(klass)		(G_TYPE_CHECK_CLASS_CAST((klass), OTB_TYPE_FRIEND, OtbFriendClass))
#define OTB_IS_FRIEND_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE((klass), OTB_TYPE_FRIEND))
#define OTB_FRIEND_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS((obj), OTB_TYPE_FRIEND, OtbFriendClass))

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
	void (*otb_friend_import_key_file_private)(OtbFriend *friend, GKeyFile *);
	void (*otb_friend_export_key_file_private)(const OtbFriend *friend, GKeyFile *);
};

GType otb_friend_get_type();

void otb_friend_set_runtime_type(GType friend_runtime_type);
gboolean otb_friend_save(const OtbFriend *friend);
OtbFriend *otb_friend_import_to_directory(const char *import_string, const char *base_path);
OtbFriend *otb_friend_load_from_directory(const char *base_path);
gboolean otb_friend_delete(OtbFriend *friend);
gboolean otb_friend_remove_expired_pads(const OtbFriend *friend);

#endif
