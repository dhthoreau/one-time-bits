/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <glib.h>
#include <uuid/uuid.h>

#include "asym-cipher.h"
#include "bitkeeper.h"
#include "friend.h"
#include "settings.h"
#include "user.h"

static void otb_bitkeeper_dispose(GObject *object);

G_DEFINE_TYPE(OtbBitkeeper, otb_bitkeeper, G_TYPE_OBJECT);

struct _OtbBitkeeperPrivate
{
	OtbUser *user;
	GSList *friends;
};

static void otb_bitkeeper_class_init(OtbBitkeeperClass *klass)
{
	GObjectClass *object_class=G_OBJECT_CLASS(klass);
	object_class->dispose=otb_bitkeeper_dispose;
}

static void otb_bitkeeper_init(OtbBitkeeper *bitkeeper)
{
	bitkeeper->priv=G_TYPE_INSTANCE_GET_PRIVATE(bitkeeper, OTB_TYPE_BITKEEPER, OtbBitkeeperPrivate);
	bitkeeper->priv->user=NULL;
	bitkeeper->priv->friends=NULL;
}

static void otb_bitkeeper_dispose(GObject *object)
{
	g_return_if_fail(object!=NULL);
	g_return_if_fail(OTB_IS_BITKEEPER(object));
	OtbBitkeeper *bitkeeper=OTB_BITKEEPER(object);
	if(bitkeeper->priv->user!=NULL)
	{
		g_object_unref(bitkeeper->priv->user);
		bitkeeper->priv->user=NULL;
	}
	g_slist_free_full(bitkeeper->priv->friends, g_object_unref);
	bitkeeper->priv->friends=NULL;
	G_OBJECT_CLASS(otb_bitkeeper_parent_class)->dispose(object);
}

gboolean otb_bitkeeper_load_friends(OtbBitkeeper *bitkeeper)
{
	gboolean ret_val=TRUE;
	char *friends_base_path=g_build_filename(otb_settings_get_data_directory_path(), "friends", NULL);
	GError *error=NULL;
	GDir *friends_dir=g_dir_open(friends_base_path, 0, &error);
	if(friends_dir)
	{
		const char *file_name;
		while(ret_val && (file_name=g_dir_read_name(friends_dir))!=NULL)
		{
			char *file_path=g_build_filename(friends_base_path, file_name, NULL);
			if(g_file_test(file_path, G_FILE_TEST_IS_DIR))
			{
				OtbFriend *friend=otb_friend_load_from_directory(file_path);
				if(friend==NULL)
					ret_val=FALSE;
				else
					bitkeeper->priv->friends=g_slist_prepend(bitkeeper->priv->friends, friend);
			}
			g_free(file_path);
		}
		g_dir_close(friends_dir);
	}
	else
	{
		g_error_free(error);
		ret_val=FALSE;
	}
	g_free(friends_base_path);
	return ret_val;
}

OtbBitkeeper *otb_bitkeeper_load()
{
	OtbBitkeeper *bitkeeper=g_object_new(OTB_TYPE_BITKEEPER, NULL);
	if((bitkeeper->priv->user=otb_user_load_from_settings_config())==NULL || !otb_bitkeeper_load_friends(bitkeeper))
	{
		g_object_unref(bitkeeper);
		bitkeeper=NULL;
	}
	return bitkeeper;
}
