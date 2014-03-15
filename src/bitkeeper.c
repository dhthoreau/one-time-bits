/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <glib/gi18n.h>

#include "asym-cipher.h"
#include "bitkeeper.h"
#include "settings.h"

enum
{
	PROP_0,
	PROP_USER
};

G_DEFINE_TYPE(OtbBitkeeper, otb_bitkeeper, G_TYPE_OBJECT);

static void otb_bitkeeper_dispose(GObject *object);
static void otb_bitkeeper_finalize(GObject *object);
static void otb_bitkeeper_get_property(GObject *object, unsigned int prop_id, GValue *value, GParamSpec *pspec);

struct _OtbBitkeeperPrivate
{
	GRWLock lock;
	OtbUser *user;
	GSList *friends;
	char *friends_base_path;
};

static void otb_bitkeeper_class_init(OtbBitkeeperClass *klass)
{
	GObjectClass *object_class=G_OBJECT_CLASS(klass);
	object_class->dispose=otb_bitkeeper_dispose;
	object_class->finalize=otb_bitkeeper_finalize;
	object_class->get_property=otb_bitkeeper_get_property;
	g_object_class_install_property(object_class, PROP_USER, g_param_spec_object(OTB_BITKEEPER_PROP_USER, _("User"), _("The user who is using the application"), OTB_TYPE_USER, G_PARAM_READABLE));
}

static void otb_bitkeeper_init(OtbBitkeeper *bitkeeper)
{
	bitkeeper->priv=G_TYPE_INSTANCE_GET_PRIVATE(bitkeeper, OTB_TYPE_BITKEEPER, OtbBitkeeperPrivate);
	g_rw_lock_init(&bitkeeper->priv->lock);
	bitkeeper->priv->user=NULL;
	bitkeeper->priv->friends=NULL;
	bitkeeper->priv->friends_base_path=g_build_filename(otb_settings_get_data_directory_path(), "friends", NULL);
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

static void otb_bitkeeper_finalize(GObject *object)
{
	g_return_if_fail(object!=NULL);
	g_return_if_fail(OTB_IS_BITKEEPER(object));
	OtbBitkeeper *bitkeeper=OTB_BITKEEPER(object);
	g_rw_lock_clear(&bitkeeper->priv->lock);
	g_free(bitkeeper->priv->friends_base_path);
	G_OBJECT_CLASS(otb_bitkeeper_parent_class)->finalize(object);
}

#define otb_bitkeeper_lock_read(bitkeeper)		(g_rw_lock_reader_lock(&bitkeeper->priv->lock))
#define otb_bitkeeper_unlock_read(bitkeeper)	(g_rw_lock_reader_unlock(&bitkeeper->priv->lock))
#define otb_bitkeeper_lock_write(bitkeeper)		(g_rw_lock_writer_lock(&bitkeeper->priv->lock))
#define otb_bitkeeper_unlock_write(bitkeeper)	(g_rw_lock_writer_unlock(&bitkeeper->priv->lock))

static void otb_bitkeeper_get_property(GObject *object, unsigned int prop_id, GValue *value, GParamSpec *pspec)
{
	OtbBitkeeper *bitkeeper=OTB_BITKEEPER(object);
	switch(prop_id)
	{
		case PROP_USER:
		{
			g_value_set_object(value, bitkeeper->priv->user);
			break;
		}
		default:
		{
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
		}
	}
}

static gboolean otb_bitkeeper_load_friends(OtbBitkeeper *bitkeeper)
{
	gboolean ret_val=TRUE;
	GError *error=NULL;
	GDir *friends_dir=g_dir_open(bitkeeper->priv->friends_base_path, 0, &error);
	if(friends_dir)
	{
		const char *file_name;
		while(ret_val && (file_name=g_dir_read_name(friends_dir))!=NULL)
		{
			char *file_path=g_build_filename(bitkeeper->priv->friends_base_path, file_name, NULL);
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

OtbUser *otb_bitkeeper_get_user(const OtbBitkeeper *bitkeeper)
{
	otb_bitkeeper_lock_read(bitkeeper);
	OtbUser *user=bitkeeper->priv->user;
	if(user!=NULL)
		g_object_ref(user);
	otb_bitkeeper_unlock_read(bitkeeper);
	return user;
}

OtbFriend *otb_bitkeeper_get_friend(const OtbBitkeeper *bitkeeper, const OtbUniqueId *unique_id)
{
	OtbFriend *friend=NULL;
	otb_bitkeeper_lock_read(bitkeeper);
	for(const GSList *curr_element=bitkeeper->priv->friends; curr_element!=NULL; curr_element=(const GSList*)g_list_next(curr_element))
	{
		OtbFriend *current_friend=OTB_FRIEND(curr_element->data);
		const OtbUniqueId *current_unique_id=NULL;
		g_object_get(current_friend, OTB_FRIEND_PROP_UNIQUE_ID, &current_unique_id, NULL);
		if(otb_unique_id_compare(unique_id, current_unique_id)==0)
		{
			friend=current_friend;
			g_object_ref(friend);
			break;
		}
	}
	otb_bitkeeper_unlock_read(bitkeeper);
	return friend;
}

static OtbFriend *otb_bitkeeper_import_friend_to_disk(const OtbBitkeeper *bitkeeper, const char *import_string)
{
	char *friend_directory_id_string=otb_unique_id_string_create();
	char *friend_base_path=g_build_filename(bitkeeper->priv->friends_base_path, friend_directory_id_string, NULL);
	OtbFriend *import_friend=otb_friend_import_to_directory(import_string, friend_base_path);
	g_free(friend_base_path);
	g_free(friend_directory_id_string);
	return import_friend;
}

OtbFriend *otb_bitkeeper_import_friend(OtbBitkeeper *bitkeeper, const char *import_string)
{
	otb_bitkeeper_lock_write(bitkeeper);
	OtbFriend *import_friend=otb_bitkeeper_import_friend_to_disk(bitkeeper, import_string);
	const OtbUniqueId *import_unique_id;
	g_object_get(import_friend, OTB_FRIEND_PROP_UNIQUE_ID, &import_unique_id, NULL);
	OtbFriend *duplicate_friend=otb_bitkeeper_get_friend(bitkeeper, import_unique_id);
	if(duplicate_friend==NULL)
		bitkeeper->priv->friends=g_slist_prepend(bitkeeper->priv->friends, import_friend);
	else
	{
		otb_friend_delete(import_friend);
		g_object_unref(duplicate_friend);
		g_object_unref(import_friend);
		import_friend=NULL;
	}
	otb_bitkeeper_unlock_write(bitkeeper);
	return import_friend;
}

gboolean otb_bitkeeper_remove_friend(OtbBitkeeper *bitkeeper, const OtbUniqueId *unique_id)
{
	gboolean ret_val;
	OtbFriend *friend_to_delete=otb_bitkeeper_get_friend(bitkeeper, unique_id);
	if(friend_to_delete==NULL)
		ret_val=FALSE;
	else
	{
		ret_val=otb_friend_delete(friend_to_delete);
		bitkeeper->priv->friends=g_slist_remove(bitkeeper->priv->friends, friend_to_delete);
		g_object_unref(friend_to_delete);
	}
	return ret_val;
}

GSList *otb_bitkeeper_get_ids_of_friends(const OtbBitkeeper *bitkeeper)
{
	GSList *selected_friend_ids=NULL;
	otb_bitkeeper_lock_read(bitkeeper);
	for(const GSList *curr_element=bitkeeper->priv->friends; curr_element!=NULL; curr_element=(const GSList*)g_list_next(curr_element))
	{
		OtbFriend *friend=OTB_FRIEND(curr_element->data);
		OtbUniqueId *unique_id=NULL;
		g_object_get(friend, OTB_FRIEND_PROP_UNIQUE_ID, &unique_id, NULL);
		selected_friend_ids=g_slist_prepend(selected_friend_ids, unique_id);
	}
	otb_bitkeeper_unlock_read(bitkeeper);
	return selected_friend_ids;
}
