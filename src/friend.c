/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <glib/gi18n.h>

#include "friend.h"
#include "io.h"
#include "settings.h"

enum
{
	PROP_0,
	PROP_UNIQUE_ID,
	PROP_BASE_PATH,
	PROP_INCOMING_PADS,
	PROP_OUTGOING_PADS,
	PROP_PUBLIC_KEY,
	PROP_ONION_BASE_DOMAIN
};

static void otb_friend_dispose(GObject *object);
static void otb_friend_finalize(GObject *object);
static void otb_friend_set_property(GObject *object, unsigned int prop_id, const GValue *value, GParamSpec *pspec);
static void otb_friend_get_property(GObject *object, unsigned int prop_id, GValue *value, GParamSpec *pspec);

G_DEFINE_TYPE(OtbFriend, otb_friend, G_TYPE_OBJECT);

struct _OtbFriendPrivate
{
	uuid_t *unique_id;
	char *base_path;
	char *file_path;
	char *incoming_pads_path;
	OtbPadDb *incoming_pads;
	char *outgoing_pads_path;
	OtbPadDb *outgoing_pads;
	char *public_key;
	char *onion_base_domain;
	char *onion_full_domain;
};

static void otb_friend_class_init(OtbFriendClass *klass)
{
	GObjectClass *object_class=G_OBJECT_CLASS(klass);
	object_class->dispose=otb_friend_dispose;
	object_class->finalize=otb_friend_finalize;
	object_class->set_property=otb_friend_set_property;
	object_class->get_property=otb_friend_get_property;
	g_object_class_install_property(object_class, PROP_UNIQUE_ID, g_param_spec_pointer(OTB_FRIEND_PROP_UNIQUE_ID, _("Unique ID"), _("UUID of the friend"), G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property(object_class, PROP_BASE_PATH, g_param_spec_string(OTB_FRIEND_PROP_BASE_PATH, _("Base path"), _("Directory where the friend's data will be saved"), NULL, G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property(object_class, PROP_INCOMING_PADS, g_param_spec_pointer(OTB_FRIEND_PROP_INCOMING_PADS, _("Incoming pads"), _("Database of incoming pads"), G_PARAM_READABLE));
	g_object_class_install_property(object_class, PROP_OUTGOING_PADS, g_param_spec_pointer(OTB_FRIEND_PROP_OUTGOING_PADS, _("Outgoing pads"), _("Database of outgoing pads"), G_PARAM_READABLE));
	g_object_class_install_property(object_class, PROP_PUBLIC_KEY, g_param_spec_string(OTB_FRIEND_PROP_PUBLIC_KEY, _("Public key"), _("Key that is used to identify the friend"), NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT));
	g_object_class_install_property(object_class, PROP_ONION_BASE_DOMAIN, g_param_spec_string(OTB_FRIEND_PROP_ONION_BASE_DOMAIN, _("Onion base domain"), _("The domain of the friend's Tor hidden service (minus the \".onion\")."), NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT));
	g_type_class_add_private(klass, sizeof(OtbFriendPrivate));
}

static void otb_friend_init(OtbFriend *friend)
{
	friend->priv=G_TYPE_INSTANCE_GET_PRIVATE(friend, OTB_TYPE_FRIEND, OtbFriendPrivate);
	friend->priv->unique_id=NULL;
	friend->priv->base_path=NULL;
	friend->priv->file_path=NULL;
	friend->priv->incoming_pads=NULL;
	friend->priv->incoming_pads_path=NULL;
	friend->priv->outgoing_pads=NULL;
	friend->priv->outgoing_pads_path=NULL;
	friend->priv->public_key=NULL;
	friend->priv->onion_base_domain=NULL;
	friend->priv->onion_full_domain=NULL;
}

static const OtbPadDb *otb_friend_set_incoming_pads_no_save(const OtbFriend *friend, OtbPadDb *incoming_pads)
{
	if(friend->priv->incoming_pads!=NULL)
		g_object_unref(friend->priv->incoming_pads);
	friend->priv->incoming_pads=incoming_pads;
	return incoming_pads;
}

static const OtbPadDb *otb_friend_set_outgoing_pads_no_save(const OtbFriend *friend, OtbPadDb *outgoing_pads)
{
	if(friend->priv->outgoing_pads!=NULL)
		g_object_unref(friend->priv->outgoing_pads);
	friend->priv->outgoing_pads=outgoing_pads;
	return outgoing_pads;
}

static void otb_friend_set_public_key_no_save(const OtbFriend *friend, const char *public_key)
{
	g_free(friend->priv->public_key);
	friend->priv->public_key=g_strdup(public_key);
}

static void otb_friend_set_onion_base_domain_no_save(const OtbFriend *friend, const char *onion_base_domain)
{
	g_free(friend->priv->onion_base_domain);
	friend->priv->onion_base_domain=g_strdup(onion_base_domain);
	g_free(friend->priv->onion_full_domain);
	friend->priv->onion_full_domain=g_strconcat(friend->priv->onion_base_domain, ".onion", NULL);
}

static void otb_friend_dispose(GObject *object)
{
	g_return_if_fail(object!=NULL);
	g_return_if_fail(OTB_IS_FRIEND(object));
	OtbFriend *friend=OTB_FRIEND(object);
	otb_friend_set_incoming_pads_no_save(friend, NULL);
	otb_friend_set_outgoing_pads_no_save(friend, NULL);
	otb_friend_set_public_key_no_save(friend, NULL);
	G_OBJECT_CLASS(otb_friend_parent_class)->dispose(object);
}

static void otb_friend_finalize(GObject *object)
{
	g_return_if_fail(object!=NULL);
	g_return_if_fail(OTB_IS_FRIEND(object));
	OtbFriend *friend=OTB_FRIEND(object);
	g_free(friend->priv->unique_id);
	g_free(friend->priv->base_path);
	g_free(friend->priv->file_path);
	g_free(friend->priv->incoming_pads_path);
	g_free(friend->priv->outgoing_pads_path);
	g_free(friend->priv->onion_base_domain);
	g_free(friend->priv->onion_full_domain);
	G_OBJECT_CLASS(otb_friend_parent_class)->finalize(object);
}

static void otb_friend_set_base_path(const OtbFriend *friend, const char *base_path)
{
	g_free(friend->priv->base_path);
	friend->priv->base_path=g_strdup(base_path);
	g_free(friend->priv->file_path);
	friend->priv->file_path=g_build_filename(base_path, "friend.otb", NULL);
	g_free(friend->priv->incoming_pads_path);
	friend->priv->incoming_pads_path=g_build_filename(base_path, "incoming", NULL);
	g_free(friend->priv->outgoing_pads_path);
	friend->priv->outgoing_pads_path=g_build_filename(base_path, "outgoing", NULL);
}

static void otb_friend_set_property(GObject *object, unsigned int prop_id, const GValue *value, GParamSpec *pspec)
{
	OtbFriend *friend=OTB_FRIEND(object);
	switch(prop_id)
	{
		case PROP_UNIQUE_ID:
			break;
		case PROP_BASE_PATH:
			otb_friend_set_base_path(friend, g_value_get_string(value));
			break;
		case PROP_PUBLIC_KEY:
			break;
		case PROP_ONION_BASE_DOMAIN:
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
	}
}

static void otb_friend_get_property(GObject *object, unsigned int prop_id, GValue *value, GParamSpec *pspec)
{
	OtbFriend *friend=OTB_FRIEND(object);
	switch(prop_id)
	{
		case PROP_UNIQUE_ID:
			g_value_set_pointer(value, friend->priv->unique_id);
			break;
		case PROP_BASE_PATH:
			g_value_set_string(value, friend->priv->base_path);
			break;
		case PROP_INCOMING_PADS:
			g_value_set_pointer(value, friend->priv->incoming_pads);
			break;
		case PROP_OUTGOING_PADS:
			g_value_set_pointer(value, friend->priv->outgoing_pads);
			break;
		case PROP_PUBLIC_KEY:
			g_value_set_string(value, friend->priv->public_key);
			break;
		case PROP_ONION_BASE_DOMAIN:
			g_value_set_string(value, friend->priv->onion_base_domain);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
	}
}

#define SAVE_GROUP					"friend"
#define SAVE_KEY_PUBLIC_KEY			"public-key"
#define SAVE_KEY_ONION_BASE_DOMAIN	"onion-base-domain"

static gboolean otb_friend_save(const OtbFriend *friend)
{
	gboolean ret_val=TRUE;
	if(otb_mkdir_with_parents(friend->priv->base_path, "otb_friend_save"))
	{
		GKeyFile *key_file=g_key_file_new();
		if(friend->priv->public_key!=NULL)
			g_key_file_set_string(key_file, SAVE_GROUP, SAVE_KEY_PUBLIC_KEY, friend->priv->public_key);
		if(friend->priv->onion_base_domain!=NULL)
			g_key_file_set_string(key_file, SAVE_GROUP, SAVE_KEY_ONION_BASE_DOMAIN, friend->priv->onion_base_domain);
		ret_val=otb_settings_save_key_file(key_file, friend->priv->file_path, "otb_friend_save");
		g_key_file_unref(key_file);
	}
	return ret_val;
}

OtbFriend *otb_friend_create_in_directory(const uuid_t *unique_id, const char *base_path)
{
	OtbFriend *friend=g_object_new(OTB_TYPE_FRIEND, OTB_FRIEND_PROP_UNIQUE_ID, unique_id, OTB_FRIEND_PROP_BASE_PATH, base_path, NULL);
	if(g_file_test(friend->priv->file_path, G_FILE_TEST_EXISTS) || !otb_friend_save(friend) || otb_friend_set_incoming_pads_no_save(friend, otb_pad_db_create_in_directory(friend->priv->incoming_pads_path))==NULL || otb_friend_set_outgoing_pads_no_save(friend, otb_pad_db_create_in_directory(friend->priv->outgoing_pads_path))==NULL)
	{
		g_object_unref(friend);
		friend=NULL;
	}
	return friend;
}

static gboolean otb_friend_load(const OtbFriend *friend)
{
	gboolean ret_val=TRUE;
	char *public_key=NULL;
	char *onion_base_domain=NULL;
	GKeyFile *key_file=otb_settings_load_key_file(friend->priv->file_path);
	if(key_file==NULL)
		ret_val=FALSE;
	else if((public_key=otb_settings_get_string(key_file, SAVE_GROUP, SAVE_KEY_PUBLIC_KEY, "otb_friend_load"))==NULL)
		ret_val=FALSE;
	else if((onion_base_domain=otb_settings_get_string(key_file, SAVE_GROUP, SAVE_KEY_ONION_BASE_DOMAIN, "otb_friend_load"))==NULL)
		ret_val=FALSE;
	if(ret_val)
	{
		otb_friend_set_public_key_no_save(friend, public_key);
		otb_friend_set_onion_base_domain_no_save(friend, onion_base_domain);
	}
	g_free(public_key);
	g_free(onion_base_domain);
	if(key_file!=NULL)
		g_key_file_unref(key_file);
	return ret_val;
}

static gboolean otb_friend_load_databases(const OtbFriend *friend)
{
	gboolean ret_val=TRUE;
	if(otb_friend_set_incoming_pads_no_save(friend, otb_pad_db_load_from_directory(friend->priv->incoming_pads_path))==NULL)
		ret_val=FALSE;
	else if(otb_friend_set_outgoing_pads_no_save(friend, otb_pad_db_load_from_directory(friend->priv->outgoing_pads_path))==NULL)
		ret_val=FALSE;
	return ret_val;
}

OtbFriend *otb_friend_load_from_directory(const uuid_t *unique_id, const char *base_path)
{
	OtbFriend *friend=g_object_new(OTB_TYPE_FRIEND, OTB_FRIEND_PROP_UNIQUE_ID, unique_id, OTB_FRIEND_PROP_BASE_PATH, base_path, NULL);
	gboolean load_successful=TRUE;
	if(!otb_friend_load(friend))
		load_successful=FALSE;
	else if(!otb_friend_load_databases(friend))
		load_successful=FALSE;
	if(!load_successful)
	{
		g_object_unref(friend);
		friend=NULL;
	}
	return friend;
}

gboolean otb_friend_set_public_key(const OtbFriend *friend, const char *public_key)
{
	otb_friend_set_public_key_no_save(friend, public_key);
	return otb_friend_save(friend);
}

gboolean otb_friend_set_onion_base_domain(const OtbFriend *friend, const char *onion_base_domain)
{
	otb_friend_set_onion_base_domain_no_save(friend, onion_base_domain);
	return otb_friend_save(friend);
}
