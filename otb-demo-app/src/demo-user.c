/**
 * Copyright © 2015 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <glib/gi18n.h>

#include "friend.h"
#include "demo-user.h"

enum
{
	PROP_0,
	PROP_NAME
};

static gboolean otb_demo_user_load_from_settings(OtbUser *user);
static void otb_demo_user_export_key_file(const OtbUser *user, GKeyFile *export_key_file);
static void otb_demo_user_finalize(GObject *object);
static void otb_demo_user_set_property(GObject *object, unsigned int prop_id, const GValue *value, GParamSpec *pspec);
static void otb_demo_user_get_property(GObject *object, unsigned int prop_id, GValue *value, GParamSpec *pspec);

G_DEFINE_TYPE(OtbDemoUser, otb_demo_user, OTB_TYPE_USER);

struct _OtbDemoUserPrivate
{
	char *name;
};

static void otb_demo_user_class_init(OtbDemoUserClass *klass)
{
	OTB_USER_CLASS(klass)->otb_user_load_from_settings_private=otb_demo_user_load_from_settings;
	OTB_USER_CLASS(klass)->otb_user_export_key_file_private=otb_demo_user_export_key_file;
	GObjectClass *object_class=G_OBJECT_CLASS(klass);
	object_class->finalize=otb_demo_user_finalize;
	object_class->set_property=otb_demo_user_set_property;
	object_class->get_property=otb_demo_user_get_property;
	g_object_class_install_property(object_class, PROP_NAME, g_param_spec_string(OTB_DEMO_USER_PROP_NAME, _("Name"), _("The name of the user"), NULL, G_PARAM_READWRITE));
	g_type_class_add_private(klass, sizeof(OtbDemoUserPrivate));
}

static void otb_demo_user_init(OtbDemoUser *user)
{
	user->priv=G_TYPE_INSTANCE_GET_PRIVATE(user, OTB_DEMO_TYPE_USER, OtbDemoUserPrivate);
	user->priv->name=NULL;
}

static void otb_demo_user_finalize(GObject *object)
{
	g_return_if_fail(object!=NULL);
	g_return_if_fail(OTB_DEMO_IS_USER(object));
	OtbDemoUser *user=OTB_DEMO_USER(object);
	g_free(user->priv->name);
	G_OBJECT_CLASS(otb_demo_user_parent_class)->finalize(object);
}

static void otb_demo_user_set_property(GObject *object, unsigned int prop_id, const GValue *value, GParamSpec *pspec)
{
	OtbDemoUser *user=OTB_DEMO_USER(object);
	switch(prop_id)
	{
		case PROP_NAME:
		{
			otb_user_lock_read(OTB_USER(user));
			g_free(user->priv->name);
			user->priv->name=g_value_dup_string(value);
			otb_user_unlock_read(OTB_USER(user));
			break;
		}
		default:
		{
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
		}
	}
}

static void otb_demo_user_get_property(GObject *object, unsigned int prop_id, GValue *value, GParamSpec *pspec)
{
	OtbDemoUser *user=OTB_DEMO_USER(object);
	switch(prop_id)
	{
		case PROP_NAME:
		{
			otb_user_lock_read(OTB_USER(user));
			g_value_set_string(value, user->priv->name);
			otb_user_unlock_read(OTB_USER(user));
			break;
		}
		default:
		{
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
		}
	}
}

#define otb_demo_user_load_name(user)	((OTB_DEMO_USER(user)->priv->name=otb_settings_get_config_string(OTB_DEMO_FRIEND_EXPORT_GROUP, OTB_DEMO_FRIEND_EXPORT_NAME))!=NULL)

static gboolean otb_demo_user_load_from_settings(OtbUser *user)
{
	return OTB_USER_CLASS(otb_demo_user_parent_class)->otb_user_load_from_settings_private(user) && otb_demo_user_load_name(user);
}

static void otb_demo_user_export_key_file(const OtbUser *user, GKeyFile *export_key_file)
{
	OTB_USER_CLASS(otb_demo_user_parent_class)->otb_user_export_key_file_private(user, export_key_file);
	g_key_file_set_string(export_key_file, OTB_DEMO_FRIEND_EXPORT_GROUP, OTB_DEMO_FRIEND_EXPORT_NAME, OTB_DEMO_USER(user)->priv->name);
}

gboolean otb_demo_user_set_name(const OtbDemoUser *user, const char *name)
{
	otb_user_lock_write(OTB_USER(user));
	g_free(user->priv->name);
	user->priv->name=g_strdup(name);
	otb_user_unlock_write(OTB_USER(user));
	gboolean ret_val=otb_settings_set_config_string(OTB_DEMO_FRIEND_EXPORT_GROUP, OTB_DEMO_FRIEND_EXPORT_NAME, user->priv->name);
	return ret_val;
}
