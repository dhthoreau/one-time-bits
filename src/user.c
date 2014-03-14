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
#include "local-crypto.h"
#include "settings.h"
#include "user.h"

#define CONFIG_GROUP						"user"
#define CONFIG_UNIQUE_ID					"unique-id"
#define CONFIG_SYM_CIPHER					"sym-cipher"
#define CONFIG_ASYM_CIPHER_NEW_KEY_SIZE		"asym-cipher-new-key-size"
#define CONFIG_ASYM_CIPHER_PRIVATE_KEY_IV	"asym-cipher-private-key-iv"
#define CONFIG_ASYM_CIPHER_PRIVATE_KEY		"asym-cipher-private-key"
#define CONFIG_ONION_BASE_DOMAIN			"onion-base-domain"

static GType otb_user_runtime_type;

enum
{
	PROP_0,
	PROP_UNIQUE_ID,
	PROP_ASYM_CIPHER,
	PROP_ONION_BASE_DOMAIN
};

static void otb_user_export_key_file(const OtbUser *user, GKeyFile *export_key_file);
static void otb_user_dispose(GObject *object);
static void otb_user_finalize(GObject *object);
static void otb_user_get_property(GObject *object, unsigned int prop_id, GValue *value, GParamSpec *pspec);

G_DEFINE_TYPE(OtbUser, otb_user, G_TYPE_OBJECT);

struct _OtbUserPrivate
{
	GRWLock lock;
	OtbUniqueId *unique_id;
	OtbAsymCipher *asym_cipher;
	char *onion_base_domain;
};

static void otb_user_class_init(OtbUserClass *klass)
{
	klass->otb_user_export_key_file_private=otb_user_export_key_file;
	GObjectClass *object_class=G_OBJECT_CLASS(klass);
	object_class->dispose=otb_user_dispose;
	object_class->finalize=otb_user_finalize;
	object_class->get_property=otb_user_get_property;
	g_object_class_install_property(object_class, PROP_UNIQUE_ID, g_param_spec_pointer(OTB_USER_PROP_UNIQUE_ID, _("Unique ID"), _("UUID of the user"), G_PARAM_READABLE));
	g_object_class_install_property(object_class, PROP_ASYM_CIPHER, g_param_spec_object(OTB_USER_PROP_ASYM_CIPHER, _("Asymetrical cipher"), _("Asymetrical cipher that is used to identify the user and communicate with friends"), OTB_TYPE_ASYM_CIPHER, G_PARAM_READABLE));
	g_object_class_install_property(object_class, PROP_ONION_BASE_DOMAIN, g_param_spec_string(OTB_USER_PROP_ONION_BASE_DOMAIN, _("Onion base domain"), _("The domain of the user's Tor hidden service (minus the \".onion\")"), NULL, G_PARAM_READABLE));
	g_type_class_add_private(klass, sizeof(OtbUserPrivate));
}

static GType *otb_user_get_runtime_type()
{
	static gboolean otb_user_runtime_path_initialized=FALSE;
	if(g_once_init_enter(&otb_user_runtime_path_initialized))
	{
		otb_user_runtime_type=OTB_TYPE_USER;
		g_once_init_leave(&otb_user_runtime_path_initialized, TRUE);
	}
	return &otb_user_runtime_type;
}

static void otb_user_init(OtbUser *user)
{
	user->priv=G_TYPE_INSTANCE_GET_PRIVATE(user, *otb_user_get_runtime_type(), OtbUserPrivate);
	g_rw_lock_init(&user->priv->lock);
	user->priv->unique_id=NULL;
	user->priv->asym_cipher=NULL;
	user->priv->onion_base_domain=NULL;
}

static void otb_user_dispose(GObject *object)
{
	g_return_if_fail(object!=NULL);
	g_return_if_fail(OTB_IS_USER(object));
	OtbUser *user=OTB_USER(object);
	if(user->priv->asym_cipher!=NULL)
	{
		g_object_unref(user->priv->asym_cipher);
		user->priv->asym_cipher=NULL;
	}
	G_OBJECT_CLASS(otb_user_parent_class)->dispose(object);
}

static void otb_user_finalize(GObject *object)
{
	g_return_if_fail(object!=NULL);
	g_return_if_fail(OTB_IS_USER(object));
	OtbUser *user=OTB_USER(object);
	g_rw_lock_clear(&user->priv->lock);
	g_free(user->priv->unique_id);
	g_free(user->priv->onion_base_domain);
	G_OBJECT_CLASS(otb_user_parent_class)->finalize(object);
}

#define otb_user_lock_read(user)	(g_rw_lock_reader_lock(&user->priv->lock))
#define otb_user_unlock_read(user)	(g_rw_lock_reader_unlock(&user->priv->lock))
#define otb_user_lock_write(user)	(g_rw_lock_writer_lock(&user->priv->lock))
#define otb_user_unlock_write(user)	(g_rw_lock_writer_unlock(&user->priv->lock))

static void otb_user_get_property(GObject *object, unsigned int prop_id, GValue *value, GParamSpec *pspec)
{
	OtbUser *user=OTB_USER(object);
	switch(prop_id)
	{
		case PROP_UNIQUE_ID:
		{
			g_value_set_pointer(value, user->priv->unique_id);
			break;
		}
		case PROP_ASYM_CIPHER:
		{
			g_value_set_object(value, user->priv->asym_cipher);
			break;
		}
		case PROP_ONION_BASE_DOMAIN:
		{
			otb_user_lock_read(user);
			g_value_set_string(value, user->priv->onion_base_domain);
			otb_user_unlock_read(user);
			break;
		}
		default:
		{
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
		}
	}
}

static void otb_user_initialize_unique_id(OtbUser *user)
{
	g_free(user->priv->unique_id);
	size_t bytes_length;
	user->priv->unique_id=otb_settings_get_config_bytes(CONFIG_GROUP, CONFIG_UNIQUE_ID, &bytes_length);
	if(user->priv->unique_id==NULL || bytes_length!=sizeof(OtbUniqueId))
	{
		g_free(user->priv->unique_id);
		user->priv->unique_id=otb_unique_id_create();
	}
}

static void otb_user_initialize_asym_cipher(OtbUser *user)
{
	user->priv->asym_cipher=g_object_new(OTB_TYPE_ASYM_CIPHER, NULL);
	char *sym_cipher_name=otb_settings_get_config_string(CONFIG_GROUP, CONFIG_SYM_CIPHER);
	if(sym_cipher_name!=NULL)
		g_object_set(user->priv->asym_cipher, OTB_ASYM_CIPHER_PROP_SYM_CIPHER, sym_cipher_name, NULL);
	g_free(sym_cipher_name);
	GBytes *private_key_iv=otb_settings_get_config_gbytes(CONFIG_GROUP, CONFIG_ASYM_CIPHER_PRIVATE_KEY_IV);
	GBytes *encrypted_private_key=otb_settings_get_config_gbytes(CONFIG_GROUP, CONFIG_ASYM_CIPHER_PRIVATE_KEY);
	if(private_key_iv!=NULL && encrypted_private_key!=NULL)
	{
		OtbSymCipher *sym_cipher=otb_local_crypto_get_sym_cipher_with_ref();
		otb_asym_cipher_set_encrypted_private_key(user->priv->asym_cipher, encrypted_private_key, sym_cipher, private_key_iv);
		g_object_unref(sym_cipher);
	}
	else
	{
		size_t key_size=otb_settings_get_config_uint(CONFIG_GROUP, CONFIG_ASYM_CIPHER_NEW_KEY_SIZE, OTB_ASYM_CIPHER_DEFAULT_KEY_SIZE);
		otb_asym_cipher_generate_random_keys(user->priv->asym_cipher, key_size);
	}
	g_bytes_unref(private_key_iv);
	g_bytes_unref(encrypted_private_key);
}

static void otb_user_initialize_onion_base_domain(OtbUser *user)
{
	user->priv->onion_base_domain=otb_settings_get_config_string(CONFIG_GROUP, CONFIG_ONION_BASE_DOMAIN);
}

void otb_user_set_runtime_type(GType user_runtime_type)
{
	g_return_if_fail(g_type_is_a(user_runtime_type, OTB_TYPE_USER));
	*otb_user_get_runtime_type()=user_runtime_type;
}

OtbUser *otb_user_load_from_settings_config()
{
	OtbUser *user=g_object_new(*otb_user_get_runtime_type(), NULL);
	otb_user_initialize_unique_id(user);
	otb_user_initialize_asym_cipher(user);
	otb_user_initialize_onion_base_domain(user);
	return user;
}

gboolean otb_user_set_onion_base_domain(const OtbUser *user, const char *onion_base_domain)
{
	otb_user_lock_write(user);
	g_free(user->priv->onion_base_domain);
	user->priv->onion_base_domain=g_strdup(onion_base_domain);
	gboolean ret_val=otb_settings_set_config_string(CONFIG_GROUP, CONFIG_ONION_BASE_DOMAIN, user->priv->onion_base_domain);
	otb_user_unlock_write(user);
	return ret_val;
}

#define otb_user_export_unique_id(user, export_key_file)	(otb_settings_set_bytes((export_key_file), OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_UNIQUE_ID, (user)->priv->unique_id, sizeof(OtbUniqueId)))

static void otb_user_export_public_key(const OtbUser *user, GKeyFile *export_key_file)
{
	char *public_key=NULL;
	g_object_get(user->priv->asym_cipher, OTB_ASYM_CIPHER_PROP_PUBLIC_KEY, &public_key, NULL);
	g_key_file_set_string(export_key_file, OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_PUBLIC_KEY, public_key);
	g_free(public_key);
}

#define otb_user_export_onion_base_domain(user, export_key_file)	(g_key_file_set_string((export_key_file), OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_ONION_BASE_DOMAIN, (user)->priv->onion_base_domain))

static void otb_user_export_key_file(const OtbUser *user, GKeyFile *export_key_file)
{
	otb_user_export_unique_id(user, export_key_file);
	otb_user_export_public_key(user, export_key_file);
	otb_user_export_onion_base_domain(user, export_key_file);
}

char *otb_user_export(const OtbUser *user)
{
	GKeyFile *export_key_file=g_key_file_new();
	otb_user_lock_read(user);
	OTB_USER_GET_CLASS(user)->otb_user_export_key_file_private(user, export_key_file);
	otb_user_unlock_read(user);
	char *export_string=g_key_file_to_data(export_key_file, NULL, NULL);
	g_key_file_unref(export_key_file);
	return export_string;
}
