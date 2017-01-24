/**
 * Copyright © 2015 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <glib/gi18n.h>

#include "bitkeeper.h"
#include "local-crypto.h"
#include "settings.h"
#include "user.h"

#define CONFIG_GROUP						"user"
#define CONFIG_UNIQUE_ID					"unique-id"
#define CONFIG_SYM_CIPHER					"sym-cipher"
#define CONFIG_ASYM_CIPHER_NEW_KEY_SIZE		"asym-cipher-new-key-size"
#define CONFIG_ASYM_CIPHER_PRIVATE_KEY_IV	"asym-cipher-private-key-iv"
#define CONFIG_ASYM_CIPHER_PRIVATE_KEY		"asym-cipher-private-key"
#define CONFIG_ADDRESS						"address"
#define CONFIG_PORT							"port"

static GType otb_user_runtime_type;

enum
{
	PROP_0,
	PROP_UNIQUE_ID,
	PROP_ASYM_CIPHER,
	PROP_ADDRESS,
	PROP_PORT
};

static gboolean otb_user_load_from_settings(OtbUser *user);
static void otb_user_export_key_file(const OtbUser *user, GKeyFile *export_key_file);
static void otb_user_dispose(GObject *object);
static void otb_user_finalize(GObject *object);
static void otb_user_set_property(GObject *object, unsigned int prop_id, const GValue *value, GParamSpec *pspec);
static void otb_user_get_property(GObject *object, unsigned int prop_id, GValue *value, GParamSpec *pspec);

G_DEFINE_TYPE(OtbUser, otb_user, G_TYPE_OBJECT);

struct _OtbUserPrivate
{
	GRWLock lock;
	OtbUniqueId *unique_id;
	OtbAsymCipher *asym_cipher;
	char *address;
	unsigned int port;
};

static void otb_user_class_init(OtbUserClass *klass)
{
	klass->otb_user_load_from_settings_private=otb_user_load_from_settings;
	klass->otb_user_export_key_file_private=otb_user_export_key_file;
	GObjectClass *object_class=G_OBJECT_CLASS(klass);
	object_class->dispose=otb_user_dispose;
	object_class->finalize=otb_user_finalize;
	object_class->set_property=otb_user_set_property;
	object_class->get_property=otb_user_get_property;
	g_object_class_install_property(object_class, PROP_UNIQUE_ID, g_param_spec_boxed(OTB_USER_PROP_UNIQUE_ID, _("Unique ID"), _("UUID of the user"), OTB_TYPE_UNIQUE_ID, G_PARAM_READABLE));
	g_object_class_install_property(object_class, PROP_ASYM_CIPHER, g_param_spec_object(OTB_USER_PROP_ASYM_CIPHER, _("Asymetrical cipher"), _("Asymetrical cipher that is used to identify the user and communicate with friends"), OTB_TYPE_ASYM_CIPHER, G_PARAM_READABLE));
	g_object_class_install_property(object_class, PROP_ADDRESS, g_param_spec_string(OTB_USER_PROP_ADDRESS, _("Address"), _("The address of the user"), NULL, G_PARAM_READWRITE));
	g_object_class_install_property(object_class, PROP_PORT, g_param_spec_uint(OTB_USER_PROP_PORT, _("Port"), _("The port of the user"), 1, G_MAXUSHORT, OTB_USER_DEFAULT_PORT, G_PARAM_READWRITE));
	g_type_class_add_private(klass, sizeof(OtbUserPrivate));
}

static GType *otb_user_get_runtime_type()
{
	static long otb_user_runtime_path_initialized=FALSE;
	if(G_UNLIKELY(g_once_init_enter(&otb_user_runtime_path_initialized)))
	{
		otb_user_runtime_type=OTB_TYPE_USER;
		g_once_init_leave(&otb_user_runtime_path_initialized, TRUE);
	}
	return &otb_user_runtime_type;
}

static void otb_user_init(OtbUser *user)
{
	user->priv=G_TYPE_INSTANCE_GET_PRIVATE(user, OTB_TYPE_USER, OtbUserPrivate);
	g_rw_lock_init(&user->priv->lock);
	user->priv->unique_id=NULL;
	user->priv->asym_cipher=NULL;
	user->priv->address=NULL;
	user->priv->port=OTB_USER_DEFAULT_PORT;
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
	otb_unique_id_unref(user->priv->unique_id);
	g_free(user->priv->address);
	G_OBJECT_CLASS(otb_user_parent_class)->finalize(object);
}

void otb_user_lock_read(const OtbUser *user)
{
	g_rw_lock_reader_lock(&user->priv->lock);
}

void otb_user_unlock_read(const OtbUser *user)
{
	g_rw_lock_reader_unlock(&user->priv->lock);
}

void otb_user_lock_write(const OtbUser *user)
{
	g_rw_lock_writer_lock(&user->priv->lock);
}

void otb_user_unlock_write(const OtbUser *user)
{
	g_rw_lock_writer_unlock(&user->priv->lock);
}

static void otb_user_set_property(GObject *object, unsigned int prop_id, const GValue *value, GParamSpec *pspec)
{
	OtbUser *user=OTB_USER(object);
	otb_user_lock_write(user);
	switch(prop_id)
	{
		case PROP_ADDRESS:
		{
			g_free(user->priv->address);
			user->priv->address=g_value_dup_string(value);
			break;
		}
		case PROP_PORT:
		{
			user->priv->port=g_value_get_uint(value);
			break;
		}
		default:
		{
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
		}
	}
	otb_user_unlock_write(user);
}

static void otb_user_get_property(GObject *object, unsigned int prop_id, GValue *value, GParamSpec *pspec)
{
	OtbUser *user=OTB_USER(object);
	switch(prop_id)
	{
		case PROP_UNIQUE_ID:
		{
			g_value_set_boxed(value, user->priv->unique_id);
			break;
		}
		case PROP_ASYM_CIPHER:
		{
			g_value_set_object(value, user->priv->asym_cipher);
			break;
		}
		case PROP_ADDRESS:
		{
			otb_user_lock_read(user);
			g_value_set_string(value, user->priv->address);
			otb_user_unlock_read(user);
			break;
		}
		case PROP_PORT:
		{
			otb_user_lock_read(user);
			g_value_set_uint(value, (unsigned int)user->priv->port);
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

static gboolean otb_user_initialize_unique_id(OtbUser *user)
{
	otb_unique_id_unref(user->priv->unique_id);
	user->priv->unique_id=otb_unique_id_new();
	return otb_settings_set_config_bytes(CONFIG_GROUP, CONFIG_UNIQUE_ID, otb_unique_id_get_bytes(user->priv->unique_id), OTB_UNIQUE_ID_BYTES_SIZE);
}

static gboolean otb_user_initialize_asym_cipher(OtbUser *user, unsigned int key_size)
{
	gboolean success=FALSE;
	user->priv->asym_cipher=g_object_new(OTB_TYPE_ASYM_CIPHER, NULL);
	char *sym_cipher_name;
	g_object_get(user->priv->asym_cipher, OTB_ASYM_CIPHER_PROP_SYM_CIPHER_NAME, &sym_cipher_name, NULL);
	if(G_LIKELY(otb_settings_set_config_string(CONFIG_GROUP, CONFIG_SYM_CIPHER, sym_cipher_name) && otb_settings_set_config_uint(CONFIG_GROUP, CONFIG_ASYM_CIPHER_NEW_KEY_SIZE, key_size) && otb_asym_cipher_generate_random_keys(user->priv->asym_cipher, key_size)))
	{
		OtbSymCipher *local_crypto_sym_cipher=otb_local_crypto_get_sym_cipher_with_ref();
		GBytes *private_key_iv;
		GBytes *encrypted_private_key=otb_asym_cipher_get_encrypted_private_key(user->priv->asym_cipher, local_crypto_sym_cipher, &private_key_iv);
		if(G_LIKELY(otb_settings_set_config_gbytes(CONFIG_GROUP, CONFIG_ASYM_CIPHER_PRIVATE_KEY_IV, private_key_iv) && otb_settings_set_config_gbytes(CONFIG_GROUP, CONFIG_ASYM_CIPHER_PRIVATE_KEY, encrypted_private_key)))
			success=TRUE;
		g_bytes_unref(encrypted_private_key);
		g_bytes_unref(private_key_iv);
		g_object_unref(local_crypto_sym_cipher);
	}
	if(!success)
	{
		OtbAsymCipher *asym_cipher=user->priv->asym_cipher;
		user->priv->asym_cipher=NULL;
		g_object_unref(asym_cipher);
	}
	g_free(sym_cipher_name);
	return success;
}

void otb_user_set_runtime_type(GType user_runtime_type)
{
	g_return_if_fail(g_type_is_a(user_runtime_type, OTB_TYPE_USER));
	*otb_user_get_runtime_type()=user_runtime_type;
}

gboolean otb_user_exists()
{
	return otb_settings_config_group_exists(CONFIG_GROUP);
}

OtbUser *otb_user_create(unsigned int key_size)
{
	OtbUser *user=g_object_new(*otb_user_get_runtime_type(), NULL);
	if(G_UNLIKELY(!otb_user_initialize_unique_id(user) || !otb_user_initialize_asym_cipher(user, key_size)))
	{
		g_object_unref(user);
		user=NULL;
	}
	return user;
}

static gboolean otb_user_load_unique_id(OtbUser *user)
{
	gboolean ret_val=FALSE;
	otb_unique_id_unref(user->priv->unique_id);
	size_t bytes_length;
	unsigned char *unique_id_bytes=otb_settings_get_config_bytes(CONFIG_GROUP, CONFIG_UNIQUE_ID, &bytes_length);
	if(G_LIKELY(unique_id_bytes!=NULL && bytes_length==OTB_UNIQUE_ID_BYTES_SIZE))
	{
		user->priv->unique_id=otb_unique_id_from_bytes(unique_id_bytes);
		ret_val=TRUE;
	}
	else
		otb_unique_id_unref(user->priv->unique_id);
	g_free(unique_id_bytes);
	return ret_val;
}


static gboolean otb_user_load_asym_cipher(OtbUser *user)
{
	gboolean success=FALSE;
	char *sym_cipher_name=otb_settings_get_config_string(CONFIG_GROUP, CONFIG_SYM_CIPHER);
	GBytes *private_key_iv=otb_settings_get_config_gbytes(CONFIG_GROUP, CONFIG_ASYM_CIPHER_PRIVATE_KEY_IV);
	GBytes *encrypted_private_key=otb_settings_get_config_gbytes(CONFIG_GROUP, CONFIG_ASYM_CIPHER_PRIVATE_KEY);
	if(G_LIKELY(sym_cipher_name!=NULL && private_key_iv!=NULL && encrypted_private_key!=NULL))
	{
		if(user->priv->asym_cipher!=NULL)
			g_object_unref(user->priv->asym_cipher);
		user->priv->asym_cipher=g_object_new(OTB_TYPE_ASYM_CIPHER, NULL);
		g_object_set(user->priv->asym_cipher, OTB_ASYM_CIPHER_PROP_SYM_CIPHER_NAME, sym_cipher_name, NULL);
		OtbSymCipher *local_crypto_sym_cipher=otb_local_crypto_get_sym_cipher_with_ref();
		otb_asym_cipher_set_encrypted_private_key(user->priv->asym_cipher, encrypted_private_key, local_crypto_sym_cipher, private_key_iv);
		success=TRUE;
		g_object_unref(local_crypto_sym_cipher);
	}
	g_bytes_unref(encrypted_private_key);
	g_bytes_unref(private_key_iv);
	g_free(sym_cipher_name);
	return success;
}

#define otb_user_load_address(user)		(((user)->priv->address=otb_settings_get_config_string(CONFIG_GROUP, CONFIG_ADDRESS))!=NULL)
#define otb_user_load_port(user)		(((user)->priv->port=otb_settings_get_config_uint(CONFIG_GROUP, CONFIG_PORT, 0))!=0)

static gboolean otb_user_load_from_settings(OtbUser *user)
{
	return otb_user_load_unique_id(user) && otb_user_load_asym_cipher(user) && otb_user_load_address(user) && otb_user_load_port(user);
}

OtbUser *otb_user_load()
{
	if(G_UNLIKELY(!otb_user_exists()))
		return NULL;
	OtbUser *user=g_object_new(*otb_user_get_runtime_type(), NULL);
	if(G_UNLIKELY(!OTB_USER_GET_CLASS(user)->otb_user_load_from_settings_private(user)))
	{
		g_object_unref(user);
		user=NULL;
	}
	return user;
}

gboolean otb_user_save(const OtbUser *user)
{
	otb_user_lock_read(user);
	gboolean ret_val=otb_settings_set_config_uint(CONFIG_GROUP, CONFIG_PORT, user->priv->port) && otb_settings_set_config_string(CONFIG_GROUP, CONFIG_ADDRESS, user->priv->address);
	otb_user_unlock_read(user);
	return ret_val;
}

#define otb_user_export_unique_id(user, export_key_file)	(otb_settings_set_bytes((export_key_file), OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_UNIQUE_ID, otb_unique_id_get_bytes((user)->priv->unique_id), OTB_UNIQUE_ID_BYTES_SIZE))

static void otb_user_export_public_key(const OtbUser *user, GKeyFile *export_key_file)
{
	char *public_key;
	g_object_get(user->priv->asym_cipher, OTB_ASYM_CIPHER_PROP_PUBLIC_KEY, &public_key, NULL);
	g_key_file_set_string(export_key_file, OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_PUBLIC_KEY, public_key);
	g_free(public_key);
}

static void otb_user_export_transport_cipher_name(const OtbUser *user, GKeyFile *export_key_file)
{
	char *transport_cipher_name;
	g_object_get(user->priv->asym_cipher, OTB_ASYM_CIPHER_PROP_SYM_CIPHER_NAME, &transport_cipher_name, NULL);
	g_key_file_set_string(export_key_file, OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_TRANSPORT_CIPHER_NAME, transport_cipher_name);
	g_free(transport_cipher_name);
}

#define otb_user_export_address(user, export_key_file)	(g_key_file_set_string((export_key_file), OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_ADDRESS, (user)->priv->address))
#define otb_user_export_port(user, export_key_file)	(g_key_file_set_integer((export_key_file), OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_PORT, (int)(user)->priv->port))

static void otb_user_export_key_file(const OtbUser *user, GKeyFile *export_key_file)
{
	otb_user_export_unique_id(user, export_key_file);
	otb_user_export_public_key(user, export_key_file);
	otb_user_export_transport_cipher_name(user, export_key_file);
	otb_user_export_address(user, export_key_file);
	otb_user_export_port(user, export_key_file);
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
