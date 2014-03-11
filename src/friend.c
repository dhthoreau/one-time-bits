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
#include "local-crypto.h"
#include "settings.h"
#include "uuid-util.h"

static GType otb_friend_type;

enum
{
	PROP_0,
	PROP_BASE_PATH,
	PROP_INCOMING_PADS,
	PROP_OUTGOING_PADS,
	PROP_UNIQUE_ID,
	PROP_PUBLIC_KEY,
	PROP_ONION_BASE_DOMAIN
};

static void otb_friend_import_key_file(OtbFriend *friend, GKeyFile *import_file);
static void otb_friend_dispose(GObject *object);
static void otb_friend_finalize(GObject *object);
static void otb_friend_set_property(GObject *object, unsigned int prop_id, const GValue *value, GParamSpec *pspec);
static void otb_friend_get_property(GObject *object, unsigned int prop_id, GValue *value, GParamSpec *pspec);

G_DEFINE_TYPE(OtbFriend, otb_friend, G_TYPE_OBJECT);

struct _OtbFriendPrivate
{
	uuid_t *unique_id;
	char *base_path;
	char *base_path_including_unique_id;
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
	otb_friend_type=OTB_TYPE_FRIEND;
	klass->otb_friend_import_key_file_private=otb_friend_import_key_file;
	GObjectClass *object_class=G_OBJECT_CLASS(klass);
	object_class->dispose=otb_friend_dispose;
	object_class->finalize=otb_friend_finalize;
	object_class->set_property=otb_friend_set_property;
	object_class->get_property=otb_friend_get_property;
	g_object_class_install_property(object_class, PROP_BASE_PATH, g_param_spec_string(OTB_FRIEND_PROP_BASE_PATH, _("Base path"), _("Directory where the friend's data will be saved"), NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property(object_class, PROP_INCOMING_PADS, g_param_spec_pointer(OTB_FRIEND_PROP_INCOMING_PADS, _("Incoming pads"), _("Database of incoming pads"), G_PARAM_READABLE));
	g_object_class_install_property(object_class, PROP_OUTGOING_PADS, g_param_spec_pointer(OTB_FRIEND_PROP_OUTGOING_PADS, _("Outgoing pads"), _("Database of outgoing pads"), G_PARAM_READABLE));
	g_object_class_install_property(object_class, PROP_UNIQUE_ID, g_param_spec_pointer(OTB_FRIEND_PROP_UNIQUE_ID, _("Unique ID"), _("UUID of the friend"), G_PARAM_READWRITE));
	g_object_class_install_property(object_class, PROP_PUBLIC_KEY, g_param_spec_string(OTB_FRIEND_PROP_PUBLIC_KEY, _("Public key"), _("Key that is used to identify the friend"), "", G_PARAM_READWRITE));
	g_object_class_install_property(object_class, PROP_ONION_BASE_DOMAIN, g_param_spec_string(OTB_FRIEND_PROP_ONION_BASE_DOMAIN, _("Onion base domain"), _("The domain of the friend's Tor hidden service (minus the \".onion\")"), NULL, G_PARAM_READWRITE));
	g_type_class_add_private(klass, sizeof(OtbFriendPrivate));
}

static void otb_friend_init(OtbFriend *friend)
{
	friend->priv=G_TYPE_INSTANCE_GET_PRIVATE(friend, OTB_TYPE_FRIEND, OtbFriendPrivate);
	friend->priv->unique_id=NULL;
	friend->priv->base_path=NULL;
	friend->priv->base_path_including_unique_id=NULL;
	friend->priv->file_path=NULL;
	friend->priv->incoming_pads=NULL;
	friend->priv->incoming_pads_path=NULL;
	friend->priv->outgoing_pads=NULL;
	friend->priv->outgoing_pads_path=NULL;
	friend->priv->public_key=NULL;
	friend->priv->onion_base_domain=NULL;
	friend->priv->onion_full_domain=NULL;
}

static const OtbPadDb *otb_friend_set_incoming_pads(const OtbFriend *friend, OtbPadDb *incoming_pads)
{
	if(friend->priv->incoming_pads!=NULL)
		g_object_unref(friend->priv->incoming_pads);
	friend->priv->incoming_pads=incoming_pads;
	return incoming_pads;
}

static const OtbPadDb *otb_friend_set_outgoing_pads(const OtbFriend *friend, OtbPadDb *outgoing_pads)
{
	if(friend->priv->outgoing_pads!=NULL)
		g_object_unref(friend->priv->outgoing_pads);
	friend->priv->outgoing_pads=outgoing_pads;
	return outgoing_pads;
}

static void otb_friend_dispose(GObject *object)
{
	g_return_if_fail(object!=NULL);
	g_return_if_fail(OTB_IS_FRIEND(object));
	OtbFriend *friend=OTB_FRIEND(object);
	otb_friend_set_incoming_pads(friend, NULL);
	otb_friend_set_outgoing_pads(friend, NULL);
	G_OBJECT_CLASS(otb_friend_parent_class)->dispose(object);
}

static void otb_friend_finalize(GObject *object)
{
	g_return_if_fail(object!=NULL);
	g_return_if_fail(OTB_IS_FRIEND(object));
	OtbFriend *friend=OTB_FRIEND(object);
	g_free(friend->priv->unique_id);
	g_free(friend->priv->base_path);
	g_free(friend->priv->base_path_including_unique_id);
	g_free(friend->priv->file_path);
	g_free(friend->priv->incoming_pads_path);
	g_free(friend->priv->outgoing_pads_path);
	g_free(friend->priv->public_key);
	g_free(friend->priv->onion_base_domain);
	g_free(friend->priv->onion_full_domain);
	G_OBJECT_CLASS(otb_friend_parent_class)->finalize(object);
}

static void otb_friend_compute_file_paths(const OtbFriend *friend)
{
	if(friend->priv->unique_id!=NULL && friend->priv->base_path!=NULL)
	{
		char unique_id_path[UNIQUE_ID_STR_BYTES];
		uuid_unparse_lower(*friend->priv->unique_id, unique_id_path);
		g_free(friend->priv->base_path_including_unique_id);
		friend->priv->base_path_including_unique_id=g_build_filename(friend->priv->base_path, unique_id_path, NULL);
		g_free(friend->priv->file_path);
		friend->priv->file_path=g_build_filename(friend->priv->base_path_including_unique_id, "friend.otb", NULL);
		g_free(friend->priv->incoming_pads_path);
		friend->priv->incoming_pads_path=g_build_filename(friend->priv->base_path_including_unique_id, "incoming", NULL);
		g_free(friend->priv->outgoing_pads_path);
		friend->priv->outgoing_pads_path=g_build_filename(friend->priv->base_path_including_unique_id, "outgoing", NULL);
	}
}

static void otb_friend_set_unique_id(const OtbFriend *friend, const uuid_t *unique_id)
{
	if(friend->priv->unique_id!=NULL)
		g_error(_("Tried to change unique ID of a friend."));
	if(unique_id==NULL)
		friend->priv->unique_id=NULL;
	else
	{
		friend->priv->unique_id=g_malloc(sizeof(uuid_t));
		uuid_copy(*friend->priv->unique_id, *unique_id);
	}
	otb_friend_compute_file_paths(friend);
}

static void otb_friend_set_base_path(const OtbFriend *friend, const char *base_path)
{
	g_free(friend->priv->base_path);
	friend->priv->base_path=g_strdup(base_path);
	otb_friend_compute_file_paths(friend);
}

static void otb_friend_set_property(GObject *object, unsigned int prop_id, const GValue *value, GParamSpec *pspec)
{
	OtbFriend *friend=OTB_FRIEND(object);
	switch(prop_id)
	{
		case PROP_BASE_PATH:
		{
			otb_friend_set_base_path(friend, g_value_get_string(value));
			break;
		}
		case PROP_UNIQUE_ID:
		{
			otb_friend_set_unique_id(friend, g_value_get_pointer(value));
			break;
		}
		case PROP_PUBLIC_KEY:
		{
			g_free(friend->priv->public_key);
			friend->priv->public_key=g_value_dup_string(value);
			break;
		}
		case PROP_ONION_BASE_DOMAIN:
		{
			g_free(friend->priv->onion_base_domain);
			friend->priv->onion_base_domain=g_value_dup_string(value);
			g_free(friend->priv->onion_full_domain);
			friend->priv->onion_full_domain=g_strconcat(friend->priv->onion_base_domain, ".onion", NULL);
			break;
		}
		default:
		{
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
		}
	}
}

static void otb_friend_get_property(GObject *object, unsigned int prop_id, GValue *value, GParamSpec *pspec)
{
	OtbFriend *friend=OTB_FRIEND(object);
	switch(prop_id)
	{
		case PROP_BASE_PATH:
		{
			g_value_set_string(value, friend->priv->base_path);
			break;
		}
		case PROP_INCOMING_PADS:
		{
			g_value_set_pointer(value, friend->priv->incoming_pads);
			break;
		}
		case PROP_OUTGOING_PADS:
		{
			g_value_set_pointer(value, friend->priv->outgoing_pads);
			break;
		}
		case PROP_UNIQUE_ID:
		{
			g_value_set_pointer(value, friend->priv->unique_id);
			break;
		}
		case PROP_PUBLIC_KEY:
		{
			g_value_set_string(value, friend->priv->public_key);
			break;
		}
		case PROP_ONION_BASE_DOMAIN:
		{
			g_value_set_string(value, friend->priv->onion_base_domain);
			break;
		}
		default:
		{
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
		}
	}
}

#define SAVE_GROUP						"friend"
#define SAVE_KEY_PUBLIC_KEY_IV			"public-key-iv"
#define SAVE_KEY_PUBLIC_KEY				"public-key"
#define SAVE_KEY_ONION_BASE_DOMAIN_IV	"onion-base-domain-iv"
#define SAVE_KEY_ONION_BASE_DOMAIN		"onion-base-domain"

static gboolean otb_friend_save(const OtbFriend *friend)	// FARE - Scrive il file originale da import.
{
	gboolean ret_val=FALSE;
	if(otb_mkdir_with_parents(friend->priv->base_path_including_unique_id))
	{
		GBytes *public_key_iv=NULL;
		GBytes *onion_base_domain_iv=NULL;
		unsigned char *encrypted_public_key=NULL;
		unsigned char *encrypted_onion_base_domain=NULL;
		size_t encrypted_public_key_size;
		size_t encrypted_onion_base_domain_size;
		OtbSymCipher *local_crypto_sym_cipher=otb_local_crypto_get_sym_cipher_with_ref();
		if(friend->priv->public_key!=NULL)
			encrypted_public_key_size=otb_sym_cipher_encrypt(local_crypto_sym_cipher, friend->priv->public_key, strlen(friend->priv->public_key)+1, &public_key_iv, &encrypted_public_key);
		if(friend->priv->onion_base_domain!=NULL)
			encrypted_onion_base_domain_size=otb_sym_cipher_encrypt(local_crypto_sym_cipher, friend->priv->onion_base_domain, strlen(friend->priv->onion_base_domain)+1, &onion_base_domain_iv, &encrypted_onion_base_domain);
		g_object_unref(local_crypto_sym_cipher);
		GKeyFile *key_file=g_key_file_new();
		if(encrypted_public_key!=NULL)
		{
			otb_settings_set_gbytes(key_file, SAVE_GROUP, SAVE_KEY_PUBLIC_KEY_IV, public_key_iv);
			otb_settings_set_bytes(key_file, SAVE_GROUP, SAVE_KEY_PUBLIC_KEY, encrypted_public_key, encrypted_public_key_size);
		}
		if(encrypted_onion_base_domain!=NULL)
		{
			otb_settings_set_gbytes(key_file, SAVE_GROUP, SAVE_KEY_ONION_BASE_DOMAIN_IV, onion_base_domain_iv);
			otb_settings_set_bytes(key_file, SAVE_GROUP, SAVE_KEY_ONION_BASE_DOMAIN, encrypted_onion_base_domain, encrypted_onion_base_domain_size);
		}
		ret_val=otb_settings_save_key_file(key_file, friend->priv->file_path);
		g_key_file_unref(key_file);
		g_bytes_unref(public_key_iv);
		g_bytes_unref(onion_base_domain_iv);
		g_free(encrypted_public_key);
		g_free(encrypted_onion_base_domain);
	}
	return ret_val;
}

static uuid_t *otb_friend_import_unique_id(GKeyFile *import_file)
{
	char *unique_id_string=otb_settings_get_string(import_file, OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_UNIQUE_ID);
	uuid_t *unique_id=g_malloc(sizeof(uuid_t));
	uuid_parse(unique_id_string, *unique_id);
	g_free(unique_id_string);
	return unique_id;
}

#define otb_friend_import_public_key(import_file)			(otb_settings_get_string((import_file), OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_PUBLIC_KEY))
#define otb_friend_import_onion_base_domain(import_file)	(otb_settings_get_string((import_file), OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_ONION_BASE_DOMAIN))

static void otb_friend_import_key_file(OtbFriend *friend, GKeyFile *import_file)
{
	uuid_t *unique_id=otb_friend_import_unique_id(import_file);
	char *public_key=otb_friend_import_public_key(import_file);
	char *onion_base_domain=otb_friend_import_onion_base_domain(import_file);
	g_object_set(friend, OTB_FRIEND_PROP_UNIQUE_ID, unique_id, OTB_FRIEND_PROP_PUBLIC_KEY, public_key, OTB_FRIEND_PROP_ONION_BASE_DOMAIN, onion_base_domain, NULL);
	g_free(unique_id);
	g_free(public_key);
	g_free(onion_base_domain);
}

void otb_friend_set_type(GType friend_type)
{
	g_return_if_fail(OTB_IS_FRIEND_CLASS(friend_type));
	otb_friend_type=friend_type;
}

OtbFriend *otb_friend_import_to_directory(const char *import_string, const char *base_path)
{
	gboolean success=TRUE;
	OtbFriend *friend=g_object_new(otb_friend_type, OTB_FRIEND_PROP_BASE_PATH, base_path, NULL);
	GKeyFile *key_file=g_key_file_new();
	GError *error=NULL;
	if(!g_key_file_load_from_data(key_file, import_string, strlen(import_string), G_KEY_FILE_NONE, &error))
		success=FALSE;
	else
	{
		OTB_FRIEND_GET_CLASS(friend)->otb_friend_import_key_file_private(friend, key_file);
		if(g_file_test(friend->priv->file_path, G_FILE_TEST_EXISTS) || !otb_friend_save(friend) || otb_friend_set_incoming_pads(friend, otb_pad_db_create_in_directory(friend->priv->incoming_pads_path))==NULL || otb_friend_set_outgoing_pads(friend, otb_pad_db_create_in_directory(friend->priv->outgoing_pads_path))==NULL)
			success=FALSE;
	}
	if(!success)
	{
		g_error_free(error);
		g_object_unref(friend);
		friend=NULL;
	}
	g_key_file_unref(key_file);
	return friend;
}

static gboolean otb_friend_load(OtbFriend *friend)
{
	gboolean ret_val=TRUE;
	GKeyFile *key_file=otb_settings_load_key_file(friend->priv->file_path);
	if(key_file==NULL)
		ret_val=FALSE;
	else
	{
		size_t encrypted_public_key_size;
		GBytes *public_key_iv=otb_settings_get_gbytes(key_file, SAVE_GROUP, SAVE_KEY_PUBLIC_KEY_IV);
		void *encrypted_public_key=otb_settings_get_bytes(key_file, SAVE_GROUP, SAVE_KEY_PUBLIC_KEY, &encrypted_public_key_size);
		size_t encrypted_onion_base_domain_size;
		GBytes *onion_base_domain_iv=otb_settings_get_gbytes(key_file, SAVE_GROUP, SAVE_KEY_ONION_BASE_DOMAIN_IV);
		void *encrypted_onion_base_domain=otb_settings_get_bytes(key_file, SAVE_GROUP, SAVE_KEY_ONION_BASE_DOMAIN, &encrypted_onion_base_domain_size);
		g_key_file_unref(key_file);
		void *public_key=NULL;
		void *onion_base_domain=NULL;
		OtbSymCipher *local_crypto_sym_cipher=otb_local_crypto_get_sym_cipher_with_ref();
		if(encrypted_public_key!=NULL && otb_sym_cipher_decrypt(local_crypto_sym_cipher, encrypted_public_key, encrypted_public_key_size, public_key_iv, &public_key)==0)
			ret_val=FALSE;
		else if(encrypted_onion_base_domain!=NULL && otb_sym_cipher_decrypt(local_crypto_sym_cipher, encrypted_onion_base_domain, encrypted_onion_base_domain_size, onion_base_domain_iv, &onion_base_domain)==0)
			ret_val=FALSE;
		g_object_unref(local_crypto_sym_cipher);
		if(ret_val)
			g_object_set(friend, OTB_FRIEND_PROP_PUBLIC_KEY, public_key, OTB_FRIEND_PROP_PUBLIC_KEY, public_key, OTB_FRIEND_PROP_ONION_BASE_DOMAIN, onion_base_domain, NULL);
		g_bytes_unref(public_key_iv);
		g_bytes_unref(onion_base_domain_iv);
		g_free(encrypted_public_key);
		g_free(encrypted_onion_base_domain);
		g_free(public_key);
		g_free(onion_base_domain);
	}
	return ret_val;
}

static gboolean otb_friend_load_databases(const OtbFriend *friend)
{
	gboolean ret_val=TRUE;
	if(otb_friend_set_incoming_pads(friend, otb_pad_db_load_from_directory(friend->priv->incoming_pads_path))==NULL)
		ret_val=FALSE;
	else if(otb_friend_set_outgoing_pads(friend, otb_pad_db_load_from_directory(friend->priv->outgoing_pads_path))==NULL)
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

gboolean otb_friend_set_public_key(OtbFriend *friend, const char *public_key)
{
	g_object_set(friend, OTB_FRIEND_PROP_PUBLIC_KEY, public_key, NULL);
	return otb_friend_save(friend);
}

gboolean otb_friend_set_onion_base_domain(OtbFriend *friend, const char *onion_base_domain)
{
	g_object_set(friend, OTB_FRIEND_PROP_ONION_BASE_DOMAIN, onion_base_domain, NULL);
	return otb_friend_save(friend);
}
