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
#include "friend.h"
#include "io.h"
#include "local-crypto.h"
#include "settings.h"
#include "unique-id.h"

static GType otb_friend_runtime_type;

enum
{
	PROP_0,
	PROP_IMPORT_STRING,
	PROP_BASE_PATH,
	PROP_INCOMING_PAD_DB,
	PROP_OUTGOING_PAD_DB,
	PROP_UNIQUE_ID,
	PROP_PUBLIC_KEY,
	PROP_TRANSPORT_CIPHER_NAME,
	PROP_ADDRESS,
	PROP_PORT
};

static void otb_friend_import_key_file(OtbFriend *friend, GKeyFile *import_key_file);
static void otb_friend_export_key_file(const OtbFriend *friend, GKeyFile *export_key_file);
static void otb_friend_dispose(GObject *object);
static void otb_friend_finalize(GObject *object);
static void otb_friend_set_property(GObject *object, unsigned int prop_id, const GValue *value, GParamSpec *pspec);
static void otb_friend_get_property(GObject *object, unsigned int prop_id, GValue *value, GParamSpec *pspec);

G_DEFINE_TYPE(OtbFriend, otb_friend, G_TYPE_OBJECT);

struct _OtbFriendPrivate
{
	GRWLock lock;
	OtbUniqueId *unique_id;
	char *base_path;
	char *file_path;
	char *incoming_pad_db_path;
	OtbPadDb *incoming_pad_db;
	char *outgoing_pad_db_path;
	OtbPadDb *outgoing_pad_db;
	char *public_key;
	char *transport_cipher_name;
	char *address;
	unsigned short port;
};

static void otb_friend_class_init(OtbFriendClass *klass)
{
	klass->otb_friend_import_key_file_private=otb_friend_import_key_file;
	klass->otb_friend_export_key_file_private=otb_friend_export_key_file;
	GObjectClass *object_class=G_OBJECT_CLASS(klass);
	object_class->dispose=otb_friend_dispose;
	object_class->finalize=otb_friend_finalize;
	object_class->set_property=otb_friend_set_property;
	object_class->get_property=otb_friend_get_property;
	g_object_class_install_property(object_class, PROP_BASE_PATH, g_param_spec_string(OTB_FRIEND_PROP_BASE_PATH, _("Base path"), _("Directory where the friend's data will be saved"), NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property(object_class, PROP_INCOMING_PAD_DB, g_param_spec_object(OTB_FRIEND_PROP_INCOMING_PAD_DB, _("Incoming pads"), _("Database of incoming pads"), OTB_TYPE_PAD_DB, G_PARAM_READABLE));
	g_object_class_install_property(object_class, PROP_OUTGOING_PAD_DB, g_param_spec_object(OTB_FRIEND_PROP_OUTGOING_PAD_DB, _("Outgoing pads"), _("Database of outgoing pads"), OTB_TYPE_PAD_DB, G_PARAM_READABLE));
	g_object_class_install_property(object_class, PROP_UNIQUE_ID, g_param_spec_boxed(OTB_FRIEND_PROP_UNIQUE_ID, _("Unique ID"), _("UUID of the friend"), OTB_TYPE_UNIQUE_ID, G_PARAM_READWRITE));
	g_object_class_install_property(object_class, PROP_PUBLIC_KEY, g_param_spec_string(OTB_FRIEND_PROP_PUBLIC_KEY, _("Public key"), _("Key that is used to identify the friend"), "", G_PARAM_READABLE));
	g_object_class_install_property(object_class, PROP_TRANSPORT_CIPHER_NAME, g_param_spec_string(OTB_FRIEND_PROP_TRANSPORT_CIPHER_NAME, _("Transport cipher"), _("The cipher used for data transport"), "", G_PARAM_READABLE));
	g_object_class_install_property(object_class, PROP_ADDRESS, g_param_spec_string(OTB_FRIEND_PROP_ADDRESS, _("Address"), _("The address of the friend"), NULL, G_PARAM_READABLE));
	g_object_class_install_property(object_class, PROP_PORT, g_param_spec_uint(OTB_FRIEND_PROP_PORT, _("Port"), _("The port of the friend"), 1, G_MAXUSHORT, OTB_BITKEEPER_DEFAULT_USER_PORT, G_PARAM_READABLE));
	g_type_class_add_private(klass, sizeof(OtbFriendPrivate));
}

static void otb_friend_init(OtbFriend *friend)
{
	friend->priv=G_TYPE_INSTANCE_GET_PRIVATE(friend, OTB_TYPE_FRIEND, OtbFriendPrivate);
	g_rw_lock_init(&friend->priv->lock);
	friend->priv->unique_id=NULL;
	friend->priv->base_path=NULL;
	friend->priv->file_path=NULL;
	friend->priv->incoming_pad_db=NULL;
	friend->priv->incoming_pad_db_path=NULL;
	friend->priv->outgoing_pad_db=NULL;
	friend->priv->outgoing_pad_db_path=NULL;
	friend->priv->public_key=NULL;
	friend->priv->transport_cipher_name=NULL;
	friend->priv->address=NULL;
	friend->priv->port=OTB_BITKEEPER_DEFAULT_USER_PORT;
}

static const OtbPadDb *otb_friend_set_incoming_pad_db(const OtbFriend *friend, OtbPadDb *incoming_pad_db)
{
	if(friend->priv->incoming_pad_db!=NULL)
		g_object_unref(friend->priv->incoming_pad_db);
	friend->priv->incoming_pad_db=incoming_pad_db;
	return incoming_pad_db;
}

static const OtbPadDb *otb_friend_set_outgoing_pad_db(const OtbFriend *friend, OtbPadDb *outgoing_pad_db)
{
	if(friend->priv->outgoing_pad_db!=NULL)
		g_object_unref(friend->priv->outgoing_pad_db);
	friend->priv->outgoing_pad_db=outgoing_pad_db;
	return outgoing_pad_db;
}

static void otb_friend_dispose(GObject *object)
{
	g_return_if_fail(object!=NULL);
	g_return_if_fail(OTB_IS_FRIEND(object));
	OtbFriend *friend=OTB_FRIEND(object);
	otb_friend_set_incoming_pad_db(friend, NULL);
	otb_friend_set_outgoing_pad_db(friend, NULL);
	G_OBJECT_CLASS(otb_friend_parent_class)->dispose(object);
}

static void otb_friend_finalize(GObject *object)
{
	g_return_if_fail(object!=NULL);
	g_return_if_fail(OTB_IS_FRIEND(object));
	OtbFriend *friend=OTB_FRIEND(object);
	g_rw_lock_clear(&friend->priv->lock);
	otb_unique_id_unref(friend->priv->unique_id);
	g_free(friend->priv->base_path);
	g_free(friend->priv->file_path);
	g_free(friend->priv->incoming_pad_db_path);
	g_free(friend->priv->outgoing_pad_db_path);
	g_free(friend->priv->public_key);
	g_free(friend->priv->transport_cipher_name);
	g_free(friend->priv->address);
	G_OBJECT_CLASS(otb_friend_parent_class)->finalize(object);
}

static void otb_friend_compute_file_paths(const OtbFriend *friend)
{
	if(friend->priv->base_path!=NULL)
	{
		g_free(friend->priv->file_path);
		friend->priv->file_path=g_build_filename(friend->priv->base_path, "friend.otb", NULL);
		g_free(friend->priv->incoming_pad_db_path);
		friend->priv->incoming_pad_db_path=g_build_filename(friend->priv->base_path, "incoming", NULL);
		g_free(friend->priv->outgoing_pad_db_path);
		friend->priv->outgoing_pad_db_path=g_build_filename(friend->priv->base_path, "outgoing", NULL);
	}
}

static void otb_friend_set_unique_id(const OtbFriend *friend, OtbUniqueId *unique_id)
{
	if(G_UNLIKELY(friend->priv->unique_id!=NULL))
		g_error(_("Tried to change unique ID of a friend."));
	if(unique_id!=NULL)
		friend->priv->unique_id=otb_unique_id_ref(unique_id);
	otb_friend_compute_file_paths(friend);
}

static void otb_friend_set_base_path(const OtbFriend *friend, const char *base_path)
{
	g_free(friend->priv->base_path);
	friend->priv->base_path=g_strdup(base_path);
	otb_friend_compute_file_paths(friend);
}

#define otb_friend_lock_read(friend)	(g_rw_lock_reader_lock(&friend->priv->lock))
#define otb_friend_unlock_read(friend)	(g_rw_lock_reader_unlock(&friend->priv->lock))
#define otb_friend_lock_write(friend)	(g_rw_lock_writer_lock(&friend->priv->lock))
#define otb_friend_unlock_write(friend)	(g_rw_lock_writer_unlock(&friend->priv->lock))

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
			otb_friend_set_unique_id(friend, g_value_get_boxed(value));
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
		case PROP_INCOMING_PAD_DB:
		{
			g_value_set_object(value, friend->priv->incoming_pad_db);
			break;
		}
		case PROP_OUTGOING_PAD_DB:
		{
			g_value_set_object(value, friend->priv->outgoing_pad_db);
			break;
		}
		case PROP_UNIQUE_ID:
		{
			g_value_set_boxed(value, friend->priv->unique_id);
			break;
		}
		case PROP_PUBLIC_KEY:
		{
			otb_friend_lock_read(friend);
			g_value_set_string(value, friend->priv->public_key);
			otb_friend_unlock_read(friend);
			break;
		}
		case PROP_TRANSPORT_CIPHER_NAME:
		{
			otb_friend_lock_read(friend);
			g_value_set_string(value, friend->priv->transport_cipher_name);
			otb_friend_unlock_read(friend);
			break;
		}
		case PROP_ADDRESS:
		{
			otb_friend_lock_read(friend);
			g_value_set_string(value, friend->priv->address);
			otb_friend_unlock_read(friend);
			break;
		}
		case PROP_PORT:
		{
			otb_friend_lock_read(friend);
			g_value_set_uint(value, (unsigned int)friend->priv->port);
			otb_friend_unlock_read(friend);
			break;
		}
		default:
		{
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
		}
	}
}

static void otb_friend_export_key_file(const OtbFriend *friend, GKeyFile *export_file)
{
	otb_settings_set_bytes(export_file, OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_UNIQUE_ID, otb_unique_id_get_bytes(friend->priv->unique_id), OTB_UNIQUE_ID_BYTES_SIZE);
	g_key_file_set_string(export_file, OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_PUBLIC_KEY, friend->priv->public_key);
	g_key_file_set_string(export_file, OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_TRANSPORT_CIPHER_NAME, friend->priv->transport_cipher_name);
	g_key_file_set_string(export_file, OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_ADDRESS, friend->priv->address);
	g_key_file_set_integer(export_file, OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_PORT, (int)friend->priv->port);
}

#define SAVE_GROUP					"friend"
#define SAVE_KEY_IMPORT_STRING_IV	"import-string-iv"
#define SAVE_KEY_IMPORT_STRING		"import-string"

static gboolean otb_friend_save_no_lock(const OtbFriend *friend)
{
	gboolean ret_val=FALSE;
	if(G_LIKELY(otb_mkdir_with_parents(friend->priv->base_path)))
	{
		GKeyFile *export_key_file=g_key_file_new();
		OTB_FRIEND_GET_CLASS(friend)->otb_friend_export_key_file_private(friend, export_key_file);
		char *export_string=g_key_file_to_data(export_key_file, NULL, NULL);
		g_key_file_unref(export_key_file);
		GBytes *import_string_iv;
		size_t encrypted_import_string_size;
		unsigned char *encrypted_import_string;
		OtbSymCipher *local_crypto_sym_cipher=otb_local_crypto_get_sym_cipher_with_ref();
		encrypted_import_string_size=otb_sym_cipher_encrypt(local_crypto_sym_cipher, export_string, strlen(export_string)+1, &import_string_iv, &encrypted_import_string);
		g_free(export_string);
		g_object_unref(local_crypto_sym_cipher);
		GKeyFile *save_key_file=g_key_file_new();
		otb_settings_set_gbytes(save_key_file, SAVE_GROUP, SAVE_KEY_IMPORT_STRING_IV, import_string_iv);
		otb_settings_set_bytes(save_key_file, SAVE_GROUP, SAVE_KEY_IMPORT_STRING, encrypted_import_string, encrypted_import_string_size);
		ret_val=otb_settings_save_key_file(save_key_file, friend->priv->file_path);
		g_key_file_unref(save_key_file);
		g_bytes_unref(import_string_iv);
		g_free(encrypted_import_string);
	}
	else
		ret_val=FALSE;
	return ret_val;
}

gboolean otb_friend_save(const OtbFriend *friend)
{
	otb_friend_lock_read(friend);
	gboolean ret_val=otb_friend_save_no_lock(friend);
	otb_friend_unlock_read(friend);
	return ret_val;
}

#define otb_friend_import_unique_id_bytes(import_file)			(otb_settings_get_bytes((import_file), OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_UNIQUE_ID, NULL))
#define otb_friend_import_public_key(import_file)				(otb_settings_get_string((import_file), OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_PUBLIC_KEY))
#define otb_friend_import_transport_cipher_name(import_file)	(otb_settings_get_string((import_file), OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_TRANSPORT_CIPHER_NAME))
#define otb_friend_import_address(import_file)					(otb_settings_get_string((import_file), OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_ADDRESS))
#define otb_friend_import_port(import_file)						((unsigned short)otb_settings_get_uint((import_file), OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_PORT, OTB_BITKEEPER_DEFAULT_USER_PORT))

static void otb_friend_set_unique_id_no_save(OtbFriend *friend, OtbUniqueId *unique_id)
{
	otb_unique_id_unref(friend->priv->unique_id);
	friend->priv->unique_id=otb_unique_id_ref(unique_id);
}

static void otb_friend_set_public_key_no_save(const OtbFriend *friend, const char *public_key)
{
	g_free(friend->priv->public_key);
	friend->priv->public_key=g_strdup(public_key);
}

static void otb_friend_set_transport_cipher_name_no_save(const OtbFriend *friend, const char *transport_cipher_name)
{
	g_free(friend->priv->transport_cipher_name);
	friend->priv->transport_cipher_name=g_strdup(transport_cipher_name);
}

static void otb_friend_set_address_no_save(const OtbFriend *friend, const char *address)
{
	g_free(friend->priv->address);
	friend->priv->address=g_strdup(address);
}

#define otb_friend_set_port_no_save(friend, port_value)	(friend)->priv->port=(port_value);

static void otb_friend_import_key_file(OtbFriend *friend, GKeyFile *import_file)
{
	unsigned char *unique_id_bytes=otb_friend_import_unique_id_bytes(import_file);
	OtbUniqueId *unique_id=otb_unique_id_from_bytes(unique_id_bytes);
	char *public_key=otb_friend_import_public_key(import_file);
	char *transport_cipher_name=otb_friend_import_transport_cipher_name(import_file);
	char *address=otb_friend_import_address(import_file);
	unsigned short port=otb_friend_import_port(import_file);
	otb_friend_set_unique_id_no_save(friend, unique_id);
	otb_friend_set_public_key_no_save(friend, public_key);
	otb_friend_set_transport_cipher_name_no_save(friend, transport_cipher_name);
	otb_friend_set_address_no_save(friend, address);
	otb_friend_set_port_no_save(friend, port);
	g_free(address);
	g_free(transport_cipher_name);
	g_free(public_key);
	g_free(unique_id_bytes);
	otb_unique_id_unref(unique_id);
}

static GType *otb_friend_get_runtime_type()
{
	static long otb_friend_runtime_path_initialized=FALSE;
	if(G_UNLIKELY(g_once_init_enter(&otb_friend_runtime_path_initialized)))
	{
		otb_friend_runtime_type=OTB_TYPE_FRIEND;
		g_once_init_leave(&otb_friend_runtime_path_initialized, TRUE);
	}
	return &otb_friend_runtime_type;
}

void otb_friend_set_runtime_type(GType friend_runtime_type)
{
	g_return_if_fail(g_type_is_a(friend_runtime_type, OTB_TYPE_FRIEND));
	*otb_friend_get_runtime_type()=friend_runtime_type;
}

OtbFriend *otb_friend_import_to_directory(const char *import_string, const char *base_path)
{
	gboolean success=TRUE;
	OtbFriend *friend=g_object_new(*otb_friend_get_runtime_type(), OTB_FRIEND_PROP_BASE_PATH, base_path, NULL);
	GKeyFile *key_file=otb_settings_load_key_file_from_string(import_string);
	if(G_UNLIKELY(key_file==NULL))
		success=FALSE;
	else
	{
		OTB_FRIEND_GET_CLASS(friend)->otb_friend_import_key_file_private(friend, key_file);
		if(G_UNLIKELY(g_file_test(friend->priv->file_path, G_FILE_TEST_EXISTS) || !otb_friend_save(friend) || otb_friend_set_incoming_pad_db(friend, otb_pad_db_create_in_directory(friend->priv->incoming_pad_db_path))==NULL || otb_friend_set_outgoing_pad_db(friend, otb_pad_db_create_in_directory(friend->priv->outgoing_pad_db_path))==NULL))
			success=FALSE;
	}
	if(G_UNLIKELY(!success))
	{
		g_object_unref(friend);
		friend=NULL;
	}
	g_key_file_unref(key_file);
	return friend;
}

static gboolean otb_friend_load(OtbFriend *friend)
{
	gboolean ret_val=TRUE;
	GKeyFile *settings_key_file=otb_settings_load_key_file_from_file(friend->priv->file_path);
	if(G_UNLIKELY(settings_key_file==NULL))
		ret_val=FALSE;
	else
	{
		size_t encrypted_import_string_size;
		GBytes *import_string_iv=otb_settings_get_gbytes(settings_key_file, SAVE_GROUP, SAVE_KEY_IMPORT_STRING_IV);
		unsigned char *encrypted_import_string=otb_settings_get_bytes(settings_key_file, SAVE_GROUP, SAVE_KEY_IMPORT_STRING, &encrypted_import_string_size);
		g_key_file_unref(settings_key_file);
		OtbSymCipher *local_crypto_sym_cipher=otb_local_crypto_get_sym_cipher_with_ref();
		char *import_string=NULL;
		if(G_UNLIKELY(import_string_iv==NULL || encrypted_import_string==NULL || otb_sym_cipher_decrypt(local_crypto_sym_cipher, encrypted_import_string, encrypted_import_string_size, import_string_iv, (void**)&import_string)==0))
			ret_val=FALSE;
		g_object_unref(local_crypto_sym_cipher);
		if(G_LIKELY(ret_val))
		{
			GKeyFile *import_key_file=otb_settings_load_key_file_from_string(import_string);
			if(G_UNLIKELY(import_key_file==NULL))
				ret_val=FALSE;
			else
			{
				OTB_FRIEND_GET_CLASS(friend)->otb_friend_import_key_file_private(friend, import_key_file);
				g_key_file_unref(import_key_file);
			}
		}
		otb_sym_cipher_dispose_decryption_buffer(import_string);
		g_free(encrypted_import_string);
		g_bytes_unref(import_string_iv);
	}
	return ret_val;
}

static gboolean otb_friend_load_databases(const OtbFriend *friend)
{
	gboolean ret_val=TRUE;
	if(G_UNLIKELY(otb_friend_set_incoming_pad_db(friend, otb_pad_db_load_from_directory(friend->priv->incoming_pad_db_path))==NULL))
		ret_val=FALSE;
	else if(G_UNLIKELY(otb_friend_set_outgoing_pad_db(friend, otb_pad_db_load_from_directory(friend->priv->outgoing_pad_db_path))==NULL))
		ret_val=FALSE;
	return ret_val;
}

OtbFriend *otb_friend_load_from_directory(const char *base_path)
{
	OtbFriend *friend=g_object_new(*otb_friend_get_runtime_type(), OTB_FRIEND_PROP_BASE_PATH, base_path, NULL);
	gboolean load_successful=TRUE;
	if(G_UNLIKELY(!otb_friend_load(friend)))
		load_successful=FALSE;
	else if(G_UNLIKELY(!otb_friend_load_databases(friend)))
		load_successful=FALSE;
	if(G_UNLIKELY(!load_successful))
	{
		g_object_unref(friend);
		friend=NULL;
	}
	return friend;
}

gboolean otb_friend_delete(OtbFriend *friend)
{
	gboolean ret_val=otb_pad_db_delete(friend->priv->incoming_pad_db);
	ret_val=(otb_pad_db_delete(friend->priv->outgoing_pad_db) && ret_val);
	ret_val=otb_delete_dir(friend->priv->base_path) && ret_val;
	return ret_val;
}

gboolean otb_friend_set_public_key(const OtbFriend *friend, const char *public_key)
{
	otb_friend_lock_write(friend);
	otb_friend_set_public_key_no_save(friend, public_key);
	gboolean ret_val=otb_friend_save_no_lock(friend);
	otb_friend_unlock_write(friend);
	return ret_val;
}

gboolean otb_friend_set_transport_cipher_name(const OtbFriend *friend, const char *transport_cipher_name)
{
	otb_friend_lock_write(friend);
	otb_friend_set_transport_cipher_name_no_save(friend, transport_cipher_name);
	gboolean ret_val=otb_friend_save_no_lock(friend);
	otb_friend_unlock_write(friend);
	return ret_val;
}

gboolean otb_friend_set_address(const OtbFriend *friend, const char *address)
{
	otb_friend_lock_write(friend);
	otb_friend_set_address_no_save(friend, address);
	gboolean ret_val=otb_friend_save_no_lock(friend);
	otb_friend_unlock_write(friend);
	return ret_val;
}

gboolean otb_friend_set_port(const OtbFriend *friend, unsigned short port)
{
	otb_friend_lock_write(friend);
	otb_friend_set_port_no_save(friend, port);
	gboolean ret_val=otb_friend_save_no_lock(friend);
	otb_friend_unlock_write(friend);
	return ret_val;
}

gboolean otb_friend_remove_expired_pads(const OtbFriend *friend)
{
	gboolean ret_val=TRUE;
	if(!otb_pad_db_remove_expired_pads(friend->priv->incoming_pad_db))
		ret_val=FALSE;
	if(!otb_pad_db_remove_expired_pads(friend->priv->outgoing_pad_db))
		ret_val=FALSE;
	return ret_val;
}
