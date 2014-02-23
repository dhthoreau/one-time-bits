/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <glib/gi18n.h>

#include "io.h"
#include "local-crypto.h"
#include "memory.h"
#include "pad-rec.h"
#include "random.h"
#include "settings.h"
#include "smem.h"

#define INPUT_BUFFER_SIZE	4096
#define UNIQUE_ID_STR_BYTES	37

struct _OtbPadRecPrivate
{
	uuid_t *unique_id;
	OtbPadRecStatus status;
	char *base_path;
	char *base_name;
	char *pad_rec_file_path;
	char *pad_file_path;
	off_t size;
	GBytes *pad_iv;
};

struct _OtbPadIO
{
	gboolean is_for_write;
	gboolean auto_rewind;
	FILE *file;
	unsigned char *input_buffer;
	unsigned char *output_buffer;
	unsigned char *final_output_buffer;
	size_t output_buffer_allocated_size;
	size_t final_output_buffer_allocated_size;
	size_t output_buffer_size;
	size_t final_output_buffer_size;
	size_t output_buffer_position;
	GBytes *pad_iv;
	OtbSymCipherContext *sym_cipher_context;
};

enum
{
	PROP_0,
	PROP_UNIQUE_ID,
	PROP_STATUS,
	PROP_BASE_PATH,
	PROP_BASE_NAME,
	PROP_SIZE
};

static void otb_pad_rec_finalize(GObject *object);
static void otb_pad_rec_set_property(GObject *object, unsigned int prop_id, const GValue *value, GParamSpec *pspec);
static void otb_pad_rec_get_property(GObject *object, unsigned int prop_id, GValue *value, GParamSpec *pspec);

G_DEFINE_TYPE(OtbPadRec, otb_pad_rec, G_TYPE_OBJECT);

static void otb_pad_rec_class_init(OtbPadRecClass *klass)
{
	GObjectClass *object_class=G_OBJECT_CLASS(klass);
	object_class->finalize=otb_pad_rec_finalize;
	object_class->set_property=otb_pad_rec_set_property;
	object_class->get_property=otb_pad_rec_get_property;
	g_object_class_install_property(object_class, PROP_UNIQUE_ID, g_param_spec_pointer(OTB_PAD_REC_PROP_UNIQUE_ID, _("Unique ID"), _("UUID of the record"), G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property(object_class, PROP_STATUS, g_param_spec_uint(OTB_PAD_REC_PROP_STATUS, _("Status"), _("Status of the record"), 0, OTB_PAD_REC_STATUS_OUT_OF_BOUNDS-1, OTB_PAD_REC_STATUS_UNSENT, G_PARAM_READWRITE | G_PARAM_CONSTRUCT));
	g_object_class_install_property(object_class, PROP_BASE_PATH, g_param_spec_string(OTB_PAD_REC_PROP_BASE_PATH, _("Base path"), _("Directory where the record will be saved"), NULL, G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property(object_class, PROP_BASE_NAME, g_param_spec_string(OTB_PAD_REC_PROP_BASE_NAME, _("Base name"), _("Name of file where the record will be saved, excluding file extension"), NULL, G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property(object_class, PROP_SIZE, g_param_spec_int64(OTB_PAD_REC_PROP_SIZE, _("Size"), _("Size of the pad file"), -1, G_MAXINT64, -1, G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY));
	g_type_class_add_private(klass, sizeof(OtbPadRecPrivate));
}

static void otb_pad_generate_unique_id(OtbPadRec *pad_rec)
{
	pad_rec->priv->unique_id=g_malloc(sizeof(uuid_t));
	uuid_generate(*pad_rec->priv->unique_id);
	pad_rec->priv->base_path=NULL;
}

static void otb_pad_generate_base_name(OtbPadRec *pad_rec)
{
	uuid_t base_name_unique_id;
	uuid_generate(base_name_unique_id);
	pad_rec->priv->base_name=g_malloc(UNIQUE_ID_STR_BYTES);
	uuid_unparse_lower(base_name_unique_id, pad_rec->priv->base_name);
}

static void otb_pad_rec_init(OtbPadRec *pad_rec)
{
	pad_rec->priv=G_TYPE_INSTANCE_GET_PRIVATE(pad_rec, OTB_TYPE_PAD_REC, OtbPadRecPrivate);
	otb_pad_generate_unique_id(pad_rec);
	otb_pad_generate_base_name(pad_rec);
	pad_rec->priv->pad_rec_file_path=NULL;
	pad_rec->priv->pad_file_path=NULL;
	pad_rec->priv->size=-1;
	pad_rec->priv->pad_iv=g_bytes_new_static("", 0);
}

static void otb_pad_rec_finalize(GObject *object)
{
	g_return_if_fail(object!=NULL);
	g_return_if_fail(OTB_IS_PAD_REC(object));
	OtbPadRec *pad_rec=OTB_PAD_REC(object);
	g_bytes_unref(pad_rec->priv->pad_iv);
	g_free(pad_rec->priv->unique_id);
	g_free(pad_rec->priv->base_path);
	g_free(pad_rec->priv->base_name);
	g_free(pad_rec->priv->pad_rec_file_path);
	g_free(pad_rec->priv->pad_file_path);
	G_OBJECT_CLASS(otb_pad_rec_parent_class)->finalize(object);
}

static void otb_pad_rec_compute_file_paths(const OtbPadRec *pad_rec)
{
	if(pad_rec->priv->base_path!=NULL)
	{
		char *file_path_without_extension=g_build_filename(pad_rec->priv->base_path, pad_rec->priv->base_name, NULL);
		g_free(pad_rec->priv->pad_rec_file_path);
		pad_rec->priv->pad_rec_file_path=g_strconcat(file_path_without_extension, ".rec", NULL);
		g_free(pad_rec->priv->pad_file_path);
		pad_rec->priv->pad_file_path=g_strconcat(file_path_without_extension, ".pad", NULL);
		g_free(file_path_without_extension);
	}
}

static void otb_pad_rec_set_property(GObject *object, unsigned int prop_id, const GValue *value, GParamSpec *pspec)
{
	gpointer pointer_value;
	OtbPadRec *pad_rec=OTB_PAD_REC(object);
	switch(prop_id)
	{
		case PROP_UNIQUE_ID:
			pointer_value=g_value_get_pointer(value);
			if(pointer_value!=NULL)
				uuid_copy(*pad_rec->priv->unique_id, pointer_value);
			break;
		case PROP_STATUS:
			pad_rec->priv->status=g_value_get_uint(value);
			break;
		case PROP_BASE_PATH:
			g_free(pad_rec->priv->base_path);
			pad_rec->priv->base_path=g_value_dup_string(value);
			otb_pad_rec_compute_file_paths(pad_rec);
			break;
		case PROP_BASE_NAME:
			if(g_value_get_string(value)!=NULL)
			{
				g_free(pad_rec->priv->base_name);
				pad_rec->priv->base_name=g_value_dup_string(value);
				otb_pad_rec_compute_file_paths(pad_rec);
			}
			break;
		case PROP_SIZE:
			pad_rec->priv->size=g_value_get_int64(value);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
	}
}

static void otb_pad_rec_get_property(GObject *object, unsigned int prop_id, GValue *value, GParamSpec *pspec)
{
	OtbPadRec *pad_rec=OTB_PAD_REC(object);
	switch(prop_id)
	{
		case PROP_STATUS:
			g_value_set_uint(value, pad_rec->priv->status);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
	}
}
const gchar *otb_pad_rec_get_base_name(const OtbPadRec *pad_rec)
{
	return pad_rec->priv->base_name;
}

const uuid_t *otb_pad_rec_get_unique_id(const OtbPadRec *pad_rec)
{
	return (const uuid_t*)pad_rec->priv->unique_id;
}

int otb_pad_rec_compare_by_id(gpointer p_pad_rec, gpointer p_unique_id)
{
	const OtbPadRec *pad_rec=OTB_PAD_REC(p_pad_rec);
	const uuid_t *unique_id=(const uuid_t*)p_unique_id;
	return uuid_compare(*pad_rec->priv->unique_id, *unique_id);
}

#define SAVE_GROUP			"pad-rec"
#define SAVE_KEY_UNIQUE_ID	"unique-id"
#define SAVE_KEY_STATUS		"status"
#define SAVE_KEY_SIZE		"size"
#define SAVE_KEY_PAD_IV		"pad-iv"

gboolean otb_pad_rec_save(const OtbPadRec *pad_rec)
{
	GKeyFile *key_file=g_key_file_new();
	otb_settings_set_bytes(key_file, SAVE_GROUP, SAVE_KEY_UNIQUE_ID, *pad_rec->priv->unique_id, sizeof *pad_rec->priv->unique_id);
	g_key_file_set_integer(key_file, SAVE_GROUP, SAVE_KEY_STATUS, pad_rec->priv->status);
	g_key_file_set_int64(key_file, SAVE_GROUP, SAVE_KEY_SIZE, pad_rec->priv->size);
	otb_settings_set_gbytes(key_file, SAVE_GROUP, SAVE_KEY_PAD_IV, pad_rec->priv->pad_iv);
	gboolean ret_val=otb_settings_save_key_file(key_file, pad_rec->priv->pad_rec_file_path, "otb_pad_rec_save");
	g_key_file_unref(key_file);
	return ret_val;
}

OtbPadRec *otb_pad_rec_load(const char *base_path, const char *file_name)
{
	gboolean load_successful=TRUE;
	char *base_name=g_strndup(file_name, strlen(file_name)-4);
	OtbPadRec *pad_rec=g_object_new(OTB_TYPE_PAD_REC, OTB_PAD_REC_PROP_BASE_PATH, base_path, OTB_PAD_REC_PROP_BASE_NAME, base_name, NULL);
	g_free(base_name);
	g_free(pad_rec->priv->unique_id);
	pad_rec->priv->unique_id=NULL;
	g_bytes_unref(pad_rec->priv->pad_iv);
	pad_rec->priv->pad_iv=NULL;
	GKeyFile *key_file=otb_settings_load_key_file(pad_rec->priv->pad_rec_file_path);
	if(key_file==NULL)
		load_successful=FALSE;
	else if((pad_rec->priv->unique_id=otb_settings_get_bytes(key_file, SAVE_GROUP, SAVE_KEY_UNIQUE_ID, NULL, "otb_pad_rec_load"))==NULL)
		load_successful=FALSE;
	else if((pad_rec->priv->status=otb_settings_get_int(key_file, SAVE_GROUP, SAVE_KEY_STATUS, -1, "otb_pad_rec_load"))==-1)
		load_successful=FALSE;
	else if((pad_rec->priv->size=otb_settings_get_int64(key_file, SAVE_GROUP, SAVE_KEY_SIZE, -2, "otb_pad_rec_load"))==-2)
		load_successful=FALSE;
	else if((pad_rec->priv->pad_iv=otb_settings_get_gbytes(key_file, SAVE_GROUP, SAVE_KEY_PAD_IV, "otb_pad_rec_load"))==NULL)
		load_successful=FALSE;
	if(key_file!=NULL)
		g_key_file_unref(key_file);
	if(!load_successful)
	{
		g_object_unref(pad_rec);
		pad_rec=NULL;
	}
	return pad_rec;
}

OtbPadIO *otb_pad_rec_open_pad_for_write(const OtbPadRec *pad_rec)
{
	OtbPadIO *pad_io=NULL;
	FILE *file=otb_open_for_write(pad_rec->priv->pad_file_path, "otb_pad_rec_open_pad_for_write");
	if(file!=NULL)
	{
		pad_io=g_malloc(sizeof(OtbPadIO));
		pad_io->pad_iv=NULL;
		pad_io->is_for_write=TRUE;
		pad_io->file=file;
		pad_io->input_buffer=NULL;
		pad_io->output_buffer=otb_sym_cipher_create_encryption_buffer(otb_local_crypto_get_sym_cipher(), INPUT_BUFFER_SIZE, &pad_io->output_buffer_allocated_size);
		pad_io->final_output_buffer=NULL;
		g_bytes_unref(pad_rec->priv->pad_iv);
		pad_io->sym_cipher_context=otb_sym_cipher_init_encryption(otb_local_crypto_get_sym_cipher(), &pad_rec->priv->pad_iv);
		if(!otb_pad_rec_save(pad_rec))
		{
			otb_pad_io_free(pad_io);
			pad_io=NULL;
		}
	}
	return pad_io;
}

OtbPadIO *otb_pad_rec_open_pad_for_read(const OtbPadRec *pad_rec, gboolean auto_rewind)
{
	OtbPadIO *pad_io=NULL;
	FILE *file=otb_open_for_read(pad_rec->priv->pad_file_path, "otb_pad_rec_open_pad_for_read");
	if(file!=NULL)
	{
		pad_io=g_malloc(sizeof(OtbPadIO));
		pad_io->is_for_write=FALSE;
		pad_io->auto_rewind=auto_rewind;
		pad_io->file=file;
		pad_io->input_buffer=g_malloc(INPUT_BUFFER_SIZE);
		pad_io->output_buffer=otb_sym_cipher_create_decryption_buffer(otb_local_crypto_get_sym_cipher(), INPUT_BUFFER_SIZE, &pad_io->output_buffer_allocated_size);
		pad_io->output_buffer_position=0;
		pad_io->output_buffer_size=0;
		pad_io->final_output_buffer=NULL;
		pad_io->pad_iv=pad_rec->priv->pad_iv;
		g_bytes_ref(pad_io->pad_iv);
		pad_io->sym_cipher_context=otb_sym_cipher_init_decryption(otb_local_crypto_get_sym_cipher(), pad_rec->priv->pad_iv);
	}
	return pad_io;
}

off_t otb_pad_rec_get_size(const OtbPadRec *pad_rec)
{
	return pad_rec->priv->size;
}

gboolean otb_pad_rec_generate_pad_file(OtbPadRec *pad_rec)
{
	size_t ret_val=TRUE;
	OtbPadIO *pad_io=otb_pad_rec_open_pad_for_write(pad_rec);
	if(pad_io==NULL)
		ret_val=FALSE;
	else
	{
		char buffer_bytes[INPUT_BUFFER_SIZE];
		for(off_t bytes_remaining=pad_rec->priv->size; bytes_remaining>0 && ret_val; bytes_remaining-=INPUT_BUFFER_SIZE)
		{
			size_t bytes_to_write=(bytes_remaining<=INPUT_BUFFER_SIZE?bytes_remaining:INPUT_BUFFER_SIZE);
			if(!otb_random_bytes(buffer_bytes, bytes_to_write))
				ret_val=FALSE;
			else if(!otb_pad_write(pad_io, buffer_bytes, bytes_to_write))
				ret_val=FALSE;
		}
		otb_pad_io_free(pad_io);
		smemset(buffer_bytes, 0, INPUT_BUFFER_SIZE);
	}
	return ret_val;
}

gboolean otb_pad_rec_delete(const OtbPadRec *pad_rec)
{
	gboolean ret_val=TRUE;
	if(!otb_unlink_if_exists(pad_rec->priv->pad_rec_file_path, "otb_pad_rec_delete"))
		ret_val=FALSE;
	else if(!otb_unlink_if_exists(pad_rec->priv->pad_file_path, "otb_pad_rec_delete"))
		ret_val=FALSE;
	return ret_val;
}

gboolean otb_pad_write(const OtbPadIO *pad_io, const void *input_buffer, size_t input_buffer_size)
{
	gboolean ret_val=TRUE;
	for(int buffer_offset=0; buffer_offset<input_buffer_size && ret_val; buffer_offset+=INPUT_BUFFER_SIZE)
	{
		size_t encrypted_bytes_size=otb_sym_cipher_encrypt(pad_io->sym_cipher_context, input_buffer+buffer_offset, (input_buffer_size-buffer_offset>INPUT_BUFFER_SIZE?INPUT_BUFFER_SIZE:input_buffer_size-buffer_offset), pad_io->output_buffer);
		if(encrypted_bytes_size>0 && !otb_write(pad_io->output_buffer, sizeof(char), encrypted_bytes_size, pad_io->file, "otb_pad_write")==encrypted_bytes_size)
			ret_val=FALSE;
	}
	return ret_val;
}

static void otb_buffer_pad_final_bytes(OtbPadIO *pad_io)
{
	pad_io->final_output_buffer=otb_sym_cipher_create_encryption_buffer(otb_local_crypto_get_sym_cipher(), INPUT_BUFFER_SIZE, &pad_io->final_output_buffer_allocated_size);
	pad_io->final_output_buffer_size=otb_sym_cipher_finish_decrypt(pad_io->sym_cipher_context, pad_io->final_output_buffer);
	if(pad_io->final_output_buffer_size==0)
	{
		g_free(pad_io->final_output_buffer);
		pad_io->final_output_buffer=NULL;
	}
	if(pad_io->auto_rewind)
	{
		pad_io->sym_cipher_context=otb_sym_cipher_init_decryption(otb_local_crypto_get_sym_cipher(), pad_io->pad_iv);
		rewind(pad_io->file);
	}
	else
		pad_io->sym_cipher_context=NULL;
}

static void otb_pad_copy_final_bytes_to_output_buffer_if_needed(OtbPadIO *pad_io)
{
	if(pad_io->final_output_buffer!=NULL && pad_io->output_buffer_position>=pad_io->output_buffer_size)
	{
		memcpy(pad_io->output_buffer, pad_io->final_output_buffer, pad_io->final_output_buffer_size);
		pad_io->output_buffer_size=pad_io->final_output_buffer_size;
		pad_io->output_buffer_position=0;
		g_free(pad_io->final_output_buffer);
		pad_io->final_output_buffer=NULL;
	}
}

static gboolean otb_read_fill_output_buffer(OtbPadIO *pad_io)
{
	gboolean ret_val=FALSE;
	size_t input_buffer_size=otb_read(pad_io->input_buffer, sizeof(char), INPUT_BUFFER_SIZE, pad_io->file, "otb_pad_read");
	if(input_buffer_size>0)
	{
		pad_io->output_buffer_size=otb_sym_cipher_decrypt(pad_io->sym_cipher_context, pad_io->input_buffer, input_buffer_size, pad_io->output_buffer);
		pad_io->output_buffer_position=0;
		if(!otb_file_has_more_bytes(pad_io->file))
			otb_buffer_pad_final_bytes(pad_io);
		ret_val=TRUE;
	}
	if(pad_io->output_buffer_size==0)
	{
		otb_pad_copy_final_bytes_to_output_buffer_if_needed(pad_io);
		ret_val=TRUE;
	}
	return ret_val;
}

gboolean otb_pad_read(OtbPadIO *pad_io, void **output_buffer, size_t *output_buffer_size)
{
	gboolean ret_val=FALSE;
	otb_pad_copy_final_bytes_to_output_buffer_if_needed(pad_io);
	if(pad_io->output_buffer_position<pad_io->output_buffer_size)
	{
		*output_buffer=pad_io->output_buffer+pad_io->output_buffer_position;
		*output_buffer_size=pad_io->output_buffer_size-pad_io->output_buffer_position;
		pad_io->output_buffer_position=pad_io->output_buffer_size;
		ret_val=TRUE;
	}
	else if(otb_pad_has_more_bytes(pad_io) && otb_read_fill_output_buffer(pad_io))
	{
		*output_buffer=pad_io->output_buffer;
		*output_buffer_size=pad_io->output_buffer_size;
		pad_io->output_buffer_position=pad_io->output_buffer_size;
		ret_val=TRUE;
	}
	return ret_val;
}

gboolean otb_pad_read_byte(OtbPadIO *pad_io, unsigned char *output_byte)
{
	gboolean ret_val=TRUE;
	otb_pad_copy_final_bytes_to_output_buffer_if_needed(pad_io);
	if(pad_io->output_buffer_position>=pad_io->output_buffer_size && !otb_read_fill_output_buffer(pad_io))
		ret_val=FALSE;
	else
		*output_byte=pad_io->output_buffer[pad_io->output_buffer_position++];
	return ret_val;
}

gboolean otb_pad_finish_read(const OtbPadIO *pad_io, const void **output_buffer, const size_t *output_buffer_size)
{
	gboolean ret_val=TRUE;
	return ret_val;
}

gboolean otb_pad_has_more_bytes(const OtbPadIO *pad_io)
{
	return pad_io->sym_cipher_context!=NULL || pad_io->output_buffer_position<pad_io->output_buffer_size || pad_io->final_output_buffer!=NULL;
}

gboolean otb_pad_io_free(OtbPadIO *pad_io)
{
	gboolean final_encrypt_successful=TRUE;
	if(pad_io->is_for_write)
	{
		size_t final_encrypted_bytes_size=otb_sym_cipher_finish_encrypt(pad_io->sym_cipher_context, pad_io->output_buffer);
		pad_io->sym_cipher_context=NULL;
		if(final_encrypted_bytes_size>0 && !otb_write(pad_io->output_buffer, sizeof(char), final_encrypted_bytes_size, pad_io->file, "otb_pad_finish_write")==final_encrypted_bytes_size)
			final_encrypt_successful=FALSE;
	}
	if(pad_io->output_buffer!=NULL)
		smemset(pad_io->output_buffer, 0, pad_io->output_buffer_allocated_size);
	if(pad_io->final_output_buffer!=NULL)
		smemset(pad_io->final_output_buffer, 0, pad_io->final_output_buffer_allocated_size);
	gboolean final_close_successful=otb_close(pad_io->file, "otb_pad_free");
	g_free(pad_io->input_buffer);
	g_free(pad_io->output_buffer);
	g_free(pad_io->final_output_buffer);
	g_bytes_unref(pad_io->pad_iv);
	if(pad_io->sym_cipher_context!=NULL)
		otb_sym_cipher_context_free(pad_io->sym_cipher_context);
	g_free(pad_io);
	return final_encrypt_successful && final_close_successful;
}
