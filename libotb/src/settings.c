/**
 * Copyright © 2015 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <glib.h>
#include <glib/gi18n.h>

#include "io.h"
#include "settings.h"

#define CONFIG_FILE_NAME			"otb.conf"
#define CONFIG_META_GROUP_NAME		"config-meta"
#define FILE_VERSION_KEY			"file-version"
#define CURRENT_CONFIG_FILE_VERSION	0

static char *otb_config_directory_path=NULL;
static char *otb_data_directory_path=NULL;
static GRWLock config_lock;
static GKeyFile *config_key_file=NULL;

#define otb_settings_get_config_file_path()	(g_build_filename(otb_config_directory_path, CONFIG_FILE_NAME, NULL))

static void otb_settings_lock_config_read(){ 	(g_rw_lock_reader_lock(&config_lock));}
static void otb_settings_unlock_config_read(){	(g_rw_lock_reader_unlock(&config_lock));}
static void otb_settings_lock_config_write(){	(g_rw_lock_writer_lock(&config_lock));}
static void otb_settings_unlock_config_write(){	(g_rw_lock_writer_unlock(&config_lock));}

GKeyFile *otb_settings_load_key_file_from_file(const char *file_path)
{
	GKeyFile *key_file=g_key_file_new();
	GError *error=NULL;
	if(G_UNLIKELY(g_file_test(file_path, G_FILE_TEST_EXISTS) && !g_key_file_load_from_file(key_file, file_path, G_KEY_FILE_KEEP_COMMENTS | G_KEY_FILE_KEEP_TRANSLATIONS, &error)))
	{
		g_message(_("Failed to load key file from %s. Error == %s"), file_path, error->message);
		g_error_free(error);
		g_key_file_free(key_file);
		key_file=NULL;
	}
	return key_file;
}

GKeyFile *otb_settings_load_key_file_from_string(const char *string)
{
	GKeyFile *key_file=g_key_file_new();
	GError *error=NULL;
	if(G_UNLIKELY(!g_key_file_load_from_data(key_file, string, strlen(string), G_KEY_FILE_KEEP_COMMENTS | G_KEY_FILE_KEEP_TRANSLATIONS, &error)))
	{
		g_message(_("Failed to load key file from %s. Error == %s"), string, error->message);
		g_error_free(error);
		g_key_file_free(key_file);
		key_file=NULL;
	}
	return key_file;
}

static void otb_settings_load_config_file()
{
	otb_settings_lock_config_write();
	GKeyFile *old_config_key_file=config_key_file;
	char *config_file_path=otb_settings_get_config_file_path();
	config_key_file=otb_settings_load_key_file_from_file(config_file_path);
	otb_settings_unlock_config_write();
	g_free(config_file_path);
	if(old_config_key_file!=NULL)
		g_key_file_unref(old_config_key_file);
	g_key_file_set_integer(config_key_file, CONFIG_META_GROUP_NAME, FILE_VERSION_KEY, CURRENT_CONFIG_FILE_VERSION);
}

static void otb_settings_initialize_directory_paths(const char *app_name, const char *otb_sub_dir)
{
	g_free(otb_config_directory_path);
	g_free(otb_data_directory_path);
	otb_config_directory_path=g_build_filename(g_get_user_config_dir(), app_name, otb_sub_dir, NULL);
	otb_data_directory_path=g_build_filename(g_get_user_data_dir(), app_name, otb_sub_dir, NULL);
}

void otb_settings_initialize(const char *app_name, const char *otb_sub_dir)
{
	static gboolean otb_settings_directory_paths_initialized=FALSE;
	if(G_UNLIKELY(g_once_init_enter(&otb_settings_directory_paths_initialized)))
	{
		bindtextdomain(GETTEXT_PACKAGE, LOCALEDIR);
		otb_settings_initialize_directory_paths(app_name, otb_sub_dir);
		otb_settings_load_config_file();
		g_once_init_leave(&otb_settings_directory_paths_initialized, TRUE);
	}
}

const char *otb_settings_get_config_directory_path()
{
	return otb_config_directory_path;
}

void otb_settings_set_config_directory_path(const char *config_directory_path)
{
	g_free(otb_config_directory_path);
	otb_config_directory_path=g_strdup(config_directory_path);
	otb_settings_load_config_file();
}

const char *otb_settings_get_data_directory_path()
{
	return otb_data_directory_path;
}

void otb_settings_set_data_directory_path(const char *data_directory_path)
{
	g_free(otb_data_directory_path);
	otb_data_directory_path=g_strdup(data_directory_path);
}

gboolean otb_settings_save_key_file(GKeyFile *key_file, const char *file_path)
{
	gboolean ret_val=TRUE;
	gsize key_file_data_size;
	char *key_file_data=g_key_file_to_data(key_file, &key_file_data_size, NULL);
	/// Does not use g_key_file_save_to_file() because of performance problems. g_key_file_save_to_file() tries to write it to a temp file first then copy it over to the target file path. Makes unit tests run terribly slow.
	FILE *file=otb_open_text_for_write(file_path);
	if(G_UNLIKELY(file==NULL))
		ret_val=FALSE;
	else if(G_UNLIKELY(otb_write(key_file_data, sizeof *key_file_data, key_file_data_size, file)!=key_file_data_size))
		ret_val=FALSE;
	if(G_UNLIKELY(!otb_close(file)))
		ret_val=FALSE;
	g_free(key_file_data);
	return ret_val;
}

static gboolean otb_settings_save_config_key_file()
{
	otb_mkdir_with_parents(otb_config_directory_path);
	char *config_file_path=otb_settings_get_config_file_path();
	gboolean ret_val=otb_settings_save_key_file(config_key_file, config_file_path);
	g_free(config_file_path);
	return ret_val;
}

gboolean otb_settings_config_group_exists(const char *group_name)
{
	otb_settings_lock_config_read();
	gboolean exists=(config_key_file!=NULL && g_key_file_has_group(config_key_file, group_name));
	otb_settings_unlock_config_read();
	return exists;
}

gboolean otb_settings_set_config_int(const char *group_name, const char *key, int value)
{
	otb_settings_lock_config_write();
	g_key_file_set_integer(config_key_file, group_name, key, value);
	gboolean ret_val=otb_settings_save_config_key_file();
	otb_settings_unlock_config_write();
	return ret_val;
}

int otb_settings_get_int(GKeyFile *key_file, const char *group_name, const char *key, int error_value)
{
	GError *error=NULL;
	int value=g_key_file_get_integer(key_file, group_name, key, &error);
	if(G_UNLIKELY(error!=NULL))
	{
		value=error_value;
		g_message(_("Failed to read %s / %s from config file. Error == %s"), group_name, key, error->message);
		g_error_free(error);
	}
	return value;
}

int otb_settings_get_config_int(const char *group_name, const char *key, int error_value)
{
	otb_settings_lock_config_read();
	int ret_val=otb_settings_get_int(config_key_file, group_name, key, error_value);
	otb_settings_unlock_config_read();
	return ret_val;
}

gboolean otb_settings_set_config_uint(const char *group_name, const char *key, unsigned int value)
{
	return otb_settings_set_config_int(group_name, key, (int)value);
}

unsigned int otb_settings_get_uint(GKeyFile *key_file, const char *group_name, const char *key, unsigned int error_value)
{
	return (unsigned int)otb_settings_get_int(key_file, group_name, key, (int)error_value);
}

unsigned int otb_settings_get_config_uint(const char *group_name, const char *key, unsigned int error_value)
{
	otb_settings_lock_config_read();
	unsigned int ret_val=otb_settings_get_uint(config_key_file, group_name, key, error_value);
	otb_settings_unlock_config_read();
	return ret_val;
}

gboolean otb_settings_set_config_int64(const char *group_name, const char *key, long long value)
{
	otb_settings_lock_config_write();
	g_key_file_set_int64(config_key_file, group_name, key, value);
	gboolean ret_val=otb_settings_save_config_key_file();
	otb_settings_unlock_config_write();
	return ret_val;
}

long long otb_settings_get_int64(GKeyFile *key_file, const char *group_name, const char *key, long long error_value)
{
	GError *error=NULL;
	long long value=g_key_file_get_int64(key_file, group_name, key, &error);
	if(G_UNLIKELY(error!=NULL))
	{
		value=error_value;
		g_message(_("Failed to read %s / %s from config file. Error == %s"), group_name, key, error->message);
		g_error_free(error);
	}
	return value;
}

long long otb_settings_get_config_int64(const char *group_name, const char *key, long long error_value)
{
	otb_settings_lock_config_read();
	long long ret_val=otb_settings_get_int64(config_key_file, group_name, key, error_value);
	otb_settings_unlock_config_read();
	return ret_val;
}

unsigned long long otb_settings_get_uint64(GKeyFile *key_file, const char *group_name, const char *key, unsigned long long error_value)
{
	GError *error=NULL;
	unsigned long long value=g_key_file_get_uint64(key_file, group_name, key, &error);
	if(G_UNLIKELY(error!=NULL))
	{
		value=error_value;
		g_message(_("Failed to read %s / %s from config file. Error == %s"), group_name, key, error->message);
		g_error_free(error);
	}
	return value;
}

gboolean otb_settings_set_config_string(const char *group_name, const char *key, const char *value)
{
	otb_settings_lock_config_write();
	g_key_file_set_string(config_key_file, group_name, key, value);
	gboolean ret_val=otb_settings_save_config_key_file();
	otb_settings_unlock_config_write();
	return ret_val;
}

char *otb_settings_get_string(GKeyFile *key_file, const char *group_name, const char *key)
{
	GError *error=NULL;
	char *value=g_key_file_get_string(key_file, group_name, key, &error);
	if(G_UNLIKELY(error!=NULL))
	{
		g_free(value);
		g_message(_("Failed to read %s / %s from config file. Error == %s"), group_name, key, error->message);
		g_error_free(error);
	}
	return value;
}

char *otb_settings_get_config_string(const char *group_name, const char *key)
{
	otb_settings_lock_config_read();
	char *ret_val=otb_settings_get_string(config_key_file, group_name, key);
	otb_settings_unlock_config_read();
	return ret_val;
}

void otb_settings_set_bytes(GKeyFile *key_file, const char *group_name, const char *key, const void *value, size_t value_size)
{
	char *encoded_bytes=g_base64_encode(value, value_size);
	g_key_file_set_string(key_file, group_name, key, encoded_bytes);
	g_free(encoded_bytes);
}
gboolean otb_settings_set_config_bytes(const char *group_name, const char *key, const void *value, size_t value_size)
{
	otb_settings_lock_config_write();
	otb_settings_set_bytes(config_key_file, group_name, key, value, value_size);
	gboolean ret_val=otb_settings_save_config_key_file();
	otb_settings_unlock_config_write();
	return ret_val;
}

void *otb_settings_get_bytes(GKeyFile *key_file, const char *group_name, const char *key, size_t *value_size)
{
	char *bytes=otb_settings_get_string(key_file, group_name, key);
	if(G_LIKELY(bytes!=NULL))
	{
		size_t value_size_temp;
		if(bytes[0])
			g_base64_decode_inplace(bytes, &value_size_temp);
		if(value_size!=NULL)
			*value_size=value_size_temp;
	}
	return bytes;
}

void *otb_settings_get_config_bytes(const char *group_name, const char *key, size_t* value_size)
{
	otb_settings_lock_config_read();
	void *ret_val=otb_settings_get_bytes(config_key_file, group_name, key, value_size);
	otb_settings_unlock_config_read();
	return ret_val;
}

void otb_settings_set_gbytes(GKeyFile *key_file, const char *group_name, const char *key, GBytes *value)
{
	otb_settings_set_bytes(key_file, group_name, key, g_bytes_get_data(value, NULL), g_bytes_get_size(value));
}

gboolean otb_settings_set_config_gbytes(const char *group_name, const char *key, GBytes *value)
{
	return otb_settings_set_config_bytes(group_name, key, g_bytes_get_data(value, NULL), g_bytes_get_size(value));
}

GBytes *otb_settings_get_gbytes(GKeyFile *key_file, const char *group_name, const char *key)
{
	GBytes *value=NULL;
	size_t value_size;
	void *value_bytes=otb_settings_get_bytes(key_file, group_name, key, &value_size);
	if(G_LIKELY(value_bytes!=NULL))
		value=g_bytes_new_take(value_bytes, value_size);
	return value;
}

GBytes *otb_settings_get_config_gbytes(const char *group_name, const char *key)
{
	otb_settings_lock_config_read();
	GBytes *ret_val=otb_settings_get_gbytes(config_key_file, group_name, key);
	otb_settings_unlock_config_read();
	return ret_val;
}
