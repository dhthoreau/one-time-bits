/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <glib.h>
#include <glib/gi18n.h>

#include "io.h"
#include "memory.h"
#include "settings.h"

#define CONFIG_FILE_NAME			"otb.conf"
#define CONFIG_META_GROUP_NAME		"config-meta"
#define FILE_VERSION_KEY			"file-version"
#define CURRENT_CONFIG_FILE_VERSION	0

static char *otb_config_directory_path=NULL;
static char *otb_data_directory_path=NULL;
static GMutex config_mutex;
static GKeyFile *config_key_file=NULL;

#define otb_settings_get_config_file_path()	(g_build_filename(otb_config_directory_path, CONFIG_FILE_NAME, NULL))

static void otb_settings_lock_config()
{
	g_mutex_lock(&config_mutex);
}

static void otb_settings_unlock_config()
{
	g_mutex_unlock(&config_mutex);
}

GKeyFile *otb_settings_load_key_file(const char *file_path)
{
	GKeyFile *key_file=g_key_file_new();
	GError *error=NULL;
	if(g_file_test(file_path, G_FILE_TEST_EXISTS) && !g_key_file_load_from_file(key_file, file_path, G_KEY_FILE_KEEP_COMMENTS | G_KEY_FILE_KEEP_TRANSLATIONS, &error))
	if(g_file_test(file_path, G_FILE_TEST_EXISTS) && !g_key_file_load_from_file(key_file, file_path, G_KEY_FILE_KEEP_COMMENTS | G_KEY_FILE_KEEP_TRANSLATIONS, &error))
	{
		g_message("%s: Failed to load settings file %s. Error == %s", "otb_settings_load_key_file", file_path, error->message);
		g_error_free(error);
		g_key_file_free(key_file);
		key_file=NULL;
	}
	return key_file;
}

static void otb_settings_load_config_file()
{
	otb_settings_lock_config();
	GKeyFile *old_config_key_file=config_key_file;
	char *config_file_path=otb_settings_get_config_file_path();
	config_key_file=otb_settings_load_key_file(config_file_path);
	otb_settings_unlock_config();
	g_free(config_file_path);
	if(old_config_key_file!=NULL)
		g_key_file_unref(old_config_key_file);
	g_key_file_set_integer(config_key_file, CONFIG_META_GROUP_NAME, FILE_VERSION_KEY, CURRENT_CONFIG_FILE_VERSION);
}

static void otb_settings_initialize_directory_paths(const char *app_name)
{
	otb_config_directory_path=g_build_filename(g_get_user_config_dir(), app_name, NULL);
	otb_data_directory_path=g_build_filename(g_get_user_data_dir(), app_name, NULL);
}

void otb_settings_initialize(const char *app_name)
{
	static gboolean otb_settings_directory_paths_initialized=FALSE;
	if(g_once_init_enter(&otb_settings_directory_paths_initialized))
	{
		bindtextdomain(GETTEXT_PACKAGE, LOCALEDIR);
		otb_settings_initialize_directory_paths(app_name);
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

static char *otb_settings_config_file_path(const char *file_name)
{
	return g_build_filename(otb_data_directory_path, file_name, NULL);
}

gboolean otb_settings_save_key_file(GKeyFile *key_file, const char *file_path, const char *func_name)
{
	gboolean ret_val=TRUE;
	gsize key_file_data_size;
	char *key_file_data=g_key_file_to_data(key_file, &key_file_data_size, NULL);
	FILE *file=otb_open_for_write(file_path, func_name);
	if(file==NULL)
		ret_val=FALSE;
	else if(otb_write(key_file_data, sizeof(char), key_file_data_size, file, func_name)!=key_file_data_size)
		ret_val=FALSE;
	if(!otb_close(file, func_name))
		ret_val=FALSE;
	g_free(key_file_data);
	return ret_val;
}

static gboolean otb_settings_save_config_key_file()
{
	char *config_file_path=otb_settings_get_config_file_path();
	otb_settings_lock_config();
	gboolean ret_val=otb_settings_save_key_file(config_key_file, config_file_path, "otb_settings_save_config_key_file");
	otb_settings_unlock_config();
	g_free(config_file_path);
	return ret_val;
}

gboolean otb_settings_set_config_int(const char *group_name, const char *key, int value)
{
	otb_settings_lock_config();
	g_key_file_set_integer(config_key_file, group_name, key, value);
	otb_settings_unlock_config();
	return otb_settings_save_config_key_file();
}

int otb_settings_get_int(GKeyFile *key_file, const char *group_name, const char *key, int error_value, const char *func_name)
{
	GError *error=NULL;
	int value=g_key_file_get_integer(key_file, group_name, key, &error);
	if(error!=NULL)
	{
		value=error_value;
		g_message("%s: Failed to read %s / %s from config file. Error == %s", func_name, group_name, key, error->message);
		g_error_free(error);
	}
	return value;
}

int otb_settings_get_config_int(const char *group_name, const char *key, int error_value)
{
	otb_settings_lock_config();
	int ret_val=otb_settings_get_int(config_key_file, group_name, key, error_value, "otb_settings_get_config_int");
	otb_settings_unlock_config();
	return ret_val;
}

long long otb_settings_get_int64(GKeyFile *key_file, const char *group_name, const char *key, long long error_value, const char *func_name)
{
	GError *error=NULL;
	long long value=g_key_file_get_int64(key_file, group_name, key, &error);
	if(error!=NULL)
	{
		value=error_value;
		g_message("%s: Failed to read %s / %s from config file. Error == %s", func_name, group_name, key, error->message);
		g_error_free(error);
	}
	return value;
}

gboolean otb_settings_set_config_string(const char *group_name, const char *key, const char *value)
{
	otb_settings_lock_config();
	g_key_file_set_string(config_key_file, group_name, key, value);
	otb_settings_unlock_config();
	return otb_settings_save_config_key_file();
}

char *otb_settings_get_string(GKeyFile *key_file, const char *group_name, const char *key, const char *func_name)
{
	GError *error=NULL;
	char *value=g_key_file_get_string(key_file, group_name, key, &error);
	if(error!=NULL)
	{
		g_free(value);
		g_message("%s: Failed to read %s / %s from config file. Error == %s", func_name, group_name, key, error->message);
		g_error_free(error);
	}
	return value;
}

char *otb_settings_get_config_string(const char *group_name, const char *key, const char *func_name)
{
	otb_settings_lock_config();
	char *ret_val=otb_settings_get_string(config_key_file, group_name, key, func_name);
	otb_settings_unlock_config();
	return ret_val;
}

void otb_settings_set_bytes(GKeyFile *key_file, const char *group_name, const char *key, const void *value, size_t value_length)
{
	char *encoded_bytes=g_base64_encode(value, value_length);
	g_key_file_set_string(key_file, group_name, key, encoded_bytes);
	g_free(encoded_bytes);
}
gboolean otb_settings_set_config_bytes(const char *group_name, const char *key, const void *value, size_t value_length)
{
	otb_settings_lock_config();
	otb_settings_set_bytes(config_key_file, group_name, key, value, value_length);
	otb_settings_unlock_config();
	return otb_settings_save_config_key_file();
}

void *otb_settings_get_bytes(GKeyFile *key_file, const char *group_name, const char *key, size_t *value_length, const char *func_name)
{
	char *bytes=otb_settings_get_string(key_file, group_name, key, func_name);
	if(bytes!=NULL)
	{
		size_t value_length_temp;
		if(bytes[0])
			g_base64_decode_inplace(bytes, &value_length_temp);
		if(value_length!=NULL)
			*value_length=value_length_temp;
	}
	return bytes;
}

void *otb_settings_get_config_bytes(const char *group_name, const char *key, size_t* value_length)
{
	otb_settings_lock_config();
	void *ret_val=otb_settings_get_bytes(config_key_file, group_name, key, value_length, "otb_settings_get_config_bytes");
	otb_settings_unlock_config();
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

GBytes *otb_settings_get_gbytes(GKeyFile *key_file, const char *group_name, const char *key, const char *func_name)
{
	GBytes *value=NULL;
	size_t value_length;
	void *value_bytes=otb_settings_get_bytes(key_file, group_name, key, &value_length, func_name);
	if(value_bytes!=NULL)
		value=g_bytes_new_take(value_bytes, value_length);
	return value;
}

GBytes *otb_settings_get_config_gbytes(const char *group_name, const char *key)
{
	otb_settings_lock_config();
	GBytes *ret_val=otb_settings_get_gbytes(config_key_file, group_name, key, "otb_settings_get_config_gbytes");
	otb_settings_unlock_config();
	return ret_val;
}
