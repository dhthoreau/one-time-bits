/**
 * Copyright © 2017 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_SETTINGS_H
#define OTB_SETTINGS_H

#include <glib.h>

gboolean otb_settings_save_key_file(GKeyFile *key_file, const char *file_path);
GKeyFile *otb_settings_load_key_file_from_file(const char *file_path);
GKeyFile *otb_settings_load_key_file_from_string(const char *string);

void otb_settings_initialize(const char *app_name, const char *otb_sub_dir);

const char *otb_settings_get_config_directory_path(void);
void otb_settings_set_config_directory_path(const char *config_directory_path);
const char *otb_settings_get_data_directory_path(void);
void otb_settings_set_data_directory_path(const char *data_directory_path);

gboolean otb_settings_config_group_exists(const char *group_name);

gboolean otb_settings_set_config_int(const char *group_name, const char *key, int value);
int otb_settings_get_int(GKeyFile *key_file, const char *group_name, const char *key, int error_value);
int otb_settings_get_config_int(const char *group_name, const char *key, int error_value);

gboolean otb_settings_set_config_uint(const char *group_name, const char *key, unsigned int value);
unsigned int otb_settings_get_uint(GKeyFile *key_file, const char *group_name, const char *key, unsigned int error_value);
unsigned int otb_settings_get_config_uint(const char *group_name, const char *key, unsigned int error_value);

gboolean otb_settings_set_config_int64(const char *group_name, const char *key, long long value);
long long otb_settings_get_int64(GKeyFile *key_file, const char *group_name, const char *key, long long error_value);
long long otb_settings_get_config_int64(const char *group_name, const char *key, long long error_value);

unsigned long long otb_settings_get_uint64(GKeyFile *key_file, const char *group_name, const char *key, unsigned long long error_value);

gboolean otb_settings_set_config_string(const char *group_name, const char *key, const char *value);
char *otb_settings_get_string(GKeyFile *key_file, const char *group_name, const char *key);
char *otb_settings_get_config_string(const char *group_name, const char *key);

void otb_settings_set_bytes(GKeyFile *key_file, const char *group_name, const char *key, const void *value, size_t value_size);
gboolean otb_settings_set_config_bytes(const char *group_name, const char *key, const void *value, size_t value_size);
void *otb_settings_get_bytes(GKeyFile *key_file, const char *group_name, const char *key, size_t* value_size);
void *otb_settings_get_config_bytes(const char *group_name, const char *key, size_t* value_size);

void otb_settings_set_gbytes(GKeyFile *key_file, const char *group_name, const char *key, GBytes *value);
gboolean otb_settings_set_config_gbytes(const char *group_name, const char *key, GBytes *value);
GBytes *otb_settings_get_gbytes(GKeyFile *key_file, const char *group_name, const char *key);
GBytes *otb_settings_get_config_gbytes(const char *group_name, const char *key);

#endif
