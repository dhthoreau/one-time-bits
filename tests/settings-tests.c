/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <glib.h>

#include "main.h"
#include "test-utils.h"
#include "../src/io.h"
#include "../src/settings.h"

#define GROUP_NAME	"test"

static void test_settings_set_config_dir()
{
	otb_settings_initialize("otb");
	otb_settings_set_config_directory_path(otb_get_test_dir_path());
	g_assert_cmpstr(otb_get_test_dir_path(), == , otb_settings_get_config_directory_path());
}

static void test_settings_set_data_dir()
{
	otb_settings_initialize("otb");
	otb_settings_set_data_directory_path(otb_get_test_dir_path());
	g_assert_cmpstr(otb_get_test_dir_path(), == , otb_settings_get_data_directory_path());
}

static void test_settings_get_set_config_string()
{
	const char *STRING_KEY="string-key";
	const char *EXPECTED_STRING="It was decided by the university of Coimbre that the sight of several persons being slowly burned in great ceremony is an infallible secret for preventing earthquakes.";
	
	otb_settings_initialize("otb");
	otb_settings_set_config_directory_path(otb_get_test_dir_path());
	g_assert(otb_settings_get_config_string(GROUP_NAME, STRING_KEY, "test_settings_get_set_config_string")==NULL);
	g_assert(otb_settings_set_config_string(GROUP_NAME, STRING_KEY, EXPECTED_STRING));
	char *actual_string=otb_settings_get_config_string(GROUP_NAME, STRING_KEY, "test_settings_get_set_config_string");
	g_assert_cmpstr(EXPECTED_STRING, ==, actual_string);
	g_free(actual_string);
}

static void test_settings_get_set_config_int()
{
	const char *INT_KEY="int-key";
	const int EXPECTED_INT=42;
	const int ERROR_INT=-1;
	
	otb_settings_initialize("otb");
	otb_settings_set_config_directory_path(otb_get_test_dir_path());
	g_assert_cmpint(ERROR_INT, ==, otb_settings_get_config_int(GROUP_NAME, INT_KEY, ERROR_INT));
	g_assert(otb_settings_set_config_int(GROUP_NAME, INT_KEY, EXPECTED_INT));
	g_assert_cmpint(EXPECTED_INT, ==, otb_settings_get_config_int(GROUP_NAME, INT_KEY, ERROR_INT));
}

static void test_settings_get_set_bytes()
{
	const char *BYTES_KEY="bytes-key";
	const size_t EXPECTED_BYTES_SIZE=9;
	const char EXPECTED_BYTES[9]={0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0xff};
	
	GKeyFile *save_key_file=g_key_file_new();
	size_t actual_bytes_size;
	g_assert(otb_settings_get_bytes(save_key_file, GROUP_NAME, BYTES_KEY, &actual_bytes_size, "test_settings_get_set_bytes")==NULL);
	otb_settings_set_bytes(save_key_file, GROUP_NAME, BYTES_KEY, EXPECTED_BYTES, EXPECTED_BYTES_SIZE);
	char *file_path=g_build_filename(otb_get_test_dir_path(), "keyfile", NULL);
	g_assert(otb_settings_save_key_file(save_key_file, file_path, "test_settings_get_set_bytes"));
	g_key_file_unref(save_key_file);
	GKeyFile *load_key_file=otb_settings_load_key_file(file_path);
	g_free(file_path);
	unsigned char *actual_bytes=otb_settings_get_bytes(load_key_file, GROUP_NAME, BYTES_KEY, &actual_bytes_size, "test_settings_get_set_bytes");
	g_assert_cmpint(EXPECTED_BYTES_SIZE, ==, actual_bytes_size);
	g_assert_cmpint(0, ==, memcmp(EXPECTED_BYTES, actual_bytes, EXPECTED_BYTES_SIZE));
	g_free(actual_bytes);
	g_key_file_unref(load_key_file);
}
static void test_settings_get_set_config_bytes()
{
	const char *BYTES_KEY="bytes-key";
	const size_t EXPECTED_BYTES_SIZE=9;
	const unsigned char EXPECTED_BYTES[9]={0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77};
	
	otb_settings_initialize("otb");
	otb_settings_set_config_directory_path(otb_get_test_dir_path());
	size_t actual_bytes_size;
	g_assert(otb_settings_get_config_bytes(GROUP_NAME, BYTES_KEY, &actual_bytes_size)==NULL);
	g_assert(otb_settings_set_config_bytes(GROUP_NAME, BYTES_KEY, EXPECTED_BYTES, EXPECTED_BYTES_SIZE));
	unsigned char *actual_bytes=otb_settings_get_config_bytes(GROUP_NAME, BYTES_KEY, &actual_bytes_size);
	g_assert_cmpint(EXPECTED_BYTES_SIZE, ==, actual_bytes_size);
	g_assert_cmpint(0, ==, memcmp(EXPECTED_BYTES, actual_bytes, EXPECTED_BYTES_SIZE));
	g_free(actual_bytes);
}

static void test_settings_get_set_gbytes()
{
	const char *GBYTES_KEY="gbytes-key";
	const size_t EXPECTED_GBYTES_SIZE=7;
	const unsigned char EXPECTED_GBYTES[7]={0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d};
	
	GKeyFile *save_key_file=g_key_file_new();
	g_assert(otb_settings_get_gbytes(save_key_file, GROUP_NAME, GBYTES_KEY, "test_settings_get_set_gbytes")==NULL);
	GBytes *expected_gbytes=g_bytes_new_static(EXPECTED_GBYTES, EXPECTED_GBYTES_SIZE);
	otb_settings_set_gbytes(save_key_file, GROUP_NAME, GBYTES_KEY, expected_gbytes);
	char *file_path=g_build_filename(otb_get_test_dir_path(), "keyfile", NULL);
	g_assert(otb_settings_save_key_file(save_key_file, file_path, "test_settings_get_set_bytes"));
	g_key_file_unref(save_key_file);
	GKeyFile *load_key_file=otb_settings_load_key_file(file_path);
	g_free(file_path);
	GBytes *actual_gbytes=otb_settings_get_gbytes(load_key_file, GROUP_NAME, GBYTES_KEY, "test_settings_get_set_gbytes");
	g_assert(g_bytes_equal(expected_gbytes, actual_gbytes));
	g_bytes_unref(actual_gbytes);
	g_bytes_unref(expected_gbytes);
	g_key_file_unref(load_key_file);
}

static void test_settings_get_set_config_gbytes()
{
	const char *GBYTES_KEY="gbytes-key";
	const size_t EXPECTED_GBYTES_SIZE=7;
	const unsigned char EXPECTED_GBYTES[7]={0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00};
	
	otb_settings_initialize("otb");
	otb_settings_set_config_directory_path(otb_get_test_dir_path());
	g_assert(otb_settings_get_config_gbytes(GROUP_NAME, GBYTES_KEY)==NULL);
	GBytes *expected_gbytes=g_bytes_new_static(EXPECTED_GBYTES, EXPECTED_GBYTES_SIZE);
	g_assert(otb_settings_set_config_gbytes(GROUP_NAME, GBYTES_KEY, expected_gbytes));
	GBytes *actual_gbytes=otb_settings_get_config_gbytes(GROUP_NAME, GBYTES_KEY);
	g_assert(g_bytes_equal(expected_gbytes, actual_gbytes));
	g_bytes_unref(actual_gbytes);
	g_bytes_unref(expected_gbytes);
}

void otb_add_settings_tests()
{
	otb_add_test_func("/settings/test_settings_set_config_dir", test_settings_set_config_dir);
	otb_add_test_func("/settings/test_settings_set_data_dir", test_settings_set_data_dir);
	otb_add_test_func("/settings/test_settings_get_set_config_string", test_settings_get_set_config_string);
	otb_add_test_func("/settings/test_settings_get_set_config_int", test_settings_get_set_config_int);
	otb_add_test_func("/settings/test_settings_get_set_config_bytes", test_settings_get_set_config_bytes);
	otb_add_test_func("/settings/test_settings_get_set_bytes", test_settings_get_set_bytes);
	otb_add_test_func("/settings/test_settings_get_set_gbytes", test_settings_get_set_gbytes);
	otb_add_test_func("/settings/test_settings_get_set_config_gbytes", test_settings_get_set_config_gbytes);
}
