/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <string.h>

#include "main.h"
#include "test-utils.h"
#include "../src/io.h"
#include "../src/pad-rec.h"
#include "../src/unique-id.h"

static char *otb_get_expected_file_name(OtbPadRec *pad_rec)
{
	char *base_name=NULL;
	g_object_get(pad_rec, OTB_PAD_REC_PROP_BASE_NAME, &base_name, NULL);
	char *file_name=g_strconcat(base_name, ".rec", NULL);
	g_free(base_name);
	return file_name;
}

static char *otb_get_expected_file_path(OtbPadRec *pad_rec)
{
	char *expected_file_name=otb_get_expected_file_name(pad_rec);
	char *expected_file_path=g_build_filename(otb_get_test_dir_path(), expected_file_name, NULL);
	g_free(expected_file_name);
	return expected_file_path;
}

static void otb_assert_pad_rec_file_exists(OtbPadRec *pad_rec)
{
	char *expected_pad_rec_file_path=otb_get_expected_file_path(pad_rec);
	g_assert(g_file_test(expected_pad_rec_file_path, G_FILE_TEST_EXISTS));
	g_free(expected_pad_rec_file_path);
}

static void otb_assert_pad_rec_file_does_not_exist(OtbPadRec *pad_rec)
{
	char *expected_pad_rec_file_path=otb_get_expected_file_path(pad_rec);
	otb_assert_file_does_not_exist(expected_pad_rec_file_path);
	g_free(expected_pad_rec_file_path);
}

static char *otb_get_expected_file_path_of_pad(OtbPadRec *pad_rec)
{
	char *expected_file_path=otb_get_expected_file_path(pad_rec);
	strcpy(expected_file_path+strlen(expected_file_path)-3, "pad");
	return expected_file_path;
}

static void otb_assert_pad_file_exists(OtbPadRec *pad_rec)
{
	char *expected_pad_file_path=otb_get_expected_file_path_of_pad(pad_rec);
	g_assert(g_file_test(expected_pad_file_path, G_FILE_TEST_EXISTS));
	g_free(expected_pad_file_path);
}

static void otb_assert_pad_file_does_not_exist(OtbPadRec *pad_rec)
{
	char *expected_pad_file_path=otb_get_expected_file_path_of_pad(pad_rec);
	otb_assert_file_does_not_exist(expected_pad_file_path);
	g_free(expected_pad_file_path);
}

static void otb_assert_pad_file(OtbPadRec *pad_rec, const unsigned char *expected_pad_bytes, off_t expected_pad_size, gboolean auto_rewind)
{
	off_t actual_pad_size;
	g_object_get(pad_rec, OTB_PAD_REC_PROP_SIZE, &actual_pad_size, NULL);
	g_assert_cmpint(expected_pad_size, ==, actual_pad_size);
	OtbPadIO *pad_io=otb_pad_rec_open_pad_for_read(pad_rec, auto_rewind);
	g_assert(pad_io!=NULL);
	for(int read_count=0; read_count<(auto_rewind?4:1); read_count++)
	{
		for(off_t iter=0; iter<expected_pad_size; iter++)
		{
			unsigned char actual_byte;
			g_assert(otb_pad_has_more_bytes(pad_io));
			g_assert(otb_pad_read_byte(pad_io, &actual_byte));
			if(expected_pad_bytes!=NULL)
				g_assert_cmpint(expected_pad_bytes[iter], ==, actual_byte);
		}
		g_assert(!auto_rewind!=otb_pad_has_more_bytes(pad_io));
	}
	g_assert(otb_pad_io_free(pad_io));
}

static void test_otb_pad_rec_default_status()
{
	otb_test_setup_local_crypto();
	OtbPadRecStatus expected_status=OTB_PAD_REC_STATUS_UNSENT;
	OtbPadRec *pad_rec=g_object_new(OTB_TYPE_PAD_REC, NULL);
	OtbPadRecStatus pad_rec_status;
	g_object_get(pad_rec, OTB_PAD_REC_PROP_STATUS, &pad_rec_status, NULL);
	g_assert_cmpint(expected_status, ==, pad_rec_status);
	g_object_unref(pad_rec);
}

static void test_otb_pad_rec_initializing_status()
{
	otb_test_setup_local_crypto();
	OtbPadRecStatus expected_status=OTB_PAD_REC_STATUS_RECEIVED;
	OtbPadRec *pad_rec=g_object_new(OTB_TYPE_PAD_REC, OTB_PAD_REC_PROP_STATUS, expected_status, NULL);
	OtbPadRecStatus pad_rec_status;
	g_object_get(pad_rec, OTB_PAD_REC_PROP_STATUS, &pad_rec_status, NULL);
	g_assert_cmpint(expected_status, ==, pad_rec_status);
	g_object_unref(pad_rec);
}

static void test_otb_pad_rec_initializing_base_path()
{
	const char *EXPECTED_BASE_PATH="hey/yo";
	
	otb_test_setup_local_crypto();
	OtbPadRec *pad_rec=g_object_new(OTB_TYPE_PAD_REC, OTB_PAD_REC_PROP_BASE_PATH, EXPECTED_BASE_PATH, NULL);
	char *actual_base_path=NULL;
	g_object_get(pad_rec, OTB_PAD_REC_PROP_BASE_PATH, &actual_base_path, NULL);
	g_assert_cmpstr(EXPECTED_BASE_PATH, ==, actual_base_path);
	g_free(actual_base_path);
	g_object_unref(pad_rec);
}

static void test_otb_pad_rec_initializing_base_name()
{
	const char *EXPECTED_BASE_NAME="12345";
	
	otb_test_setup_local_crypto();
	OtbPadRec *pad_rec=g_object_new(OTB_TYPE_PAD_REC, OTB_PAD_REC_PROP_BASE_NAME, EXPECTED_BASE_NAME, NULL);
	char *actual_base_name=NULL;
	g_object_get(pad_rec, OTB_PAD_REC_PROP_BASE_NAME, &actual_base_name, NULL);
	g_assert_cmpstr(EXPECTED_BASE_NAME, ==, actual_base_name);
	g_free(actual_base_name);
	g_object_unref(pad_rec);
}

static void test_otb_pad_rec_specifying_unique_id()
{
	otb_test_setup_local_crypto();
	OtbUniqueId *expected_unique_id=otb_unique_id_create();
	OtbPadRec *pad_rec=g_object_new(OTB_TYPE_PAD_REC, OTB_PAD_REC_PROP_UNIQUE_ID, expected_unique_id, NULL);
	OtbUniqueId *actual_unique_id=NULL;
	g_object_get(pad_rec, OTB_PAD_REC_PROP_UNIQUE_ID, &actual_unique_id, NULL);
	g_assert_cmpint(0, ==, otb_unique_id_compare(expected_unique_id, actual_unique_id));
	g_free(actual_unique_id);
	g_object_unref(pad_rec);
	g_free(expected_unique_id);
}

static void test_otb_pad_rec_without_specifying_unique_id()
{
	otb_test_setup_local_crypto();
	OtbUniqueId *expected_unique_id=otb_unique_id_create();
	OtbPadRec *pad_rec=g_object_new(OTB_TYPE_PAD_REC, NULL);
	OtbUniqueId *actual_unique_id=NULL;
	g_object_get(pad_rec, OTB_PAD_REC_PROP_UNIQUE_ID, &actual_unique_id, NULL);
	g_assert_cmpint(0, !=, otb_unique_id_compare(expected_unique_id, actual_unique_id));
	g_free(actual_unique_id);
	g_free(expected_unique_id);
	g_object_unref(pad_rec);
}

static void test_otb_pad_rec_compare_by_id()
{
	otb_test_setup_local_crypto();
	OtbUniqueId *expected_unique_id=otb_unique_id_create();
	OtbUniqueId *unexpected_unique_id=otb_unique_id_create();
	OtbPadRec *pad_rec=g_object_new(OTB_TYPE_PAD_REC, OTB_PAD_REC_PROP_UNIQUE_ID, expected_unique_id, NULL);
	g_assert_cmpint(0, ==, otb_pad_rec_compare_by_id(pad_rec, expected_unique_id));
	g_assert_cmpint(0, !=, otb_pad_rec_compare_by_id(pad_rec, unexpected_unique_id));
	g_free(expected_unique_id);
	g_free(unexpected_unique_id);
	g_object_unref(pad_rec);
}

static void test_otb_pad_rec_save_load()
{
	otb_test_setup_local_crypto();
	OtbUniqueId *expected_unique_id=otb_unique_id_create();
	OtbPadRecStatus expected_status=OTB_PAD_REC_STATUS_RECEIVED;
	OtbPadRec *pad_rec_save=g_object_new(OTB_TYPE_PAD_REC, OTB_PAD_REC_PROP_BASE_PATH, otb_get_test_dir_path(), OTB_PAD_REC_PROP_STATUS, expected_status, OTB_PAD_REC_PROP_UNIQUE_ID, expected_unique_id, NULL);
	g_assert(otb_pad_rec_save(pad_rec_save));
	otb_assert_pad_rec_file_exists(pad_rec_save);
	char *expected_file_name=otb_get_expected_file_name(pad_rec_save);
	OtbPadRec *pad_rec_load=otb_pad_rec_load(otb_get_test_dir_path(), expected_file_name);
	g_free(expected_file_name);
	g_assert(pad_rec_load!=NULL);
	OtbUniqueId *actual_unique_id=NULL;
	g_object_get(pad_rec_load, OTB_PAD_REC_PROP_UNIQUE_ID, &actual_unique_id, NULL);
	g_assert_cmpint(0, ==, otb_unique_id_compare(expected_unique_id, actual_unique_id));
	g_free(actual_unique_id);
	g_free(expected_unique_id);
	OtbPadRecStatus pad_rec_status;
	g_object_get(pad_rec_load, OTB_PAD_REC_PROP_STATUS, &pad_rec_status, NULL);
	g_assert_cmpint(expected_status, ==, pad_rec_status);
	g_object_unref(pad_rec_load);
	g_object_unref(pad_rec_save);
}

static void test_otb_pad_rec_generate_pad_file()
{
	const off_t EXPECTED_PAD_SIZE=20;
	
	otb_test_setup_local_crypto();
	OtbPadRec *pad_rec=g_object_new(OTB_TYPE_PAD_REC, OTB_PAD_REC_PROP_BASE_PATH, otb_get_test_dir_path(), OTB_PAD_REC_PROP_SIZE, EXPECTED_PAD_SIZE, NULL);
	otb_pad_rec_generate_pad_file(pad_rec);
	otb_assert_pad_file_exists(pad_rec);
	otb_assert_pad_file(pad_rec, NULL, EXPECTED_PAD_SIZE, FALSE);
	g_object_unref(pad_rec);
}

static void test_otb_pad_rec_io_and_full_deletion()
{
	const off_t EXPECTED_PAD_SIZE=1;
	const unsigned char EXPECTED_PAD_BYTES[10]={0x85, 0x83, 0x3b, 0xee, 0x34, 0x7a, 0x2b, 0x96, 0xec, 0x87};
	
	otb_test_setup_local_crypto();
	OtbPadRec *pad_rec=g_object_new(OTB_TYPE_PAD_REC, OTB_PAD_REC_PROP_BASE_PATH, otb_get_test_dir_path(), OTB_PAD_REC_PROP_SIZE, EXPECTED_PAD_SIZE, NULL);
	OtbPadIO *write_pad_io=otb_pad_rec_open_pad_for_write(pad_rec);
	g_assert(write_pad_io!=NULL);
	g_assert(otb_pad_write(write_pad_io, EXPECTED_PAD_BYTES, EXPECTED_PAD_SIZE));
	g_assert(otb_pad_io_free(write_pad_io));
	otb_assert_pad_rec_file_exists(pad_rec);
	otb_assert_pad_file_exists(pad_rec);
	otb_assert_pad_file(pad_rec, EXPECTED_PAD_BYTES, EXPECTED_PAD_SIZE, FALSE);
	otb_assert_pad_file(pad_rec, EXPECTED_PAD_BYTES, EXPECTED_PAD_SIZE, TRUE);
	otb_pad_rec_delete(pad_rec);
	otb_assert_pad_rec_file_does_not_exist(pad_rec);
	otb_assert_pad_file_does_not_exist(pad_rec);
	g_object_unref(pad_rec);
}

static void test_otb_pad_rec_io_and_pad_deletion()
{
	const off_t EXPECTED_PAD_SIZE=1;
	const unsigned char EXPECTED_PAD_BYTES[10]={0x85, 0x83, 0x3b, 0xee, 0x34, 0x7a, 0x2b, 0x96, 0xec, 0x87};
	
	otb_test_setup_local_crypto();
	OtbPadRec *pad_rec=g_object_new(OTB_TYPE_PAD_REC, OTB_PAD_REC_PROP_BASE_PATH, otb_get_test_dir_path(), OTB_PAD_REC_PROP_SIZE, EXPECTED_PAD_SIZE, NULL);
	OtbPadIO *write_pad_io=otb_pad_rec_open_pad_for_write(pad_rec);
	g_assert(write_pad_io!=NULL);
	g_assert(otb_pad_write(write_pad_io, EXPECTED_PAD_BYTES, EXPECTED_PAD_SIZE));
	g_assert(otb_pad_io_free(write_pad_io));
	otb_assert_pad_rec_file_exists(pad_rec);
	otb_assert_pad_file_exists(pad_rec);
	otb_assert_pad_file(pad_rec, EXPECTED_PAD_BYTES, EXPECTED_PAD_SIZE, FALSE);
	otb_assert_pad_file(pad_rec, EXPECTED_PAD_BYTES, EXPECTED_PAD_SIZE, TRUE);
	otb_pad_rec_delete_pad(pad_rec);
	otb_assert_pad_rec_file_exists(pad_rec);
	otb_assert_pad_file_does_not_exist(pad_rec);
	g_object_unref(pad_rec);
}

void otb_add_pad_rec_tests()
{
	otb_add_test_func("/pad-rec/test_otb_pad_rec_default_status", test_otb_pad_rec_default_status);
	otb_add_test_func("/pad-rec/test_otb_pad_rec_initializing_status", test_otb_pad_rec_initializing_status);
	otb_add_test_func("/pad-rec/test_otb_pad_rec_initializing_base_path", test_otb_pad_rec_initializing_base_path);
	otb_add_test_func("/pad-rec/test_otb_pad_rec_initializing_base_name", test_otb_pad_rec_initializing_base_name);
	otb_add_test_func("/pad-rec/test_otb_pad_rec_specifying_unique_id", test_otb_pad_rec_specifying_unique_id);
	otb_add_test_func("/pad-rec/test_otb_pad_rec_without_specifying_unique_id", test_otb_pad_rec_without_specifying_unique_id);
	otb_add_test_func("/pad-rec/test_otb_pad_rec_compare_by_id", test_otb_pad_rec_compare_by_id);
	otb_add_test_func("/pad-rec/test_otb_pad_rec_save_load", test_otb_pad_rec_save_load);
	otb_add_test_func("/pad-rec/test_otb_pad_rec_generate_pad_file", test_otb_pad_rec_generate_pad_file);
	otb_add_test_func("/pad-rec/test_otb_pad_rec_io_and_full_deletion", test_otb_pad_rec_io_and_full_deletion);
	otb_add_test_func("/pad-rec/test_otb_pad_rec_io_and_pad_deletion", test_otb_pad_rec_io_and_pad_deletion);
}
