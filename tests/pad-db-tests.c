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
#include "pad-rec-tests.h"
#include "test-utils.h"
#include "../src/cipher.h"
#include "../src/io.h"
#include "../src/pad-db.h"
#include "../src/pad-rec.h"
#include "../src/random.h"

#define ABSOLUTE_MIN_PAD_SIZE	1024

static void otb_assert_file_size(const char *file_path, size_t expected_size)
{
	size_t actual_size=otb_get_file_size(file_path, "otb_assert_file_size");
	g_assert_cmpint(expected_size, ==, actual_size);
}

static char *otb_get_expected_pad_db_file_path(const char *base_path)
{
	return g_build_filename(base_path, "db.otb", NULL);
}

static void otb_assert_pad_db_file_exists(const char *base_path)
{
	char *expected_pad_db_file_path=otb_get_expected_pad_db_file_path(base_path);
	g_assert(g_file_test(expected_pad_db_file_path, G_FILE_TEST_EXISTS));
	g_free(expected_pad_db_file_path);
}

static OtbPadDb *otb_create_pad_db_in_random_test_path()
{
	char *pad_db_dir_path=otb_generate_unique_test_subdir_path();
	OtbPadDb *pad_db=otb_pad_db_create_in_directory(pad_db_dir_path);
	g_assert(pad_db!=NULL);
	g_free(pad_db_dir_path);
	return pad_db;
}

static void test_set_new_pad_size()
{
	OtbPadDb *pad_db=otb_create_pad_db_in_random_test_path();
	g_assert(otb_pad_db_set_new_pad_min_size(pad_db, ABSOLUTE_MIN_PAD_SIZE)+1);
	g_assert(!otb_pad_db_set_new_pad_min_size(pad_db, ABSOLUTE_MIN_PAD_SIZE-1));
	g_assert(otb_pad_db_set_new_pad_max_size(pad_db, ABSOLUTE_MIN_PAD_SIZE));
	off_t actual_new_pad_min;
	g_object_get(pad_db, OTB_PAD_DB_PROP_NEW_PAD_MIN_SIZE, &actual_new_pad_min, NULL);
	g_assert_cmpint(ABSOLUTE_MIN_PAD_SIZE, ==, actual_new_pad_min);
	g_assert(otb_pad_db_set_new_pad_min_size(pad_db, ABSOLUTE_MIN_PAD_SIZE+1));
	off_t actual_new_pad_max;
	g_object_get(pad_db, OTB_PAD_DB_PROP_NEW_PAD_MAX_SIZE, &actual_new_pad_max, NULL);
	g_assert_cmpint(ABSOLUTE_MIN_PAD_SIZE+1, ==, actual_new_pad_max);
	g_object_unref(pad_db);
}

static void otb_assert_pad_db_default_property_values(OtbPadDb *pad_db)
{
	const off_t EXPECTED_DEFAULT_MAX_SIZE=10485760;
	const off_t EXPECTED_DEFAULT_NEW_PAD_MIN_SIZE=10240;
	const off_t EXPECTED_DEFAULT_NEW_PAD_MAX_SIZE=20480;

	off_t actual_max_size;
	off_t actual_new_pad_min;
	off_t actual_new_pad_max;
	g_object_get(pad_db, OTB_PAD_DB_PROP_MAX_SIZE, &actual_max_size, OTB_PAD_DB_PROP_NEW_PAD_MIN_SIZE, &actual_new_pad_min, OTB_PAD_DB_PROP_NEW_PAD_MAX_SIZE, &actual_new_pad_max, NULL);
	g_assert_cmpint(EXPECTED_DEFAULT_MAX_SIZE, ==, actual_max_size);
	g_assert_cmpint(EXPECTED_DEFAULT_NEW_PAD_MIN_SIZE, ==, actual_new_pad_min);
	g_assert_cmpint(EXPECTED_DEFAULT_NEW_PAD_MAX_SIZE, ==, actual_new_pad_max);
}

static void otb_create_db_in_path_with_custom_property_values(const char *pad_db_dir_path, off_t max_size, off_t new_pad_min_size, off_t new_pad_max_size)
{
	OtbPadDb *pad_db=otb_pad_db_create_in_directory(pad_db_dir_path);
	g_assert(pad_db!=NULL);
	otb_assert_pad_db_default_property_values(pad_db);
	g_assert(otb_pad_db_set_max_size(pad_db, max_size));
	off_t actual_max_size;
	g_object_get(pad_db, OTB_PAD_DB_PROP_MAX_SIZE, &actual_max_size, NULL);
	g_assert_cmpint(max_size, ==, actual_max_size);
	g_assert(otb_pad_db_set_new_pad_min_size(pad_db, new_pad_min_size));
	off_t actual_new_pad_min;
	g_object_get(pad_db, OTB_PAD_DB_PROP_NEW_PAD_MIN_SIZE, &actual_new_pad_min, NULL);
	g_assert_cmpint(new_pad_min_size, ==, actual_new_pad_min);
	g_assert(otb_pad_db_set_new_pad_max_size(pad_db, new_pad_max_size));
	off_t actual_new_pad_max;
	g_object_get(pad_db, OTB_PAD_DB_PROP_NEW_PAD_MAX_SIZE, &actual_new_pad_max, NULL);
	g_assert_cmpint(new_pad_max_size, ==, actual_new_pad_max);
	g_object_unref(pad_db);
	otb_assert_pad_db_file_exists(pad_db_dir_path);
}

static void otb_load_db_from_path_with_custom_property_values(const char *pad_db_dir_path, off_t max_size, off_t new_pad_min_size, off_t new_pad_max_size)
{
	OtbPadDb *pad_db=otb_pad_db_load_from_directory(pad_db_dir_path);
	g_assert(pad_db!=NULL);
	off_t actual_max_size;
	off_t actual_new_pad_min;
	off_t actual_new_pad_max;
	g_object_get(pad_db, OTB_PAD_DB_PROP_MAX_SIZE, &actual_max_size, OTB_PAD_DB_PROP_NEW_PAD_MIN_SIZE, &actual_new_pad_min, OTB_PAD_DB_PROP_NEW_PAD_MAX_SIZE, &actual_new_pad_max, NULL);
	g_assert_cmpint(max_size, ==, actual_max_size);
	g_assert_cmpint(new_pad_min_size, ==, actual_new_pad_min);
	g_assert_cmpint(new_pad_max_size, ==, actual_new_pad_max);
	g_object_unref(pad_db);
}

static void test_otb_pad_db_io()
{
	const off_t EXPECTED_MAX_SIZE=1234567890123456;
	const off_t EXPECTED_NEW_PAD_MIN_SIZE=1234567890;
	const off_t EXPECTED_NEW_PAD_MAX_SIZE=12345678901;
	
	char *pad_db_dir_path=otb_generate_unique_test_subdir_path();
	otb_create_db_in_path_with_custom_property_values(pad_db_dir_path, EXPECTED_MAX_SIZE, EXPECTED_NEW_PAD_MIN_SIZE, EXPECTED_NEW_PAD_MAX_SIZE);
	otb_load_db_from_path_with_custom_property_values(pad_db_dir_path, EXPECTED_MAX_SIZE, EXPECTED_NEW_PAD_MIN_SIZE, EXPECTED_NEW_PAD_MAX_SIZE);
	g_free(pad_db_dir_path);
}

static void otb_assert_number_of_pads_in_status(const OtbPadDb *pad_db, size_t expected_number, OtbPadRecStatus pad_rec_status)
{
	GSList *pad_ids=otb_pad_db_get_ids_of_pads_in_status(pad_db, pad_rec_status);
	g_assert_cmpint(expected_number, ==, g_slist_length(pad_ids));
	g_slist_free(pad_ids);
}

static void test_otb_pad_db_rejects_pads_too_large()
{
	const off_t MAX_SIZE=2047;
	
	otb_test_setup_local_crypto();
	OtbPadDb *pad_db=otb_create_pad_db_in_random_test_path();
	g_assert(otb_pad_db_set_max_size(pad_db, MAX_SIZE));
	g_assert(otb_pad_db_set_new_pad_min_size(pad_db, ABSOLUTE_MIN_PAD_SIZE));
	g_assert(otb_pad_db_set_new_pad_max_size(pad_db, ABSOLUTE_MIN_PAD_SIZE));
	g_assert(otb_pad_db_create_unsent_pad(pad_db));
	g_assert(!otb_pad_db_create_unsent_pad(pad_db));
	otb_assert_number_of_pads_in_status(pad_db, 1, OTB_PAD_REC_STATUS_UNSENT);
	const uuid_t unique_id;
	g_assert(otb_pad_db_add_received_pad(pad_db, &unique_id, ABSOLUTE_MIN_PAD_SIZE)==NULL);
	g_object_unref(pad_db);
}

static void test_otb_pad_db_rejects_pads_duplicate_id()
{
	const size_t ARBITRARY_SIZE=10;
	
	otb_test_setup_local_crypto();
	OtbPadDb *pad_db=otb_create_pad_db_in_random_test_path();
	uuid_t unique_id;
	uuid_generate(unique_id);
	g_assert(otb_pad_db_add_received_pad(pad_db, (const uuid_t*)&unique_id, ARBITRARY_SIZE)!=NULL);
	g_assert(otb_pad_db_close_pad(pad_db));
	g_assert(otb_pad_db_add_received_pad(pad_db, (const uuid_t*)&unique_id, ARBITRARY_SIZE)==NULL);
	g_object_unref(pad_db);
}

static const uuid_t *otb_pad_db_fetch_random_rec_id_with_null_assertion(const OtbPadDb *pad_db, OtbPadRecStatus status)
{
	const uuid_t *unique_id=otb_pad_db_fetch_random_rec_id(pad_db, status);
	g_assert(unique_id!=NULL);
	return unique_id;
}

static void test_create_unsent_pad_results_in_proper_pad_file()
{
	otb_test_setup_local_crypto();
	char *pad_db_dir_path=otb_generate_unique_test_subdir_path();
	OtbPadDb *pad_db=otb_pad_db_create_in_directory(pad_db_dir_path);
	g_assert(pad_db!=NULL);
	g_assert(otb_pad_db_set_new_pad_min_size(pad_db, ABSOLUTE_MIN_PAD_SIZE));
	g_assert(otb_pad_db_set_new_pad_max_size(pad_db, ABSOLUTE_MIN_PAD_SIZE));
	g_assert(otb_pad_db_create_unsent_pad(pad_db));
	otb_pad_db_fetch_random_rec_id_with_null_assertion(pad_db, OTB_PAD_REC_STATUS_UNSENT);
	g_free(pad_db_dir_path);
	g_object_unref(pad_db);
}

static char *otb_assert_pad_read(OtbPadIO *pad_io, const char *expected_bytes, size_t expected_bytes_size)
{
	size_t expected_bytes_position=0;
	void *actual_bytes;
	size_t actual_bytes_size;
	GByteArray *pad_byte_array=(expected_bytes==NULL?g_byte_array_new():NULL);
	while(otb_pad_has_more_bytes(pad_io))
	{
		g_assert(otb_pad_read(pad_io, &actual_bytes, &actual_bytes_size));
		g_assert_cmpint(expected_bytes_position, <=, expected_bytes_size);
		if(expected_bytes!=NULL)
			g_assert_cmpint(0, <=, memcmp(expected_bytes+expected_bytes_position, actual_bytes, actual_bytes_size));
		else
			g_byte_array_append(pad_byte_array, actual_bytes, actual_bytes_size);
		expected_bytes_position+=actual_bytes_size;
	}
	g_assert_cmpint(expected_bytes_position, ==, expected_bytes_size);
	return pad_byte_array==NULL?NULL:g_byte_array_free(pad_byte_array, FALSE);
}

static void test_pads_save_and_load()
{
	const off_t EXPECTED_DEFAULT_NEW_PAD_SIZE=10240;
	
	otb_test_setup_local_crypto();
	char *pad_db_dir_path=otb_generate_unique_test_subdir_path();
	OtbPadDb *save_pad_db=otb_pad_db_create_in_directory(pad_db_dir_path);
	g_assert(save_pad_db!=NULL);
	g_assert(otb_pad_db_set_new_pad_min_size(save_pad_db, EXPECTED_DEFAULT_NEW_PAD_SIZE));
	g_assert(otb_pad_db_set_new_pad_max_size(save_pad_db, EXPECTED_DEFAULT_NEW_PAD_SIZE));
	g_assert(otb_pad_db_create_unsent_pad(save_pad_db));
	const uuid_t *expected_unsent_unique_id=otb_pad_db_fetch_random_rec_id_with_null_assertion(save_pad_db, OTB_PAD_REC_STATUS_UNSENT);
	OtbPadIO *unsent_save_pad_io=otb_pad_db_open_pad_for_read(save_pad_db, expected_unsent_unique_id);
	g_assert(unsent_save_pad_io!=NULL);
	char *expected_unsent_bytes=otb_assert_pad_read(unsent_save_pad_io, NULL, EXPECTED_DEFAULT_NEW_PAD_SIZE);
	g_assert(otb_pad_db_close_pad(save_pad_db));
	uuid_t expected_received_unique_id;
	uuid_generate(expected_received_unique_id);
	char expected_received_bytes[EXPECTED_DEFAULT_NEW_PAD_SIZE];
	g_assert(otb_random_bytes(expected_received_bytes, EXPECTED_DEFAULT_NEW_PAD_SIZE));
	OtbPadIO *received_save_pad_io=otb_pad_db_add_received_pad(save_pad_db, (const uuid_t*)&expected_received_unique_id, 10);
	g_assert(received_save_pad_io!=NULL);
	g_assert(otb_pad_write(received_save_pad_io, expected_received_bytes, EXPECTED_DEFAULT_NEW_PAD_SIZE));
	g_assert(otb_pad_db_close_pad(save_pad_db));
	OtbPadDb *load_pad_db=otb_pad_db_load_from_directory(pad_db_dir_path);
	g_assert(load_pad_db!=NULL);
	g_free(pad_db_dir_path);
	const uuid_t *actual_unsent_unique_id=otb_pad_db_fetch_random_rec_id_with_null_assertion(load_pad_db, OTB_PAD_REC_STATUS_UNSENT);
	g_assert_cmpint(0, ==, uuid_compare(*expected_unsent_unique_id, *actual_unsent_unique_id));
	const uuid_t *actual_received_unique_id=otb_pad_db_fetch_random_rec_id_with_null_assertion(load_pad_db, OTB_PAD_REC_STATUS_RECEIVED);
	g_assert_cmpint(0, ==, uuid_compare(expected_received_unique_id, *actual_received_unique_id));
	char actual_unsent_bytes[EXPECTED_DEFAULT_NEW_PAD_SIZE];
	OtbPadIO *unsent_load_pad_io=otb_pad_db_open_pad_for_read(load_pad_db, actual_unsent_unique_id);
	g_assert(unsent_load_pad_io!=NULL);
	otb_assert_pad_read(unsent_load_pad_io, expected_unsent_bytes, EXPECTED_DEFAULT_NEW_PAD_SIZE);
	g_assert(otb_pad_db_close_pad(load_pad_db));
	OtbPadIO *received_load_pad_io=otb_pad_db_open_pad_for_read(load_pad_db, actual_received_unique_id);
	otb_assert_pad_read(received_load_pad_io, expected_received_bytes, EXPECTED_DEFAULT_NEW_PAD_SIZE);
	g_assert(otb_pad_db_close_pad(load_pad_db));
	g_free(expected_unsent_bytes);
	g_object_unref(save_pad_db);
	g_object_unref(load_pad_db);
}

static uuid_t *otb_pad_db_add_received_pad_from_bytes(const OtbPadDb *pad_db, const char *bytes, off_t size)
{
	uuid_t *unique_id=g_malloc(sizeof(uuid_t));
	uuid_generate(*unique_id);
	OtbPadIO *pad_io=otb_pad_db_add_received_pad(pad_db, (const uuid_t*)unique_id, size);
	g_assert(pad_io!=NULL);
	g_assert(otb_pad_write(pad_io, bytes, size));
	g_assert(otb_pad_db_close_pad(pad_db));
	return unique_id;
}

static void test_add_received_pad()
{
	const off_t EXPECTED_PAD_SIZE=8;
	const char EXPECTED_PAD_BYTES[8]={0x43, 0x61, 0x7a, 0x5a, 0x6f, 0x4e, 0x53, 0x61};
	
	otb_test_setup_local_crypto();
	char *pad_db_dir_path=otb_generate_unique_test_subdir_path();
	OtbPadDb *pad_db=otb_pad_db_create_in_directory(pad_db_dir_path);
	g_assert(pad_db!=NULL);
	uuid_t *unique_id=otb_pad_db_add_received_pad_from_bytes(pad_db, EXPECTED_PAD_BYTES, EXPECTED_PAD_SIZE);
	g_assert_cmpint(EXPECTED_PAD_SIZE, ==, otb_pad_db_get_pad_size(pad_db, (const uuid_t*)unique_id));
	g_free(pad_db_dir_path);
	OtbPadIO *pad_io=otb_pad_db_open_pad_for_read(pad_db, (const uuid_t*)unique_id);
	g_free(unique_id);
	g_assert(pad_io!=NULL);
	otb_assert_pad_read(pad_io, EXPECTED_PAD_BYTES, EXPECTED_PAD_SIZE);
	g_assert(otb_pad_db_close_pad(pad_db));
	g_object_unref(pad_db);
}

static void test_get_random_rec_id()
{
	otb_test_setup_local_crypto();
	OtbPadDb *pad_db=otb_create_pad_db_in_random_test_path();
	g_assert(otb_pad_db_fetch_random_rec_id(pad_db, OTB_PAD_REC_STATUS_RECEIVED)==NULL);
	g_assert(otb_pad_db_fetch_random_rec_id(pad_db, OTB_PAD_REC_STATUS_SENT)==NULL);
	uuid_t expected_unique_id_1;
	uuid_generate(expected_unique_id_1);
	g_assert(otb_pad_db_add_received_pad(pad_db, (const uuid_t*)&expected_unique_id_1, 10)!=NULL);
	g_assert(otb_pad_db_close_pad(pad_db));
	const uuid_t *actual_unique_id=otb_pad_db_fetch_random_rec_id_with_null_assertion(pad_db, OTB_PAD_REC_STATUS_RECEIVED);
	g_assert_cmpint(0, ==, uuid_compare(expected_unique_id_1, *actual_unique_id));
	g_assert(otb_pad_db_fetch_random_rec_id(pad_db, OTB_PAD_REC_STATUS_SENT)==NULL);
	uuid_t expected_unique_id_2;
	uuid_generate(expected_unique_id_2);
	g_assert(otb_pad_db_add_received_pad(pad_db, (const uuid_t*)&expected_unique_id_2, 10)!=NULL);
	g_assert(otb_pad_db_close_pad(pad_db));
	actual_unique_id=otb_pad_db_fetch_random_rec_id_with_null_assertion(pad_db, OTB_PAD_REC_STATUS_RECEIVED);
	g_assert_cmpint(0, ==, (uuid_compare(expected_unique_id_1, *actual_unique_id) && uuid_compare(expected_unique_id_2, *actual_unique_id)));
	g_assert(otb_pad_db_fetch_random_rec_id(pad_db, OTB_PAD_REC_STATUS_SENT)==NULL);
	g_object_unref(pad_db);
}

static void test_close_pad_fails_when_nothing_is_opened()
{
	OtbPadDb *pad_db=otb_create_pad_db_in_random_test_path();
	g_assert(!otb_pad_db_close_pad(pad_db));
	g_object_unref(pad_db);
}

static void test_remove_rec()
{
	otb_test_setup_local_crypto();
	char *pad_db_dir_path=otb_generate_unique_test_subdir_path();
	OtbPadDb *pad_db=otb_pad_db_create_in_directory(pad_db_dir_path);
	g_assert(pad_db!=NULL);
	uuid_t unique_id_to_remove;
	uuid_generate(unique_id_to_remove);
	g_assert(otb_pad_db_add_received_pad(pad_db, (const uuid_t*)&unique_id_to_remove, 10)!=NULL);
	g_assert(otb_pad_db_close_pad(pad_db));
	uuid_t unique_id_to_keep;
	uuid_generate(unique_id_to_keep);
	g_assert(otb_pad_db_add_received_pad(pad_db, (const uuid_t*)&unique_id_to_keep, 10)!=NULL);
	g_assert(otb_pad_db_close_pad(pad_db));
	g_assert(otb_pad_db_remove_pad(pad_db, (const uuid_t*)&unique_id_to_remove));
	g_free(pad_db_dir_path);
	g_object_unref(pad_db);
}

static void test_remove_rec_that_does_not_exist()
{
	OtbPadDb *pad_db=otb_create_pad_db_in_random_test_path();
	uuid_t unique_id;
	uuid_generate(unique_id);
	g_assert(otb_pad_db_remove_pad(pad_db, (const uuid_t*)&unique_id));
	g_object_unref(pad_db);
}

static const uuid_t *otb_mark_random_pad_as_sent(const OtbPadDb *pad_db)
{
	const uuid_t *unique_id=otb_pad_db_fetch_random_rec_id_with_null_assertion(pad_db, OTB_PAD_REC_STATUS_UNSENT);
	g_assert(otb_pad_db_mark_pad_as_sent(pad_db, unique_id));
	return unique_id;
}

static void test_pad_rec_mark_as_sent()
{
	otb_test_setup_local_crypto();
	OtbPadDb *pad_db=otb_create_pad_db_in_random_test_path();
	g_assert(otb_pad_db_set_new_pad_min_size(pad_db, ABSOLUTE_MIN_PAD_SIZE));
	g_assert(otb_pad_db_set_new_pad_max_size(pad_db, ABSOLUTE_MIN_PAD_SIZE));
	g_assert(otb_pad_db_create_unsent_pad(pad_db));
	const uuid_t *expected_unique_id=otb_mark_random_pad_as_sent(pad_db);
	g_assert(otb_pad_db_fetch_random_rec_id(pad_db, OTB_PAD_REC_STATUS_UNSENT)==NULL);
	const uuid_t *actual_unique_id=otb_pad_db_fetch_random_rec_id_with_null_assertion(pad_db, OTB_PAD_REC_STATUS_SENT);
	g_assert_cmpint(0, ==, uuid_compare(*expected_unique_id, *actual_unique_id));
	g_object_unref(pad_db);
}

static char *otb_input_create_file(const char *pad_db_dir_path, const char *bytes, size_t number_of_bytes)
{
	char *input_file_path=g_strconcat(pad_db_dir_path, "/input_file", NULL);
	FILE *input_file=otb_open_for_write(input_file_path, "otb_input_create_file");
	g_assert(input_file!=NULL);
	g_assert_cmpint(number_of_bytes, ==, otb_write(bytes, sizeof(char), number_of_bytes, input_file, "otb_input_create_file"));
	g_assert(otb_close(input_file, "otb_input_create_file"));
	return input_file_path;
}

static void test_encryption_fails_due_to_not_enough_pad_bytes()
{
	const size_t MESSAGE_SIZE=1009;
	const char *EXPECTED_MESSAGE="I heartily accept the motto, \"That government is best which governs least\"; and I should like to see it acted up to more rapidly and systematically. Carried out, it finally amounts to this, which also I believe - \"That government is best which governs not at all\"; and when men are prepared for it, that will be the kind of government which they will have. Government is at best but an expedient; but most governments are usually, and all governments are sometimes, inexpedient. The objections which have been brought against a standing army, and they are many and weighty, and deserve to prevail, may also at last be brought against a standing government. The standing army is only an arm of the standing government. The government itself, which is only the mode which the people have chosen to execute their will, is equally liable to be abused and perverted before the people can act through it. Witness the present Mexican war, the work of comparatively a few individuals using the standing government as ";
	
	otb_test_setup_local_crypto();
	char *pad_db_dir_path=otb_generate_unique_test_subdir_path();
	OtbPadDb *pad_db=otb_pad_db_create_in_directory(pad_db_dir_path);
	g_assert(pad_db!=NULL);
	g_assert(otb_pad_db_set_new_pad_min_size(pad_db, ABSOLUTE_MIN_PAD_SIZE));
	g_assert(otb_pad_db_set_new_pad_max_size(pad_db, ABSOLUTE_MIN_PAD_SIZE));
	g_assert(otb_pad_db_create_unsent_pad(pad_db));
	otb_mark_random_pad_as_sent(pad_db);
	char *input_file_path=otb_input_create_file(pad_db_dir_path, EXPECTED_MESSAGE, MESSAGE_SIZE);
	char *output_file_path=g_strconcat(pad_db_dir_path, "/output_file", NULL);
	g_assert_cmpint(OTB_PAD_DB_CRYPT_RESULT_NOT_ENOUGH_PADS, ==, otb_pad_db_encrypt_file(pad_db, input_file_path, output_file_path));
	g_free(input_file_path);
	g_free(output_file_path);
	g_free(pad_db_dir_path);
	g_object_unref(pad_db);
}

static void test_encryption_with_one_pad()
{
	const size_t MESSAGE_SIZE=1008;
	const char *EXPECTED_MESSAGE="I heartily accept the motto, \"That government is best which governs least\"; and I should like to see it acted up to more rapidly and systematically. Carried out, it finally amounts to this, which also I believe - \"That government is best which governs not at all\"; and when men are prepared for it, that will be the kind of government which they will have. Government is at best but an expedient; but most governments are usually, and all governments are sometimes, inexpedient. The objections which have been brought against a standing army, and they are many and weighty, and deserve to prevail, may also at last be brought against a standing government. The standing army is only an arm of the standing government. The government itself, which is only the mode which the people have chosen to execute their will, is equally liable to be abused and perverted before the people can act through it. Witness the present Mexican war, the work of comparatively a few individuals using the standing government as";
	const size_t START_OF_ENCRYPTED_MESSAGE=sizeof(guint8)+sizeof(uuid_t);
	const off_t EXPECTED_ENCRYPTED_FILE_SIZE=START_OF_ENCRYPTED_MESSAGE+MESSAGE_SIZE;
	
	otb_test_setup_local_crypto();
	char *pad_db_dir_path=otb_generate_unique_test_subdir_path();
	OtbPadDb *pad_db=otb_pad_db_create_in_directory(pad_db_dir_path);
	g_assert(pad_db!=NULL);
	g_assert(otb_pad_db_set_new_pad_min_size(pad_db, ABSOLUTE_MIN_PAD_SIZE));
	g_assert(otb_pad_db_set_new_pad_max_size(pad_db, ABSOLUTE_MIN_PAD_SIZE));
	g_assert(otb_pad_db_create_unsent_pad(pad_db));
	const const uuid_t *expected_unique_id=otb_mark_random_pad_as_sent(pad_db);
	char *input_file_path=otb_input_create_file(pad_db_dir_path, EXPECTED_MESSAGE, MESSAGE_SIZE);
	char *output_file_path=g_strconcat(pad_db_dir_path, "/output_file", NULL);
	g_assert_cmpint(OTB_PAD_DB_CRYPT_RESULT_SUCCESS, ==, otb_pad_db_encrypt_file(pad_db, input_file_path, output_file_path));
	g_free(input_file_path);
	otb_assert_file_size(output_file_path, EXPECTED_ENCRYPTED_FILE_SIZE);
	FILE *output_file=otb_open_for_read(output_file_path, "test_encryption_with_one_pad");
	g_assert(output_file!=NULL);
	g_free(output_file_path);
	char encrypted_bytes[EXPECTED_ENCRYPTED_FILE_SIZE];
	g_assert_cmpint(EXPECTED_ENCRYPTED_FILE_SIZE, ==, otb_read(encrypted_bytes, sizeof(char), EXPECTED_ENCRYPTED_FILE_SIZE, output_file, "test_encryption_with_one_pad"));
	g_assert(!otb_file_has_more_bytes(output_file));
	g_assert(otb_close(output_file, "test_encryption_with_one_pad"));
	g_assert_cmpint(0, ==, (guint8)encrypted_bytes[0]);
	g_assert_cmpint(0, ==, uuid_compare(*expected_unique_id, *((uuid_t*)(encrypted_bytes+sizeof(guint8)))));
	OtbPadIO *pad_io=otb_pad_db_open_pad_for_read(pad_db, expected_unique_id);
	g_assert(pad_io!=NULL);
	char *pad_bytes=otb_assert_pad_read(pad_io, NULL, ABSOLUTE_MIN_PAD_SIZE);
	g_assert(otb_pad_db_close_pad(pad_db));
	for(size_t byte_index=0; byte_index<MESSAGE_SIZE; byte_index++)
		g_assert_cmpint(EXPECTED_MESSAGE[byte_index], ==, encrypted_bytes[byte_index+START_OF_ENCRYPTED_MESSAGE]^pad_bytes[byte_index]);
	g_free(pad_bytes);
	g_assert(otb_pad_db_fetch_random_rec_id(pad_db, OTB_PAD_REC_STATUS_SENT)==NULL);
	const const uuid_t *actual_unique_id=otb_pad_db_fetch_random_rec_id_with_null_assertion(pad_db, OTB_PAD_REC_STATUS_CONSUMED);
	g_assert_cmpint(0, ==, uuid_compare(*expected_unique_id, *actual_unique_id));
	g_free(pad_db_dir_path);
	g_object_unref(pad_db);
}

static void test_decryption_fails_due_to_unsupported_file_format()
{
	const guint8 FILE_FORMAT_VERSION='\xff';
	
	char *pad_db_dir_path=otb_generate_unique_test_subdir_path();
	OtbPadDb *pad_db=otb_pad_db_create_in_directory(pad_db_dir_path);
	g_assert(pad_db!=NULL);
	char *input_file_path=otb_input_create_file(pad_db_dir_path, (char*)&FILE_FORMAT_VERSION, sizeof(guint8));
	char *output_file_path=g_strconcat(pad_db_dir_path, "/output_file", NULL);
	g_assert_cmpint(OTB_PAD_DB_CRYPT_RESULT_UNSUPPORTED_FILE_FORMAT, ==, otb_pad_db_decrypt_file(pad_db, input_file_path, output_file_path));
	g_free(input_file_path);
	g_free(output_file_path);
	g_free(pad_db_dir_path);
	g_object_unref(pad_db);
}

static void test_decryption_fails_due_to_missing_pad()
{
	const guint8 FILE_FORMAT_VERSION='\x00';
	
	char *pad_db_dir_path=otb_generate_unique_test_subdir_path();
	OtbPadDb *pad_db=otb_pad_db_create_in_directory(pad_db_dir_path);
	g_assert(pad_db!=NULL);
	char input_file_bytes[sizeof(FILE_FORMAT_VERSION)+sizeof(uuid_t)];
	memcpy(input_file_bytes, &FILE_FORMAT_VERSION, sizeof(FILE_FORMAT_VERSION));
	char *input_file_path=otb_input_create_file(pad_db_dir_path, input_file_bytes, sizeof(guint8)+sizeof(uuid_t));
	char *output_file_path=g_strconcat(pad_db_dir_path, "/output_file", NULL);
	g_assert_cmpint(OTB_PAD_DB_CRYPT_RESULT_MISSING_PAD, ==, otb_pad_db_decrypt_file(pad_db, input_file_path, output_file_path));
	g_free(input_file_path);
	g_free(output_file_path);
	g_free(pad_db_dir_path);
	g_object_unref(pad_db);
}

static void test_pad_db_get_pad_size()
{
	otb_test_setup_local_crypto();
	OtbPadDb *pad_db=otb_create_pad_db_in_random_test_path();
	g_assert(otb_pad_db_set_new_pad_min_size(pad_db, ABSOLUTE_MIN_PAD_SIZE));
	g_assert(otb_pad_db_set_new_pad_max_size(pad_db, ABSOLUTE_MIN_PAD_SIZE));
	g_assert(otb_pad_db_create_unsent_pad(pad_db));
	const uuid_t *unique_id=otb_mark_random_pad_as_sent(pad_db);
	g_assert(unique_id!=NULL);
	g_assert_cmpint(ABSOLUTE_MIN_PAD_SIZE, ==, otb_pad_db_get_pad_size(pad_db, unique_id));
	g_object_unref(pad_db);
}

static void test_pad_db_get_pad_size_range()
{
	otb_test_setup_local_crypto();
	OtbPadDb *pad_db=otb_create_pad_db_in_random_test_path();
	g_assert(otb_pad_db_set_new_pad_min_size(pad_db, ABSOLUTE_MIN_PAD_SIZE));
	g_assert(otb_pad_db_set_new_pad_max_size(pad_db, ABSOLUTE_MIN_PAD_SIZE*2));
	g_assert(otb_pad_db_create_unsent_pad(pad_db));
	const uuid_t *unique_id=otb_mark_random_pad_as_sent(pad_db);
	g_assert(unique_id!=NULL);
	g_assert_cmpint(ABSOLUTE_MIN_PAD_SIZE, <=, otb_pad_db_get_pad_size(pad_db, unique_id));
	g_assert_cmpint(ABSOLUTE_MIN_PAD_SIZE*2, >=, otb_pad_db_get_pad_size(pad_db, unique_id));
	g_object_unref(pad_db);
}

static void otb_send_random_pad(const OtbPadDb *sender_pad_db, const OtbPadDb *recipient_pad_db)
{
	const uuid_t *unique_id=otb_mark_random_pad_as_sent(sender_pad_db);
	OtbPadIO *output_pad_io=otb_pad_db_add_received_pad(recipient_pad_db, unique_id, otb_pad_db_get_pad_size(sender_pad_db, unique_id));
	OtbPadIO *input_pad_io=otb_pad_db_open_pad_for_read(sender_pad_db, unique_id);
	while(otb_pad_has_more_bytes(input_pad_io))
	{
		char byte;
		g_assert(otb_pad_read_byte(input_pad_io, &byte));
		g_assert(otb_pad_write(output_pad_io, &byte, sizeof byte));
	}
	g_assert(otb_pad_db_close_pad(sender_pad_db));
	g_assert(otb_pad_db_close_pad(recipient_pad_db));
}

static void otb_send_random_pads(const OtbPadDb *sender_pad_db, const OtbPadDb *recipient_pad_db, size_t number_of_pads)
{
	for(size_t iter=0; iter<number_of_pads; iter++)
		otb_send_random_pad(sender_pad_db, recipient_pad_db);
}

static char *otb_encrypt_file_for_two_pad_test(const char *pad_db_dir_path, const OtbPadDb *pad_db, const char *message, size_t message_size)
{
	char *input_file_path=g_strconcat(pad_db_dir_path, "/original_file", NULL);
	FILE *input_file=otb_open_for_write(input_file_path, "otb_encrypt_file_for_two_pad_test");
	g_assert(input_file!=NULL);
	g_assert_cmpint(message_size, ==, otb_write(message, sizeof(char), message_size, input_file, "otb_encrypt_file_for_two_pad_test"));
	g_assert(otb_close(input_file, "otb_encrypt_file_for_two_pad_test"));
	char *encrypted_file_path=g_strconcat(pad_db_dir_path, "/encrypted_file", NULL);
	g_assert_cmpint(OTB_PAD_DB_CRYPT_RESULT_SUCCESS, ==, otb_pad_db_encrypt_file(pad_db, input_file_path, encrypted_file_path));
	g_free(input_file_path);
	otb_assert_number_of_pads_in_status(pad_db, 1, OTB_PAD_REC_STATUS_UNSENT);
	otb_assert_number_of_pads_in_status(pad_db, 1, OTB_PAD_REC_STATUS_SENT);
	otb_assert_number_of_pads_in_status(pad_db, 2, OTB_PAD_REC_STATUS_CONSUMED);
	return encrypted_file_path;
}

static void otb_pad_db_create_unsent_pads(const OtbPadDb *pad_db, size_t number_of_pads)
{
	for(size_t iter=0; iter<number_of_pads; iter++)
		g_assert(otb_pad_db_create_unsent_pad(pad_db));
}

static void test_encryption_decryption_with_two_pads()
{
	const size_t MESSAGE_SIZE=2016;
	const char *EXPECTED_MESSAGE="I heartily accept the motto, \"That government is best which governs least\"; and I should like to see it acted up to more rapidly and systematically. Carried out, it finally amounts to this, which also I believe - \"That government is best which governs not at all\"; and when men are prepared for it, that will be the kind of government which the will have. Government is at best but an expedient; but most governments are usually, and all governments are sometimes, inexpedient. The objections which have been brought against a standing army, and they are many and weighty, and deserve to prevail, may also at last be brought against a standing government. The standing army is only an arm of the standing government. The government itself, which is only the mode which the people have chosen to execute their will, is equally liable to be abused and perverted before the people can act through it. Witness the present Mexican war, the work of comparatively a few individuals using the standing government as their tool; for in the outset, the people would not have consented to this measure. This American government - what is it but a tradition, though a recent one, endeavoring to transmit itself unimpaired to posterity, but each instant losing some of its integrity? It has not the vitality and force of a single living man; for a single man can bend it to his will. It is a sort of wooden gun to the people themselves. But it is not the less necessary for this; for the people must have some complicated machinery or other, and hear its din, to satisfy that idea of government which they have. Governments show thus how successfully men can be imposed upon, even impose on themselves, for their own advantage. It is excellent, we must all allow. Yet this government never of itself furthered any enterprise, but by the alacrity with which it got out of its way. It does not keep the country free. It does not settle the West. It does not educate. The character inherent in the American people has done all that.";
	
	otb_test_setup_local_crypto();
	char *sender_pad_db_dir_path=otb_generate_unique_test_subdir_path();
	OtbPadDb *sender_pad_db=otb_pad_db_create_in_directory(sender_pad_db_dir_path);
	g_assert(sender_pad_db!=NULL);
	char *recipient_pad_db_dir_path=otb_generate_unique_test_subdir_path();
	OtbPadDb *recipient_pad_db=otb_pad_db_create_in_directory(recipient_pad_db_dir_path);
	g_assert(recipient_pad_db!=NULL);
	g_assert(otb_pad_db_set_new_pad_min_size(sender_pad_db, ABSOLUTE_MIN_PAD_SIZE));
	g_assert(otb_pad_db_set_new_pad_max_size(sender_pad_db, ABSOLUTE_MIN_PAD_SIZE));
	otb_pad_db_create_unsent_pads(sender_pad_db, 4);
	otb_send_random_pads(sender_pad_db, recipient_pad_db, 3);
	char *encrypted_file_path=otb_encrypt_file_for_two_pad_test(sender_pad_db_dir_path, sender_pad_db, EXPECTED_MESSAGE, MESSAGE_SIZE);
	g_free(sender_pad_db_dir_path);
	g_object_unref(sender_pad_db);
	char *decrypted_file_path=g_strconcat(recipient_pad_db_dir_path, "/decrypted_file", NULL);
	g_free(recipient_pad_db_dir_path);
	g_assert_cmpint(OTB_PAD_DB_CRYPT_RESULT_SUCCESS, ==, otb_pad_db_decrypt_file(recipient_pad_db, encrypted_file_path, decrypted_file_path));
	otb_assert_number_of_pads_in_status(recipient_pad_db, 1, OTB_PAD_REC_STATUS_RECEIVED);
	g_object_unref(recipient_pad_db);
	FILE *decrypted_file=otb_open_for_read(decrypted_file_path, "test_encryption_decryption_with_two_pads");
	g_assert(decrypted_file!=NULL);
	char actual_message[MESSAGE_SIZE];
	g_assert_cmpint(MESSAGE_SIZE, ==, otb_read(actual_message, sizeof(char), MESSAGE_SIZE, decrypted_file, "test_encryption_decryption_with_two_pads"));
	g_assert(!otb_file_has_more_bytes(decrypted_file));
	g_assert(otb_close(decrypted_file, "test_encryption_decryption_with_two_pads"));
	g_assert_cmpint(0, ==, memcmp(EXPECTED_MESSAGE, actual_message, MESSAGE_SIZE));
	g_free(decrypted_file_path);
	g_free(encrypted_file_path);
}

void add_pad_db_tests()
{
	add_test_func("/pad-db/test_set_new_pad_size", test_set_new_pad_size);
	add_test_func("/pad-db/test_otb_pad_db_io", test_otb_pad_db_io);
	add_test_func("/pad-db/test_otb_pad_db_rejects_pads_too_large", test_otb_pad_db_rejects_pads_too_large);
	add_test_func("/pad-db/test_otb_pad_db_rejects_pads_duplicate_id", test_otb_pad_db_rejects_pads_duplicate_id);
	add_test_func("/pad-db/test_create_unsent_pad_results_in_proper_pad_file", test_create_unsent_pad_results_in_proper_pad_file);
	add_test_func("/pad-db/test_pads_save_and_load", test_pads_save_and_load);
	add_test_func("/pad-db/test_add_received_pad", test_add_received_pad);
	add_test_func("/pad-db/test_get_random_rec_id", test_get_random_rec_id);
	add_test_func("/pad-db/test_close_pad_fails_when_nothing_is_opened", test_close_pad_fails_when_nothing_is_opened);
	add_test_func("/pad-db/test_remove_rec", test_remove_rec);
	add_test_func("/pad-db/test_remove_rec_that_does_not_exist", test_remove_rec_that_does_not_exist);
	add_test_func("/pad-db/test_pad_rec_mark_as_sent", test_pad_rec_mark_as_sent);
	add_test_func("/pad-db/test_encryption_fails_due_to_not_enough_pad_bytes", test_encryption_fails_due_to_not_enough_pad_bytes);
	add_test_func("/pad-db/test_encryption_with_one_pad", test_encryption_with_one_pad);
	add_test_func("/pad-db/test_decryption_fails_due_to_unsupported_file_format", test_decryption_fails_due_to_unsupported_file_format);
	add_test_func("/pad-db/test_decryption_fails_due_to_missing_pad", test_decryption_fails_due_to_missing_pad);
	add_test_func("/pad-db/test_pad_db_get_pad_size", test_pad_db_get_pad_size);
	add_test_func("/pad-db/test_pad_db_get_pad_size_range", test_pad_db_get_pad_size_range);
	add_test_func("/pad-db/test_encryption_decryption_with_two_pads", test_encryption_decryption_with_two_pads);
}
