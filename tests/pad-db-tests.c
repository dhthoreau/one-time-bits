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
#include "pad-db-tests.h"
#include "pad-rec-tests.h"
#include "test-utils.h"
#include "../src/io.h"
#include "../src/pad-db.h"
#include "../src/pad-rec.h"
#include "../src/random.h"

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
	const long long EXPECTED_DEFAULT_NEW_PAD_EXPIRATION=31536000000000;

	off_t actual_max_size;
	off_t actual_new_pad_min;
	off_t actual_new_pad_max;
	long long actual_new_pad_expiration;
	g_object_get(pad_db, OTB_PAD_DB_PROP_MAX_SIZE, &actual_max_size, OTB_PAD_DB_PROP_NEW_PAD_MIN_SIZE, &actual_new_pad_min, OTB_PAD_DB_PROP_NEW_PAD_MAX_SIZE, &actual_new_pad_max, OTB_PAD_DB_PROP_NEW_PAD_EXPIRATION, &actual_new_pad_expiration, NULL);
	g_assert_cmpint(EXPECTED_DEFAULT_MAX_SIZE, ==, actual_max_size);
	g_assert_cmpint(EXPECTED_DEFAULT_NEW_PAD_MIN_SIZE, ==, actual_new_pad_min);
	g_assert_cmpint(EXPECTED_DEFAULT_NEW_PAD_MAX_SIZE, ==, actual_new_pad_max);
	g_assert_cmpint(EXPECTED_DEFAULT_NEW_PAD_EXPIRATION, ==, actual_new_pad_expiration);
}

static void otb_assert_set_max_size(OtbPadDb *pad_db, off_t max_size)
{
	g_assert(otb_pad_db_set_max_size(pad_db, max_size));
	off_t actual_max_size;
	g_object_get(pad_db, OTB_PAD_DB_PROP_MAX_SIZE, &actual_max_size, NULL);
	g_assert_cmpint(max_size, ==, actual_max_size);
}

static void otb_assert_set_new_pad_min_size(OtbPadDb *pad_db, off_t new_pad_min_size)
{
	g_assert(otb_pad_db_set_new_pad_min_size(pad_db, new_pad_min_size));
	off_t actual_new_pad_min_size;
	g_object_get(pad_db, OTB_PAD_DB_PROP_NEW_PAD_MIN_SIZE, &actual_new_pad_min_size, NULL);
	g_assert_cmpint(new_pad_min_size, ==, actual_new_pad_min_size);
}

static void otb_assert_set_new_pad_max_size(OtbPadDb *pad_db, off_t new_pad_max_size)
{
	g_assert(otb_pad_db_set_new_pad_max_size(pad_db, new_pad_max_size));
	off_t actual_new_pad_max_size;
	g_object_get(pad_db, OTB_PAD_DB_PROP_NEW_PAD_MAX_SIZE, &actual_new_pad_max_size, NULL);
	g_assert_cmpint(new_pad_max_size, ==, actual_new_pad_max_size);
}

static void otb_assert_set_new_pad_expiration(OtbPadDb *pad_db, long long new_pad_expiration)
{
	g_assert(otb_pad_db_set_new_pad_expiration(pad_db, new_pad_expiration));
	long long actual_new_pad_expiration;
	g_object_get(pad_db, OTB_PAD_DB_PROP_NEW_PAD_EXPIRATION, &actual_new_pad_expiration, NULL);
	g_assert_cmpint(new_pad_expiration, ==, actual_new_pad_expiration);
}

static void otb_create_db_in_path_with_custom_property_values(const char *pad_db_dir_path, off_t max_size, off_t new_pad_min_size, off_t new_pad_max_size, long long new_pad_expiration)
{
	OtbPadDb *pad_db=otb_pad_db_create_in_directory(pad_db_dir_path);
	g_assert(pad_db!=NULL);
	otb_assert_pad_db_default_property_values(pad_db);
	otb_assert_set_max_size(pad_db, max_size);
	otb_assert_set_new_pad_min_size(pad_db, new_pad_min_size);
	otb_assert_set_new_pad_max_size(pad_db, new_pad_max_size);
	otb_assert_set_new_pad_expiration(pad_db, new_pad_expiration);
	g_object_unref(pad_db);
	otb_assert_pad_db_file_exists(pad_db_dir_path);
}

static void otb_load_db_from_path_with_custom_property_values(const char *pad_db_dir_path, off_t max_size, off_t new_pad_min_size, off_t new_pad_max_size, long long new_pad_expiration)
{
	OtbPadDb *pad_db=otb_pad_db_load_from_directory(pad_db_dir_path);
	g_assert(pad_db!=NULL);
	off_t actual_max_size;
	off_t actual_new_pad_min;
	off_t actual_new_pad_max;
	long long actual_new_pad_expiration;
	g_object_get(pad_db, OTB_PAD_DB_PROP_MAX_SIZE, &actual_max_size, OTB_PAD_DB_PROP_NEW_PAD_MIN_SIZE, &actual_new_pad_min, OTB_PAD_DB_PROP_NEW_PAD_MAX_SIZE, &actual_new_pad_max, OTB_PAD_DB_PROP_NEW_PAD_EXPIRATION, &actual_new_pad_expiration, NULL);
	g_assert_cmpint(max_size, ==, actual_max_size);
	g_assert_cmpint(new_pad_min_size, ==, actual_new_pad_min);
	g_assert_cmpint(new_pad_max_size, ==, actual_new_pad_max);
	g_assert_cmpint(new_pad_expiration, ==, actual_new_pad_expiration);
	g_object_unref(pad_db);
}

static void test_otb_pad_db_io()
{
	const off_t EXPECTED_MAX_SIZE=1234567890;
	const off_t EXPECTED_NEW_PAD_MIN_SIZE=12345678;
	const off_t EXPECTED_NEW_PAD_MAX_SIZE=123456789;
	const long long EXPECTED_NEW_PAD_EXPIRATION=123400000000;
	
	char *pad_db_dir_path=otb_generate_unique_test_subdir_path();
	otb_create_db_in_path_with_custom_property_values(pad_db_dir_path, EXPECTED_MAX_SIZE, EXPECTED_NEW_PAD_MIN_SIZE, EXPECTED_NEW_PAD_MAX_SIZE, EXPECTED_NEW_PAD_EXPIRATION);
	otb_load_db_from_path_with_custom_property_values(pad_db_dir_path, EXPECTED_MAX_SIZE, EXPECTED_NEW_PAD_MIN_SIZE, EXPECTED_NEW_PAD_MAX_SIZE, EXPECTED_NEW_PAD_EXPIRATION);
	g_free(pad_db_dir_path);
}

static void otb_assert_number_of_pads_in_status(const OtbPadDb *pad_db, size_t expected_number, OtbPadRecStatus pad_rec_status)
{
	GSList *pad_unique_ids=otb_pad_db_get_ids_of_pads_in_status(pad_db, pad_rec_status);
	g_assert_cmpint(expected_number, ==, g_slist_length(pad_unique_ids));
	g_slist_free_full(pad_unique_ids, (GDestroyNotify)otb_unique_id_unref);
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
	OtbUniqueId *unique_id=otb_unique_id_new();
	long long few_months_from_now=otb_few_months_from_now();
	g_assert(otb_pad_db_add_incoming_pad(pad_db, unique_id, ABSOLUTE_MIN_PAD_SIZE, few_months_from_now)==NULL);
	otb_unique_id_unref(unique_id);
	g_object_unref(pad_db);
}

static void test_otb_pad_db_rejects_pads_duplicate_id()
{
	const size_t ARBITRARY_SIZE=10;
	
	otb_test_setup_local_crypto();
	OtbPadDb *pad_db=otb_create_pad_db_in_random_test_path();
	OtbUniqueId *unique_id=otb_unique_id_new();
	long long few_months_from_now=otb_few_months_from_now();
	OtbPadIO *pad_io=otb_pad_db_add_incoming_pad(pad_db, unique_id, ARBITRARY_SIZE, few_months_from_now);
	g_assert(pad_io!=NULL);
	g_assert(otb_pad_db_close_pad(pad_db, pad_io));
	g_assert(otb_pad_db_add_incoming_pad(pad_db, unique_id, ARBITRARY_SIZE, few_months_from_now)==NULL);
	otb_unique_id_unref(unique_id);
	g_object_unref(pad_db);
}

static OtbUniqueId *otb_pad_db_fetch_random_rec_id_with_null_assertion(const OtbPadDb *pad_db, OtbPadRecStatus status)
{
	OtbUniqueId *unique_id=otb_pad_db_fetch_random_rec_id(pad_db, status);
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
	otb_unique_id_unref(otb_pad_db_fetch_random_rec_id_with_null_assertion(pad_db, OTB_PAD_REC_STATUS_UNSENT));
	g_free(pad_db_dir_path);
	g_object_unref(pad_db);
}

static void *otb_assert_pad_read(OtbPadIO *pad_io, const unsigned char *expected_bytes, size_t expected_bytes_size)
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

static void otb_assert_expiration(const OtbPadDb *pad_db, const OtbUniqueId* pad_unique_id, long long expected_expiration)
{
	const long long MICROSECONDS_PER_SECOND=1000000;
	
	long long actual_expiration=otb_pad_db_get_pad_expiration(pad_db, pad_unique_id);
	g_assert_cmpint(0, ==, (actual_expiration-expected_expiration)/MICROSECONDS_PER_SECOND);
}

static void otb_assert_save_pad_db(const char *pad_db_dir_path, off_t default_new_pad_size, OtbUniqueId **expected_unsent_unique_id_out, long long *expected_unsent_expiration_out, unsigned char **expected_unsent_bytes_out, OtbUniqueId **expected_incoming_unique_id_out, long long *expected_incoming_expiration_out, unsigned char **expected_incoming_bytes_out)
{
	const off_t INCOMING_PAD_SIZE=10;
	const long long NEW_PAD_EXPIRATION_ONE_MONTH=2629822965840;
	
	OtbPadDb *save_pad_db=otb_pad_db_create_in_directory(pad_db_dir_path);
	g_assert(save_pad_db!=NULL);
	g_assert(g_file_test(pad_db_dir_path, G_FILE_TEST_EXISTS));
	g_assert(otb_pad_db_set_new_pad_min_size(save_pad_db, default_new_pad_size));
	g_assert(otb_pad_db_set_new_pad_max_size(save_pad_db, default_new_pad_size));
	g_assert(otb_pad_db_set_new_pad_expiration(save_pad_db, NEW_PAD_EXPIRATION_ONE_MONTH));
	*expected_unsent_expiration_out=g_get_real_time()+MICROSECONDS_PER_MONTH;
	g_assert(otb_pad_db_create_unsent_pad(save_pad_db));
	*expected_unsent_unique_id_out=otb_pad_db_fetch_random_rec_id_with_null_assertion(save_pad_db, OTB_PAD_REC_STATUS_UNSENT);
	OtbPadIO *unsent_save_pad_io=otb_pad_db_open_pad_for_read(save_pad_db, *expected_unsent_unique_id_out);
	g_assert(unsent_save_pad_io!=NULL);
	*expected_unsent_bytes_out=otb_assert_pad_read(unsent_save_pad_io, NULL, default_new_pad_size);
	g_assert(otb_pad_db_close_pad(save_pad_db, unsent_save_pad_io));
	*expected_incoming_unique_id_out=otb_unique_id_new();
	*expected_incoming_bytes_out=g_malloc(default_new_pad_size);
	g_assert(otb_random_bytes(*expected_incoming_bytes_out, default_new_pad_size));
	*expected_incoming_expiration_out=otb_few_months_from_now();
	OtbPadIO *incoming_save_pad_io=otb_pad_db_add_incoming_pad(save_pad_db, *expected_incoming_unique_id_out, INCOMING_PAD_SIZE, *expected_incoming_expiration_out);
	g_assert(incoming_save_pad_io!=NULL);
	g_assert(otb_pad_write(incoming_save_pad_io, *expected_incoming_bytes_out, default_new_pad_size));
	g_assert(otb_pad_db_close_pad(save_pad_db, incoming_save_pad_io));
	g_object_unref(save_pad_db);
}

static void otb_assert_pad_db_loaded_pad_rec(OtbPadDb *pad_db, OtbPadRecStatus status, off_t default_new_pad_size, const OtbUniqueId* expected_unique_id, long long expected_expiration, const unsigned char *expected_bytes)
{
	OtbUniqueId *actual_unique_id=otb_pad_db_fetch_random_rec_id_with_null_assertion(pad_db, status);
	g_assert_cmpint(0, ==, otb_unique_id_compare(expected_unique_id, actual_unique_id));
	otb_assert_expiration(pad_db, actual_unique_id, expected_expiration);
	OtbPadIO *pad_io=otb_pad_db_open_pad_for_read(pad_db, actual_unique_id);
	g_assert(pad_io!=NULL);
	otb_assert_pad_read(pad_io, expected_bytes, default_new_pad_size);
	g_assert(otb_pad_db_close_pad(pad_db, pad_io));
	otb_unique_id_unref(actual_unique_id);
}

static void otb_assert_load_pad_db(const char *pad_db_dir_path, off_t default_new_pad_size, const OtbUniqueId *expected_unsent_unique_id, long long expected_unsent_expiration, const unsigned char *expected_unsent_bytes, const OtbUniqueId *expected_incoming_unique_id, long long expected_incoming_expiration, const unsigned char *expected_incoming_bytes)
{
	OtbPadDb *load_pad_db=otb_pad_db_load_from_directory(pad_db_dir_path);
	g_assert(load_pad_db!=NULL);
	otb_assert_pad_db_loaded_pad_rec(load_pad_db, OTB_PAD_REC_STATUS_UNSENT, default_new_pad_size, expected_unsent_unique_id, expected_unsent_expiration, expected_unsent_bytes);
	otb_assert_pad_db_loaded_pad_rec(load_pad_db, OTB_PAD_REC_STATUS_INCOMING, default_new_pad_size, expected_incoming_unique_id, expected_incoming_expiration, expected_incoming_bytes);
	g_assert(otb_pad_db_delete(load_pad_db));
	otb_assert_file_does_not_exist(pad_db_dir_path);
	g_object_unref(load_pad_db);
}

static void test_pads_save_load_delete()
{
	const off_t EXPECTED_DEFAULT_NEW_PAD_SIZE=10240;
	
	otb_test_setup_local_crypto();
	char *pad_db_dir_path=otb_generate_unique_test_subdir_path();
	OtbUniqueId *expected_unsent_unique_id=NULL;
	long long expected_unsent_expiration=-1;
	unsigned char *expected_unsent_bytes=NULL;
	OtbUniqueId *expected_incoming_unique_id=NULL;
	long long expected_incoming_expiration=-1;
	unsigned char *expected_incoming_bytes=NULL;
	otb_assert_save_pad_db(pad_db_dir_path, EXPECTED_DEFAULT_NEW_PAD_SIZE, &expected_unsent_unique_id, &expected_unsent_expiration, &expected_unsent_bytes, &expected_incoming_unique_id, &expected_incoming_expiration, &expected_incoming_bytes);
	otb_assert_load_pad_db(pad_db_dir_path, EXPECTED_DEFAULT_NEW_PAD_SIZE, expected_unsent_unique_id, expected_unsent_expiration, expected_unsent_bytes, expected_incoming_unique_id, expected_incoming_expiration, expected_incoming_bytes);
	g_free(expected_incoming_bytes);
	g_free(expected_unsent_bytes);
	otb_unique_id_unref(expected_incoming_unique_id);
	otb_unique_id_unref(expected_unsent_unique_id);
	g_free(pad_db_dir_path);
}

static OtbUniqueId *otb_pad_db_add_incoming_pad_from_bytes(const OtbPadDb *pad_db, const unsigned char *bytes, off_t size, long long expiration)
{
	OtbUniqueId *unique_id=otb_unique_id_new();
	OtbPadIO *pad_io=otb_pad_db_add_incoming_pad(pad_db, unique_id, size, expiration);
	g_assert(pad_io!=NULL);
	g_assert(otb_pad_write(pad_io, bytes, size));
	g_assert(otb_pad_db_close_pad(pad_db, pad_io));
	return unique_id;
}

static void test_add_incoming_pad()
{
	const off_t EXPECTED_PAD_SIZE=8;
	const unsigned char EXPECTED_PAD_BYTES[8]={0x43, 0x61, 0x7a, 0x5a, 0x6f, 0x4e, 0x53, 0x61};
	
	otb_test_setup_local_crypto();
	char *pad_db_dir_path=otb_generate_unique_test_subdir_path();
	OtbPadDb *pad_db=otb_pad_db_create_in_directory(pad_db_dir_path);
	g_assert(pad_db!=NULL);
	long long expected_expiration=otb_few_months_from_now();
	OtbUniqueId *unique_id=otb_pad_db_add_incoming_pad_from_bytes(pad_db, EXPECTED_PAD_BYTES, EXPECTED_PAD_SIZE, expected_expiration);
	g_assert_cmpint(EXPECTED_PAD_SIZE, ==, otb_pad_db_get_pad_size(pad_db, unique_id));
	g_free(pad_db_dir_path);
	OtbPadIO *pad_io=otb_pad_db_open_pad_for_read(pad_db, unique_id);
	otb_unique_id_unref(unique_id);
	g_assert(pad_io!=NULL);
	otb_assert_pad_read(pad_io, EXPECTED_PAD_BYTES, EXPECTED_PAD_SIZE);
	g_assert(otb_pad_db_close_pad(pad_db, pad_io));
	otb_assert_expiration(pad_db, unique_id, expected_expiration);
	g_object_unref(pad_db);
}

static void test_get_random_rec_id()
{
	otb_test_setup_local_crypto();
	OtbPadDb *pad_db=otb_create_pad_db_in_random_test_path();
	long long expiration=otb_few_months_from_now();
	g_assert(otb_pad_db_fetch_random_rec_id(pad_db, OTB_PAD_REC_STATUS_INCOMING)==NULL);
	g_assert(otb_pad_db_fetch_random_rec_id(pad_db, OTB_PAD_REC_STATUS_SENT)==NULL);
	OtbUniqueId *expected_unique_id_1=otb_unique_id_new();
	OtbPadIO *pad_io1=otb_pad_db_add_incoming_pad(pad_db, expected_unique_id_1, 10, expiration);
	g_assert(pad_io1!=NULL);
	g_assert(otb_pad_db_close_pad(pad_db, pad_io1));
	OtbUniqueId *actual_unique_id1=otb_pad_db_fetch_random_rec_id_with_null_assertion(pad_db, OTB_PAD_REC_STATUS_INCOMING);
	g_assert_cmpint(0, ==, otb_unique_id_compare(expected_unique_id_1, actual_unique_id1));
	g_assert(otb_pad_db_fetch_random_rec_id(pad_db, OTB_PAD_REC_STATUS_SENT)==NULL);
	OtbUniqueId *expected_unique_id_2=otb_unique_id_new();
	OtbPadIO *pad_io2=otb_pad_db_add_incoming_pad(pad_db, expected_unique_id_2, 10, expiration);
	g_assert(pad_io2!=NULL);
	g_assert(otb_pad_db_close_pad(pad_db, pad_io2));
	OtbUniqueId *actual_unique_id2=otb_pad_db_fetch_random_rec_id_with_null_assertion(pad_db, OTB_PAD_REC_STATUS_INCOMING);
	g_assert_cmpint(0, ==, (otb_unique_id_compare(expected_unique_id_1, actual_unique_id2) && otb_unique_id_compare(expected_unique_id_2, actual_unique_id2)));
	g_assert(otb_pad_db_fetch_random_rec_id(pad_db, OTB_PAD_REC_STATUS_SENT)==NULL);
	otb_unique_id_unref(actual_unique_id2);
	otb_unique_id_unref(expected_unique_id_2);
	otb_unique_id_unref(actual_unique_id1);
	otb_unique_id_unref(expected_unique_id_1);
	g_object_unref(pad_db);
}

static void test_otb_pad_db_get_ids_of_pads_in_status()
{
	otb_test_setup_local_crypto();
	OtbPadDb *pad_db=otb_create_pad_db_in_random_test_path();
	long long expiration=otb_few_months_from_now();
	OtbUniqueId *expected_unique_id_1=otb_unique_id_new();
	OtbPadIO *pad_io1=otb_pad_db_add_incoming_pad(pad_db, expected_unique_id_1, 10, expiration);
	g_assert(pad_io1!=NULL);
	g_assert(otb_pad_db_close_pad(pad_db, pad_io1));
	OtbUniqueId *expected_unique_id_2=otb_unique_id_new();
	OtbPadIO *pad_io2=otb_pad_db_add_incoming_pad(pad_db, expected_unique_id_2, 10, expiration);
	g_assert(pad_io2!=NULL);
	g_assert(otb_pad_db_close_pad(pad_db, pad_io2));
	GSList *actual_unique_ids=otb_pad_db_get_ids_of_pads_in_status(pad_db, OTB_PAD_REC_STATUS_INCOMING);
	g_assert_cmpint(2, ==, g_slist_length(actual_unique_ids));
	g_assert(g_slist_find_custom(actual_unique_ids, expected_unique_id_1, (GCompareFunc)otb_unique_id_compare)!=NULL);
	g_assert(g_slist_find_custom(actual_unique_ids, expected_unique_id_2, (GCompareFunc)otb_unique_id_compare)!=NULL);
	g_slist_free_full(actual_unique_ids, (GDestroyNotify)otb_unique_id_unref);
	otb_unique_id_unref(expected_unique_id_2);
	otb_unique_id_unref(expected_unique_id_1);
	g_object_unref(pad_db);
}

static void test_close_pad_fails_when_nothing_is_opened()
{
	OtbPadDb *pad_db=otb_create_pad_db_in_random_test_path();
	g_assert(!otb_pad_db_close_pad(pad_db, NULL));
	void *dummy_pad_io=g_malloc(sizeof (unsigned char));
	g_assert(!otb_pad_db_close_pad(pad_db, dummy_pad_io));
	g_free(dummy_pad_io);
	g_object_unref(pad_db);
}

static void test_remove_rec()
{
	const off_t INCOMING_PAD_SIZE=10;
	
	otb_test_setup_local_crypto();
	char *pad_db_dir_path=otb_generate_unique_test_subdir_path();
	OtbPadDb *pad_db=otb_pad_db_create_in_directory(pad_db_dir_path);
	g_assert(pad_db!=NULL);
	long long expiration=otb_few_months_from_now();
	OtbUniqueId *unique_id_to_remove=otb_unique_id_new();
	OtbPadIO *pad_io_remove=otb_pad_db_add_incoming_pad(pad_db, unique_id_to_remove, INCOMING_PAD_SIZE, expiration);
	g_assert(pad_io_remove!=NULL);
	g_assert(otb_pad_db_close_pad(pad_db, pad_io_remove));
	OtbUniqueId *unique_id_to_keep=otb_unique_id_new();
	OtbPadIO *pad_io_keep=otb_pad_db_add_incoming_pad(pad_db, unique_id_to_keep, INCOMING_PAD_SIZE, expiration);
	g_assert(pad_io_keep!=NULL);
	g_assert(otb_pad_db_close_pad(pad_db, pad_io_keep));
	g_assert(otb_pad_db_remove_pad(pad_db, unique_id_to_remove));
	otb_unique_id_unref(unique_id_to_keep);
	otb_unique_id_unref(unique_id_to_remove);
	g_free(pad_db_dir_path);
	g_object_unref(pad_db);
}

static void test_remove_rec_that_does_not_exist()
{
	OtbPadDb *pad_db=otb_create_pad_db_in_random_test_path();
	OtbUniqueId *unique_id=otb_unique_id_new();
	g_assert(otb_pad_db_remove_pad(pad_db, unique_id));
	otb_unique_id_unref(unique_id);
	g_object_unref(pad_db);
}

static void test_remove_expired_pads()
{
	const off_t INCOMING_PAD_SIZE=10;
	
	otb_test_setup_local_crypto();
	char *pad_db_dir_path=otb_generate_unique_test_subdir_path();
	OtbPadDb *pad_db=otb_pad_db_create_in_directory(pad_db_dir_path);
	g_assert(pad_db!=NULL);
	OtbUniqueId *pad_unique_id_to_expire=otb_unique_id_new();
	OtbUniqueId *pad_unique_id_to_preserve=otb_unique_id_new();
	OtbPadIO *pad_io_to_expire=otb_pad_db_add_incoming_pad(pad_db, pad_unique_id_to_expire, INCOMING_PAD_SIZE, g_get_real_time()-10000000);
	g_assert(pad_io_to_expire!=NULL);
	g_assert(otb_pad_db_close_pad(pad_db, pad_io_to_expire));
	OtbPadIO *pad_io_to_keep=otb_pad_db_add_incoming_pad(pad_db, pad_unique_id_to_preserve, INCOMING_PAD_SIZE, g_get_real_time()+10000000);
	g_assert(pad_io_to_keep!=NULL);
	g_assert(otb_pad_db_close_pad(pad_db, pad_io_to_keep));
	otb_pad_db_remove_expired_pads(pad_db);
	GSList *remaining_pads=otb_pad_db_get_ids_of_pads_in_status(pad_db, OTB_PAD_REC_STATUS_INCOMING);
	g_assert_cmpint(1, ==, g_slist_length(remaining_pads));
	g_assert_cmpint(0, ==, otb_unique_id_compare(g_slist_nth_data(remaining_pads, 0), pad_unique_id_to_preserve));
	g_slist_free_full(remaining_pads, (GFreeFunc)otb_unique_id_unref);
	otb_unique_id_unref(pad_unique_id_to_preserve);
	otb_unique_id_unref(pad_unique_id_to_expire);
	g_free(pad_db_dir_path);
	g_object_unref(pad_db);
}

static OtbUniqueId *otb_mark_random_pad_as_sent(const OtbPadDb *pad_db)
{
	OtbUniqueId *unique_id=otb_pad_db_fetch_random_rec_id_with_null_assertion(pad_db, OTB_PAD_REC_STATUS_UNSENT);
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
	OtbUniqueId *expected_unique_id=otb_mark_random_pad_as_sent(pad_db);
	g_assert(otb_pad_db_fetch_random_rec_id(pad_db, OTB_PAD_REC_STATUS_UNSENT)==NULL);
	OtbUniqueId *actual_unique_id=otb_pad_db_fetch_random_rec_id_with_null_assertion(pad_db, OTB_PAD_REC_STATUS_SENT);
	g_assert_cmpint(0, ==, otb_unique_id_compare(expected_unique_id, actual_unique_id));
	otb_unique_id_unref(expected_unique_id);
	otb_unique_id_unref(actual_unique_id);
	g_object_unref(pad_db);
}

static OtbUniqueId *otb_mark_random_pad_as_received(const OtbPadDb *pad_db)
{
	OtbUniqueId *unique_id=otb_pad_db_fetch_random_rec_id_with_null_assertion(pad_db, OTB_PAD_REC_STATUS_INCOMING);
	g_assert(otb_pad_db_mark_pad_as_received(pad_db, unique_id));
	return unique_id;
}

static void test_pad_rec_mark_as_received()
{
	otb_test_setup_local_crypto();
	OtbPadDb *pad_db=otb_create_pad_db_in_random_test_path();
	OtbUniqueId *unique_id=otb_unique_id_new();
	long long expected_expiration=otb_few_months_from_now();
	OtbPadIO *pad_io=otb_pad_db_add_incoming_pad(pad_db, unique_id, ABSOLUTE_MIN_PAD_SIZE, expected_expiration);
	g_assert(pad_io!=NULL);
	otb_pad_db_close_pad(pad_db, pad_io);
	g_assert(otb_pad_db_create_unsent_pad(pad_db));
	OtbUniqueId *expected_unique_id=otb_mark_random_pad_as_received(pad_db);
	g_assert(otb_pad_db_fetch_random_rec_id(pad_db, OTB_PAD_REC_STATUS_INCOMING)==NULL);
	OtbUniqueId *actual_unique_id=otb_pad_db_fetch_random_rec_id_with_null_assertion(pad_db, OTB_PAD_REC_STATUS_RECEIVED);
	g_assert_cmpint(0, ==, otb_unique_id_compare(expected_unique_id, actual_unique_id));
	otb_assert_expiration(pad_db, actual_unique_id, expected_expiration);
	otb_unique_id_unref(actual_unique_id);
	otb_unique_id_unref(expected_unique_id);
	otb_unique_id_unref(unique_id);
	g_object_unref(pad_db);
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
	OtbUniqueId *pad_unique_id=otb_mark_random_pad_as_sent(pad_db);
	g_assert(pad_unique_id!=NULL);
	unsigned char *encrypted_bytes;
	size_t encrypted_bytes_size;
	OtbCipherContext *cipher_context=otb_cipher_context_new();
	g_assert_cmpint(OTB_PAD_DB_CRYPT_RESULT_NOT_ENOUGH_PADS, ==, otb_pad_db_encrypt(pad_db, cipher_context, EXPECTED_MESSAGE, MESSAGE_SIZE, &encrypted_bytes, &encrypted_bytes_size));
	g_assert(encrypted_bytes==NULL);
	g_assert_cmpint(0, ==, encrypted_bytes_size);
	g_free(encrypted_bytes);
	otb_cipher_context_free(cipher_context);
	otb_unique_id_unref(pad_unique_id);
	g_object_unref(pad_db);
	g_free(pad_db_dir_path);
}

static void test_encryption_with_one_pad()
{
	const size_t MESSAGE_SIZE=1008;
	const char *EXPECTED_MESSAGE="I heartily accept the motto, \"That government is best which governs least\"; and I should like to see it acted up to more rapidly and systematically. Carried out, it finally amounts to this, which also I believe - \"That government is best which governs not at all\"; and when men are prepared for it, that will be the kind of government which they will have. Government is at best but an expedient; but most governments are usually, and all governments are sometimes, inexpedient. The objections which have been brought against a standing army, and they are many and weighty, and deserve to prevail, may also at last be brought against a standing government. The standing army is only an arm of the standing government. The government itself, which is only the mode which the people have chosen to execute their will, is equally liable to be abused and perverted before the people can act through it. Witness the present Mexican war, the work of comparatively a few individuals using the standing government as";
	const size_t START_OF_ENCRYPTED_MESSAGE=sizeof(unsigned char)+OTB_UNIQUE_ID_BYTES_LENGTH;
	const off_t EXPECTED_ENCRYPTED_MESSAGE_SIZE=START_OF_ENCRYPTED_MESSAGE+MESSAGE_SIZE;
	
	otb_test_setup_local_crypto();
	char *pad_db_dir_path=otb_generate_unique_test_subdir_path();
	OtbPadDb *pad_db=otb_pad_db_create_in_directory(pad_db_dir_path);
	g_assert(pad_db!=NULL);
	g_assert(otb_pad_db_set_new_pad_min_size(pad_db, ABSOLUTE_MIN_PAD_SIZE));
	g_assert(otb_pad_db_set_new_pad_max_size(pad_db, ABSOLUTE_MIN_PAD_SIZE));
	g_assert(otb_pad_db_create_unsent_pad(pad_db));
	OtbUniqueId *expected_unique_id=otb_mark_random_pad_as_sent(pad_db);
	unsigned char *encrypted_bytes;
	size_t encrypted_bytes_size;
	OtbCipherContext *cipher_context=otb_cipher_context_new();
	g_assert_cmpint(OTB_PAD_DB_CRYPT_RESULT_SUCCESS, ==, otb_pad_db_encrypt(pad_db, cipher_context, EXPECTED_MESSAGE, MESSAGE_SIZE, &encrypted_bytes, &encrypted_bytes_size));
	g_assert(encrypted_bytes!=NULL);
	g_assert_cmpint(EXPECTED_ENCRYPTED_MESSAGE_SIZE, ==, encrypted_bytes_size);
	g_assert_cmpint(0, ==, (unsigned char)encrypted_bytes[0]);
	g_assert_cmpint(0, ==, memcmp(otb_unique_id_get_bytes(expected_unique_id), (OtbUniqueId*)(encrypted_bytes+sizeof(unsigned char)), OTB_UNIQUE_ID_BYTES_LENGTH));
	OtbPadIO *pad_io=otb_pad_db_open_pad_for_read(pad_db, expected_unique_id);
	g_assert(pad_io!=NULL);
	unsigned char *pad_bytes=otb_assert_pad_read(pad_io, NULL, ABSOLUTE_MIN_PAD_SIZE);
	g_assert(otb_pad_db_close_pad(pad_db, pad_io));
	for(size_t byte_index=0; byte_index<MESSAGE_SIZE; byte_index++)
		g_assert_cmpint(EXPECTED_MESSAGE[byte_index], ==, encrypted_bytes[byte_index+START_OF_ENCRYPTED_MESSAGE]^pad_bytes[byte_index]);
	g_assert(otb_pad_db_fetch_random_rec_id(pad_db, OTB_PAD_REC_STATUS_SENT)==NULL);
	OtbUniqueId *actual_unique_id=otb_pad_db_fetch_random_rec_id_with_null_assertion(pad_db, OTB_PAD_REC_STATUS_CONSUMED);
	g_assert_cmpint(0, ==, otb_unique_id_compare(expected_unique_id, actual_unique_id));
	g_free(pad_bytes);
	g_free(encrypted_bytes);
	otb_cipher_context_free(cipher_context);
	otb_unique_id_unref(expected_unique_id);
	otb_unique_id_unref(actual_unique_id);
	g_free(pad_db_dir_path);
	g_object_unref(pad_db);
}

static void test_decryption_fails_due_to_unsupported_file_format()
{
	const unsigned char FORMAT_VERSION='\xff';
	
	char *pad_db_dir_path=otb_generate_unique_test_subdir_path();
	OtbPadDb *pad_db=otb_pad_db_create_in_directory(pad_db_dir_path);
	g_assert(pad_db!=NULL);
	unsigned char input_bytes[sizeof FORMAT_VERSION+OTB_UNIQUE_ID_BYTES_LENGTH];
	memcpy(input_bytes, &FORMAT_VERSION, sizeof(FORMAT_VERSION));
	void *decrypted_bytes;
	size_t decrypted_bytes_size;
	OtbCipherContext *cipher_context=otb_cipher_context_new();
	g_assert_cmpint(OTB_PAD_DB_CRYPT_RESULT_UNSUPPORTED_FILE_FORMAT, ==, otb_pad_db_decrypt(pad_db, cipher_context, input_bytes, sizeof FORMAT_VERSION+OTB_UNIQUE_ID_BYTES_LENGTH, &decrypted_bytes, &decrypted_bytes_size));
	g_assert(decrypted_bytes==NULL);
	g_assert_cmpint(0, ==, decrypted_bytes_size);
	otb_free_locked(decrypted_bytes, decrypted_bytes_size);
	otb_cipher_context_free(cipher_context);
	g_free(pad_db_dir_path);
	g_object_unref(pad_db);
}

static void test_decryption_fails_due_to_missing_pad()
{
	const unsigned char FORMAT_VERSION='\x00';
	
	char *pad_db_dir_path=otb_generate_unique_test_subdir_path();
	OtbPadDb *pad_db=otb_pad_db_create_in_directory(pad_db_dir_path);
	g_assert(pad_db!=NULL);
	unsigned char input_bytes[sizeof FORMAT_VERSION+OTB_UNIQUE_ID_BYTES_LENGTH];
	memcpy(input_bytes, &FORMAT_VERSION, sizeof FORMAT_VERSION);
	void *decrypted_bytes;
	size_t decrypted_bytes_size;
	OtbCipherContext *cipher_context=otb_cipher_context_new();
	g_assert_cmpint(OTB_PAD_DB_CRYPT_RESULT_MISSING_PAD, ==, otb_pad_db_decrypt(pad_db, cipher_context, input_bytes, sizeof FORMAT_VERSION+OTB_UNIQUE_ID_BYTES_LENGTH, &decrypted_bytes, &decrypted_bytes_size));
	g_assert(decrypted_bytes==NULL);
	g_assert_cmpint(0, ==, decrypted_bytes_size);
	otb_free_locked(decrypted_bytes, decrypted_bytes_size);
	otb_cipher_context_free(cipher_context);
	g_object_unref(pad_db);
	g_free(pad_db_dir_path);
}

static void test_pad_db_get_pad_size()
{
	otb_test_setup_local_crypto();
	OtbPadDb *pad_db=otb_create_pad_db_in_random_test_path();
	g_assert(otb_pad_db_set_new_pad_min_size(pad_db, ABSOLUTE_MIN_PAD_SIZE));
	g_assert(otb_pad_db_set_new_pad_max_size(pad_db, ABSOLUTE_MIN_PAD_SIZE));
	g_assert(otb_pad_db_create_unsent_pad(pad_db));
	OtbUniqueId *unique_id=otb_mark_random_pad_as_sent(pad_db);
	g_assert(unique_id!=NULL);
	g_assert_cmpint(ABSOLUTE_MIN_PAD_SIZE, ==, otb_pad_db_get_pad_size(pad_db, unique_id));
	otb_unique_id_unref(unique_id);
	g_object_unref(pad_db);
}

static void test_pad_db_get_pad_size_range()
{
	otb_test_setup_local_crypto();
	OtbPadDb *pad_db=otb_create_pad_db_in_random_test_path();
	g_assert(otb_pad_db_set_new_pad_min_size(pad_db, ABSOLUTE_MIN_PAD_SIZE));
	g_assert(otb_pad_db_set_new_pad_max_size(pad_db, ABSOLUTE_MIN_PAD_SIZE*2));
	g_assert(otb_pad_db_create_unsent_pad(pad_db));
	OtbUniqueId *unique_id=otb_mark_random_pad_as_sent(pad_db);
	g_assert(unique_id!=NULL);
	g_assert_cmpint(ABSOLUTE_MIN_PAD_SIZE, <=, otb_pad_db_get_pad_size(pad_db, unique_id));
	g_assert_cmpint(ABSOLUTE_MIN_PAD_SIZE*2, >=, otb_pad_db_get_pad_size(pad_db, unique_id));
	otb_unique_id_unref(unique_id);
	g_object_unref(pad_db);
}

static void otb_send_random_pad(OtbPadDb *sender_pad_db, const OtbPadDb *recipient_pad_db)
{
	OtbUniqueId *unique_id=otb_mark_random_pad_as_sent(sender_pad_db);
	long long expiration=otb_few_months_from_now();
	OtbPadIO *output_pad_io=otb_pad_db_add_incoming_pad(recipient_pad_db, unique_id, otb_pad_db_get_pad_size(sender_pad_db, unique_id), expiration);
	OtbPadIO *input_pad_io=otb_pad_db_open_pad_for_read(sender_pad_db, unique_id);
	while(otb_pad_has_more_bytes(input_pad_io))
	{
		unsigned char byte;
		g_assert(otb_pad_read_byte(input_pad_io, &byte));
		g_assert(otb_pad_write(output_pad_io, &byte, sizeof byte));
	}
	g_assert(!otb_pad_db_close_pad(sender_pad_db, output_pad_io));
	g_assert(!otb_pad_db_close_pad(recipient_pad_db, input_pad_io));
	g_assert(otb_pad_db_close_pad(sender_pad_db, input_pad_io));
	g_assert(otb_pad_db_close_pad(recipient_pad_db, output_pad_io));
	otb_unique_id_unref(unique_id);
}

static void otb_send_random_pads(OtbPadDb *sender_pad_db, const OtbPadDb *recipient_pad_db, size_t number_of_pads)
{
	for(size_t iter=0; iter<number_of_pads; iter++)
		otb_send_random_pad(sender_pad_db, recipient_pad_db);
}

static void otb_encrypt_file_for_two_pad_test(const OtbPadDb *pad_db, const void *message, size_t message_size, unsigned char **encrypted_message, size_t *encrypted_message_size)
{
	*encrypted_message=NULL;
	*encrypted_message_size=0;
	OtbCipherContext *cipher_context=otb_cipher_context_new();
	g_assert_cmpint(OTB_PAD_DB_CRYPT_RESULT_SUCCESS, ==, otb_pad_db_encrypt(pad_db, cipher_context, message, message_size, encrypted_message, encrypted_message_size));
	g_assert(encrypted_message!=NULL);
	g_assert_cmpint(0, !=, *encrypted_message_size);
	otb_assert_number_of_pads_in_status(pad_db, 1, OTB_PAD_REC_STATUS_UNSENT);
	otb_assert_number_of_pads_in_status(pad_db, 1, OTB_PAD_REC_STATUS_SENT);
	otb_assert_number_of_pads_in_status(pad_db, 2, OTB_PAD_REC_STATUS_CONSUMED);
	otb_cipher_context_free(cipher_context);
}

static void otb_pad_db_create_unsent_pads(const OtbPadDb *pad_db, size_t number_of_pads)
{
	for(size_t iter=0; iter<number_of_pads; iter++)
		g_assert(otb_pad_db_create_unsent_pad(pad_db));
}

static void test_encryption_decryption_with_two_pads()
{
	const size_t EXPECTED_MESSAGE_SIZE=2016;
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
	unsigned char *encrypted_message;
	size_t encrypted_message_size;
	otb_encrypt_file_for_two_pad_test(sender_pad_db, EXPECTED_MESSAGE, EXPECTED_MESSAGE_SIZE, &encrypted_message, &encrypted_message_size);
	void *actual_message;
	size_t actual_message_size;
	OtbCipherContext *cipher_context=otb_cipher_context_new();
	g_assert_cmpint(OTB_PAD_DB_CRYPT_RESULT_SUCCESS, ==, otb_pad_db_decrypt(recipient_pad_db, cipher_context, encrypted_message, encrypted_message_size, &actual_message, &actual_message_size));
	otb_assert_number_of_pads_in_status(recipient_pad_db, 1, OTB_PAD_REC_STATUS_INCOMING);
	g_assert_cmpint(EXPECTED_MESSAGE_SIZE, ==, actual_message_size);
	g_assert_cmpint(0, ==, memcmp(EXPECTED_MESSAGE, actual_message, EXPECTED_MESSAGE_SIZE));
	otb_free_locked(actual_message, actual_message_size);
	otb_cipher_context_free(cipher_context);
	g_free(encrypted_message);
	g_object_unref(recipient_pad_db);
	g_free(recipient_pad_db_dir_path);
	g_object_unref(sender_pad_db);
	g_free(sender_pad_db_dir_path);
}

void otb_add_pad_db_tests()
{
	otb_add_test_func("/pad-db/test_set_new_pad_size", test_set_new_pad_size);
	otb_add_test_func("/pad-db/test_otb_pad_db_io", test_otb_pad_db_io);
	otb_add_test_func("/pad-db/test_otb_pad_db_rejects_pads_too_large", test_otb_pad_db_rejects_pads_too_large);
	otb_add_test_func("/pad-db/test_otb_pad_db_rejects_pads_duplicate_id", test_otb_pad_db_rejects_pads_duplicate_id);
	otb_add_test_func("/pad-db/test_create_unsent_pad_results_in_proper_pad_file", test_create_unsent_pad_results_in_proper_pad_file);
	otb_add_test_func("/pad-db/test_pads_save_load_delete", test_pads_save_load_delete);
	otb_add_test_func("/pad-db/test_add_incoming_pad", test_add_incoming_pad);
	otb_add_test_func("/pad-db/test_get_random_rec_id", test_get_random_rec_id);
	otb_add_test_func("/pad-db/test_otb_pad_db_get_ids_of_pads_in_status", test_otb_pad_db_get_ids_of_pads_in_status);
	otb_add_test_func("/pad-db/test_close_pad_fails_when_nothing_is_opened", test_close_pad_fails_when_nothing_is_opened);
	otb_add_test_func("/pad-db/test_remove_rec", test_remove_rec);
	otb_add_test_func("/pad-db/test_remove_rec_that_does_not_exist", test_remove_rec_that_does_not_exist);
	otb_add_test_func("/pad-db/test_remove_expired_pads", test_remove_expired_pads);
	otb_add_test_func("/pad-db/test_pad_rec_mark_as_sent", test_pad_rec_mark_as_sent);
	otb_add_test_func("/pad-db/test_pad_rec_mark_as_received", test_pad_rec_mark_as_received);
	otb_add_test_func("/pad-db/test_encryption_fails_due_to_not_enough_pad_bytes", test_encryption_fails_due_to_not_enough_pad_bytes);
	otb_add_test_func("/pad-db/test_encryption_with_one_pad", test_encryption_with_one_pad);
	otb_add_test_func("/pad-db/test_decryption_fails_due_to_unsupported_file_format", test_decryption_fails_due_to_unsupported_file_format);
	otb_add_test_func("/pad-db/test_decryption_fails_due_to_missing_pad", test_decryption_fails_due_to_missing_pad);
	otb_add_test_func("/pad-db/test_pad_db_get_pad_size", test_pad_db_get_pad_size);
	otb_add_test_func("/pad-db/test_pad_db_get_pad_size_range", test_pad_db_get_pad_size_range);
	otb_add_test_func("/pad-db/test_encryption_decryption_with_two_pads", test_encryption_decryption_with_two_pads);
}
