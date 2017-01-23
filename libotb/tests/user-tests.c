/**
 * Copyright © 2015 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <glib/gstdio.h>
#include <string.h>

#include "main.h"
#include "dummy-friend.h"
#include "dummy-user.h"
#include "test-utils.h"
#include "../src/friend.h"
#include "../src/io.h"
#include "../src/local-crypto.h"
#include "../src/random.h"
#include "../src/settings.h"
#include "../src/user.h"

static void test_otb_user_create_with_no_config_file()
{
	const char *EXPECTED_DEFAULT_SYM_CIPHER_NAME="AES-256-CBC";
	const char *EXPECTED_ADDRESS="sajkhdgdjashg.onion";
	const unsigned short EXPECTED_PORT=31415;
	
	otb_initialize_settings_for_tests();
	otb_local_crypto_create_sym_cipher("");
	char *config_file_path=g_build_filename(otb_get_test_dir_path(), "otb.conf", NULL);
	g_unlink(config_file_path);
	g_free(config_file_path);
	g_assert(!otb_user_exists());
	OtbUser *user=otb_user_load();
	g_assert(user==NULL);
	user=otb_user_create(256);
	g_assert(user!=NULL);
	g_object_set(user, OTB_USER_PROP_ADDRESS, EXPECTED_ADDRESS, OTB_USER_PROP_PORT, EXPECTED_PORT, NULL);
	g_assert(otb_user_save(user));
	g_assert(otb_user_exists());
	OtbUniqueId *actual_unique_id=NULL;
	OtbAsymCipher *actual_asym_cipher=NULL;
	char *actual_address=NULL;
	unsigned int actual_port=0;
	g_object_get(user, OTB_USER_PROP_UNIQUE_ID, &actual_unique_id, OTB_USER_PROP_ASYM_CIPHER, &actual_asym_cipher, OTB_USER_PROP_ADDRESS, &actual_address, OTB_USER_PROP_PORT, &actual_port, NULL);
	g_assert(actual_unique_id!=NULL);
	char *actual_sym_cipher_name=NULL;
	char *actual_public_key=NULL;
	g_object_get(actual_asym_cipher, OTB_ASYM_CIPHER_PROP_SYM_CIPHER_NAME, &actual_sym_cipher_name, OTB_ASYM_CIPHER_PROP_PUBLIC_KEY, &actual_public_key, NULL);
	g_assert_cmpstr(EXPECTED_DEFAULT_SYM_CIPHER_NAME, ==, actual_sym_cipher_name);
	g_assert(actual_public_key!=NULL);
	g_assert_cmpstr(EXPECTED_ADDRESS, ==, actual_address);
	g_assert_cmpint(EXPECTED_PORT, ==, (unsigned short)actual_port);
	otb_local_crypto_lock_sym_cipher();
	g_free(actual_sym_cipher_name);
	g_free(actual_public_key);
	g_object_unref(actual_asym_cipher);
	otb_unique_id_unref(actual_unique_id);
	g_object_unref(user);
}

static void otb_write_unique_id(FILE *file, const OtbUniqueId *unique_id)
{
	char *encoded_unique_id=g_base64_encode(otb_unique_id_get_bytes(unique_id), OTB_UNIQUE_ID_BYTES_SIZE);
	g_assert(otb_write("unique-id=", 1, 10, file)==10);
	g_assert(otb_write(encoded_unique_id, 1, strlen(encoded_unique_id), file)==strlen(encoded_unique_id));
	g_assert(otb_write("\n", 1, 1, file)==1);
	g_free(encoded_unique_id);
}

static void otb_write_sym_cipher_name(FILE *file, const char *sym_cipher_name)
{
	g_assert(otb_write("sym-cipher=", 1, 11, file)==11);
	g_assert(otb_write(sym_cipher_name, 1, strlen(sym_cipher_name), file)==strlen(sym_cipher_name));
	g_assert(otb_write("\n", 1, 1, file)==1);
}

static void otb_write_asym_cipher(FILE *file, const OtbAsymCipher *asym_cipher)
{
	OtbSymCipher *local_crypto=otb_local_crypto_get_sym_cipher_with_ref();
	GBytes *iv;
	GBytes *encrypted_private_key=otb_asym_cipher_get_encrypted_private_key(asym_cipher, local_crypto, &iv);
	g_object_unref(local_crypto);
	g_assert(iv!=NULL);
	g_assert(encrypted_private_key!=NULL);
	char *encoded_iv=g_base64_encode(g_bytes_get_data(iv, NULL), g_bytes_get_size(iv));
	g_bytes_unref(iv);
	char *encoded_encrypted_private_key=g_base64_encode(g_bytes_get_data(encrypted_private_key, NULL), g_bytes_get_size(encrypted_private_key));
	g_bytes_unref(encrypted_private_key);
	g_assert(otb_write("asym-cipher-private-key-iv=", 1, 27, file)==27);
	g_assert(otb_write(encoded_iv, 1, strlen(encoded_iv), file)==strlen(encoded_iv));
	g_assert(otb_write("\n", 1, 1, file)==1);
	g_assert(otb_write("asym-cipher-private-key=", 1, 24, file)==24);
	g_assert(otb_write(encoded_encrypted_private_key, 1, strlen(encoded_encrypted_private_key), file)==strlen(encoded_encrypted_private_key));
	g_assert(otb_write("\n", 1, 1, file)==1);
	g_free(encoded_iv);
	g_free(encoded_encrypted_private_key);
}

static void otb_write_address(FILE *file, const char *address)
{
	g_assert(otb_write("address=", 1, 8, file)==8);
	g_assert(otb_write(address, 1, strlen(address), file)==strlen(address));
	g_assert(otb_write("\n", 1, 1, file)==1);
}

static void otb_write_port(FILE *file, unsigned short port)
{
	if(port>0)
	{
		char port_string[6];
		g_assert_cmpint(sprintf(port_string, "%hu", port), >, 0);
		g_assert(otb_write("port=", 1, 5, file)==5);
		g_assert(otb_write(port_string, 1, strlen(port_string), file)==strlen(port_string));
		g_assert(otb_write("\n", 1, 1, file)==1);
	}
}

static void otb_write_dummy_value(FILE *file)
{
	g_assert(otb_write(OTB_DUMMY_FRIEND_KEY, 1, strlen(OTB_DUMMY_FRIEND_KEY), file)==strlen(OTB_DUMMY_FRIEND_KEY));
	g_assert(otb_write("=", 1, 1, file)==1);
	g_assert(otb_write(OTB_DUMMY_USER_EXPORT_VALUE, 1, strlen(OTB_DUMMY_USER_EXPORT_VALUE), file)==strlen(OTB_DUMMY_USER_EXPORT_VALUE));
	g_assert(otb_write("\n", 1, 1, file)==1);
}

static void otb_write_dummy_data(FILE *file)
{
	g_assert(otb_write("[", 1, 1, file)==1);
	g_assert(otb_write(OTB_DUMMY_FRIEND_GROUP, 1, strlen(OTB_DUMMY_FRIEND_GROUP), file)==strlen(OTB_DUMMY_FRIEND_GROUP));
	g_assert(otb_write("]\n", 1, 2, file)==2);
	otb_write_dummy_value(file);
}

void otb_setup_config_file_for_user_tests(const OtbUniqueId *unique_id, const char *sym_cipher_name, const OtbAsymCipher *asym_cipher, const char *address, unsigned short port)
{
	otb_test_setup_local_crypto();
	char *config_file_path=g_build_filename(otb_get_test_dir_path(), "otb.conf", NULL);
	FILE *file=otb_open_text_for_write(config_file_path);
	g_free(config_file_path);
	g_assert(file!=NULL);
	g_assert(otb_write("[user]\n", 1, 7, file)==7);
	otb_write_unique_id(file, unique_id);
	otb_write_sym_cipher_name(file, sym_cipher_name);
	otb_write_asym_cipher(file, asym_cipher);
	otb_write_address(file, address);
	otb_write_port(file, port);
	otb_write_dummy_data(file);
	g_assert(otb_close(file));
	otb_initialize_settings_for_tests();
}

static OtbUser *otb_load_user_from_existing_config_file(const OtbUniqueId *unique_id, const char *sym_cipher_name, OtbAsymCipher *asym_cipher, const char *address, unsigned short port)
{
	otb_setup_config_file_for_user_tests(unique_id, sym_cipher_name, asym_cipher, address, port);
	OtbUser *user=otb_user_load();
	g_assert(user!=NULL);
	g_assert(otb_user_exists());
	return user;
}

static OtbUser *otb_do_user_create_from_existing_config_file_test()
{
	const size_t NEW_KEY_SIZE=256;
	const char *EXPECTED_SYM_CIPHER_NAME="DES-CBC";
	const char *EXPECTED_ADDRESS1="akjsdhkljashgd.onion";
	const char *EXPECTED_ADDRESS2="kjshdfjkhgssdj.onion";
	const unsigned short EXPECTED_PORT1=12345;
	const unsigned short EXPECTED_PORT2=6789;
	
	otb_initialize_settings_for_tests();
	otb_local_crypto_create_sym_cipher("");
	OtbUniqueId *expected_unique_id=otb_unique_id_new();
	OtbAsymCipher *expected_asym_cipher=g_object_new(OTB_TYPE_ASYM_CIPHER, NULL);
	g_assert(otb_asym_cipher_generate_random_keys(expected_asym_cipher, NEW_KEY_SIZE));
	OtbUser *user=otb_load_user_from_existing_config_file(expected_unique_id, EXPECTED_SYM_CIPHER_NAME, expected_asym_cipher, EXPECTED_ADDRESS1, EXPECTED_PORT1);
	OtbUniqueId *actual_unique_id=NULL;
	OtbAsymCipher *actual_asym_cipher=NULL;
	char *actual_address1=NULL;
	unsigned int actual_port1=0;
	g_object_get(user, OTB_USER_PROP_UNIQUE_ID, &actual_unique_id, OTB_USER_PROP_ASYM_CIPHER, &actual_asym_cipher, OTB_USER_PROP_ADDRESS, &actual_address1, OTB_USER_PROP_PORT, &actual_port1, NULL);
	g_assert_cmpint(0, ==, otb_unique_id_compare(expected_unique_id, actual_unique_id));
	char *expected_public_key=NULL;
	g_object_get(expected_asym_cipher, OTB_ASYM_CIPHER_PROP_PUBLIC_KEY, &expected_public_key, NULL);
	g_assert(expected_public_key!=NULL);
	char *actual_sym_cipher_name=NULL;
	char *actual_public_key=NULL;
	g_object_get(actual_asym_cipher, OTB_ASYM_CIPHER_PROP_SYM_CIPHER_NAME, &actual_sym_cipher_name, OTB_ASYM_CIPHER_PROP_PUBLIC_KEY, &actual_public_key, NULL);
	g_assert_cmpstr(EXPECTED_SYM_CIPHER_NAME, ==, actual_sym_cipher_name);
	g_assert_cmpstr(expected_public_key, ==, actual_public_key);
	g_assert_cmpstr(EXPECTED_ADDRESS1, ==, actual_address1);
	g_assert_cmpint((unsigned int)EXPECTED_PORT1, ==, actual_port1);
	g_object_set(user, OTB_USER_PROP_ADDRESS, EXPECTED_ADDRESS2, OTB_USER_PROP_PORT, EXPECTED_PORT2, NULL);
	g_assert(otb_user_save(user));
	char *actual_address2=NULL;
	unsigned int actual_port2=0;
	g_object_get(user, OTB_USER_PROP_ADDRESS, &actual_address2, NULL);
	g_object_get(user, OTB_USER_PROP_PORT, &actual_port2, NULL);
	g_assert_cmpstr(EXPECTED_ADDRESS2, ==, actual_address2);
	g_assert_cmpint((unsigned int)EXPECTED_PORT2, ==, actual_port2);
	otb_local_crypto_lock_sym_cipher();
	otb_unique_id_unref(actual_unique_id);
	otb_unique_id_unref(expected_unique_id);
	g_free(actual_sym_cipher_name);
	g_free(expected_public_key);
	g_free(actual_public_key);
	g_object_unref(actual_asym_cipher);
	g_free(actual_address1);
	g_free(actual_address2);
	g_object_unref(expected_asym_cipher);
	return user;
}

static void test_otb_user_create_from_existing_config_file()
{
	OtbUser *user=otb_do_user_create_from_existing_config_file_test();
	g_assert(OTB_IS_USER(user));
	g_assert(!OTB_IS_DUMMY_USER(user));
	g_object_unref(user);
}

static void test_otb_dummy_user_create_from_existing_config_file()
{
	otb_user_set_runtime_type(OTB_TYPE_DUMMY_USER);
	OtbUser *user=otb_do_user_create_from_existing_config_file_test();
	g_assert(OTB_IS_USER(user));
	g_assert(OTB_IS_DUMMY_USER(user));
	g_assert_cmpstr(OTB_DUMMY_USER_EXPORT_VALUE, ==, OTB_DUMMY_USER(user)->loaded_key_value);
	g_object_unref(user);
	otb_user_set_runtime_type(OTB_TYPE_USER);
}

static void otb_do_user_export_test(OtbUser **user, GKeyFile **export_key_file)
{
	const size_t NEW_KEY_SIZE=256;
	const char *EXPECTED_SYM_CIPHER_NAME="DES-CBC";
	const char *EXPECTED_ADDRESS="kdjhgkfgjhfhj.onion";
	const unsigned short EXPECTED_PORT=11235;
	
	OtbUniqueId *expected_unique_id=otb_unique_id_new();
	OtbAsymCipher *expected_asym_cipher=g_object_new(OTB_TYPE_ASYM_CIPHER, NULL);
	g_assert(otb_asym_cipher_generate_random_keys(expected_asym_cipher, NEW_KEY_SIZE));
	*user=otb_load_user_from_existing_config_file(expected_unique_id, EXPECTED_SYM_CIPHER_NAME, expected_asym_cipher, EXPECTED_ADDRESS, EXPECTED_PORT);
	char *expected_public_key=NULL;
	g_object_get(expected_asym_cipher, OTB_ASYM_CIPHER_PROP_PUBLIC_KEY, &expected_public_key, NULL);
	g_assert(expected_public_key!=NULL);
	char *export_string=otb_user_export(*user);
	g_assert((*export_key_file=otb_settings_load_key_file_from_string(export_string))!=NULL);
	unsigned char *actual_unique_id_bytes=otb_settings_get_bytes(*export_key_file, OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_UNIQUE_ID, NULL);
	OtbUniqueId *actual_unique_id=otb_unique_id_from_bytes(actual_unique_id_bytes);
	char *actual_public_key=otb_settings_get_string(*export_key_file, OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_PUBLIC_KEY);
	char *actual_sym_cipher_name=otb_settings_get_string(*export_key_file, OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_TRANSPORT_CIPHER_NAME);
	char *actual_address=otb_settings_get_string(*export_key_file, OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_ADDRESS);
	unsigned short actual_port=(unsigned short)otb_settings_get_uint(*export_key_file, OTB_FRIEND_IMPORT_GROUP, OTB_FRIEND_IMPORT_PORT, 0);
	g_assert_cmpint(0, ==, otb_unique_id_compare(expected_unique_id, actual_unique_id));
	g_assert_cmpstr(expected_public_key, ==, actual_public_key);
	g_assert_cmpstr(EXPECTED_SYM_CIPHER_NAME, ==, actual_sym_cipher_name);
	g_assert_cmpstr(EXPECTED_ADDRESS, ==, actual_address);
	g_assert_cmpint(EXPECTED_PORT, ==, actual_port);
	otb_local_crypto_lock_sym_cipher();
	g_free(export_string);
	otb_unique_id_unref(actual_unique_id);
	g_free(actual_unique_id_bytes);
	otb_unique_id_unref(expected_unique_id);
	g_free(expected_public_key);
	g_free(actual_public_key);
	g_free(actual_sym_cipher_name);
	g_free(actual_address);
	g_object_unref(expected_asym_cipher);
}

static void test_otb_user_export()
{
	OtbUser *user=NULL;
	GKeyFile *export_key_file=NULL;
	otb_do_user_export_test(&user, &export_key_file);
	g_key_file_unref(export_key_file);
	g_assert(OTB_IS_USER(user));
	g_assert(!OTB_IS_DUMMY_USER(user));
	g_object_unref(user);
}

static void test_otb_dummy_user_export()
{
	OtbUser *user=NULL;
	GKeyFile *export_key_file=NULL;
	otb_user_set_runtime_type(OTB_TYPE_DUMMY_USER);
	otb_do_user_export_test(&user, &export_key_file);
	char *actual_dummy_value=otb_settings_get_string(export_key_file, OTB_DUMMY_FRIEND_GROUP, OTB_DUMMY_FRIEND_KEY);
	g_key_file_unref(export_key_file);
	g_assert_cmpstr(OTB_DUMMY_USER_EXPORT_VALUE, ==, actual_dummy_value);
	g_assert(OTB_IS_USER(user));
	g_assert(OTB_IS_DUMMY_USER(user));
	g_free(actual_dummy_value);
	g_object_unref(user);
	otb_user_set_runtime_type(OTB_TYPE_USER);
}

static gboolean writing=FALSE;
static int readers=0;
static GMutex reader_writer_test_mutex;

static void sleep_for_up_to_100_microseconds()
{
	useconds_t sleep_time;
	otb_random_bytes(&sleep_time, sizeof(sleep_time));
	usleep(otb_modulo(sleep_time, 100));
}

static void *reader_thread_func(OtbUser *user)
{
	for(int iter=0; iter<1000; iter++)
	{
		otb_user_lock_read(user);
		g_assert(!writing);
		g_mutex_lock(&reader_writer_test_mutex);
		readers++;
		g_mutex_unlock(&reader_writer_test_mutex);
		sleep_for_up_to_100_microseconds();
		g_mutex_lock(&reader_writer_test_mutex);
		readers--;
		g_mutex_unlock(&reader_writer_test_mutex);
		g_assert(!writing);
		otb_user_unlock_read(user);
	}
	return NULL;
}

static void test_locks()
{
	otb_initialize_settings_for_tests();
	otb_local_crypto_create_sym_cipher("");
	char *config_file_path=g_build_filename(otb_get_test_dir_path(), "otb.conf", NULL);
	g_unlink(config_file_path);
	g_free(config_file_path);
	g_assert(!otb_user_exists());
	OtbUser *user=otb_user_create(256);
	g_assert(user!=NULL);
	g_object_set(user, OTB_USER_PROP_ADDRESS, "asjhdgjsahgd.onion", OTB_USER_PROP_PORT, 1234, NULL);
	g_assert(otb_user_save(user));
	GThread *reader_thread1=g_thread_new("ReaderThread1", (GThreadFunc)reader_thread_func, user);
	GThread *reader_thread2=g_thread_new("ReaderThread1", (GThreadFunc)reader_thread_func, user);
	GThread *reader_thread3=g_thread_new("ReaderThread1", (GThreadFunc)reader_thread_func, user);
	for(int iter=0; iter<1000; iter++)
	{
		otb_user_lock_write(user);
		g_assert_cmpint(readers, ==, 0);
		writing=TRUE;
		sleep_for_up_to_100_microseconds();
		writing=FALSE;
		g_assert_cmpint(readers, ==, 0);
		otb_user_unlock_write(user);
	}
	g_thread_join(reader_thread3);
	g_thread_join(reader_thread2);
	g_thread_join(reader_thread1);
}

void otb_add_user_tests()
{
	otb_add_test_func("/user/test_otb_user_create_with_no_config_file", test_otb_user_create_with_no_config_file);
	otb_add_test_func("/user/test_otb_user_create_from_existing_config_file", test_otb_user_create_from_existing_config_file);
	otb_add_test_func("/user/test_otb_dummy_user_create_from_existing_config_file", test_otb_dummy_user_create_from_existing_config_file);
	otb_add_test_func("/user/test_otb_user_export", test_otb_user_export);
	otb_add_test_func("/user/test_otb_dummy_user_export", test_otb_dummy_user_export);
	otb_add_test_func("/user/test_locks", test_locks);
}
