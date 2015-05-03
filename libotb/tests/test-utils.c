/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <glib/gstdio.h>
#include <time.h>

#include "test-utils.h"
#include "../src/io.h"
#include "../src/local-crypto.h"
#include "../src/random.h"
#include "../src/settings.h"
#include "../src/sym-cipher.h"
#include "../src/unique-id.h"

static char *otb_test_dir_path=NULL;

void otb_recreate_test_dir()
{
	g_free(otb_test_dir_path);
	otb_test_dir_path=NULL;
	otb_test_dir_path=g_strconcat(g_get_tmp_dir(), "/otb-pad-tests", NULL);
	otb_delete_dir(otb_test_dir_path);
	g_mkdir(otb_test_dir_path, S_IRUSR | S_IWUSR | S_IRWXU);
}

void otb_delete_test_dir()
{
	otb_delete_dir(otb_test_dir_path);
	g_free(otb_test_dir_path);
	otb_test_dir_path=NULL;
}

const char *otb_get_test_dir_path()
{
	return otb_test_dir_path;
}

char *otb_generate_unique_test_subdir_path()
{
	char *unique_id_str=otb_unique_id_string_new();
	char *subdir_path=g_build_filename(otb_test_dir_path, unique_id_str, NULL);
	g_free(unique_id_str);
	return subdir_path;
}

void otb_create_local_crypto_test_config_with_few_has_iteration_so_that_unit_test_does_not_take_too_long()
{
	char *config_file_path=g_build_filename(otb_get_test_dir_path(), "otb.conf", NULL);
	FILE *file=otb_open_text_for_write(config_file_path);
	g_free(config_file_path);
	g_assert(file!=NULL);
	g_assert(otb_write("[local-crypto]\n", 1, 15, file)==15);
	g_assert(otb_write("hash-iterations=1\n", 1, 18, file)==18);
	g_assert(otb_write("[user]\n", 1, 7, file)==7);
	g_assert(otb_write("asym-cipher-new-key-size=256\n", 1, 29, file)==29);
	g_assert(otb_close(file));
}

void otb_test_setup_local_crypto()
{
	const char *PASSPHRASE="Civilization is the progress toward a society of privacy.";
	
	otb_create_local_crypto_test_config_with_few_has_iteration_so_that_unit_test_does_not_take_too_long();
	otb_settings_set_config_directory_path(otb_get_test_dir_path());
	otb_local_crypto_create_sym_cipher(PASSPHRASE);
}

#define SECONDS_TO_WAIT_FOR_DELETION_OPERATION_TO_COMPLETE	1

void otb_assert_file_does_not_exist(const char *file_path)
{
	for(clock_t start_clock=clock(), current_clock=clock(); (current_clock-start_clock)/CLOCKS_PER_SEC<SECONDS_TO_WAIT_FOR_DELETION_OPERATION_TO_COMPLETE && g_file_test(file_path, G_FILE_TEST_EXISTS) || current_clock==-1 || start_clock==-1; current_clock=clock())
		;
	g_assert(!g_file_test(file_path, G_FILE_TEST_EXISTS));
}

long long otb_few_months_from_now()
{
	long long now=g_get_real_time();
	unsigned int months;
	otb_random_bytes(&months, sizeof months);
	months=otb_modulo(months, 3)+1;
	return now+months*MICROSECONDS_PER_MONTH;
}

void otb_initialize_settings_for_tests()
{
	otb_settings_initialize("otb-tests", "otb");
	otb_settings_set_config_directory_path(otb_get_test_dir_path());
	otb_settings_set_data_directory_path(otb_get_test_dir_path());
}
