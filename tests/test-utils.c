/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <glib/gstdio.h>
#include <uuid.h>

#include "test-utils.h"
#include "../src/io.h"
#include "../src/local-crypto.h"
#include "../src/settings.h"
#include "../src/sym-cipher.h"
#include "../src/uuid-util.h"

char *otb_test_dir_path=NULL;

static void otb_delete_dir(const char *dir_path)
{
	GError *error=NULL;
	GDir *test_dir=g_dir_open(dir_path, 0, &error);
	if(test_dir)
	{
		const char *file_name;
		while((file_name=g_dir_read_name(test_dir)))
		{
			char *file_path=g_build_filename(dir_path, file_name, NULL);
			if(g_file_test(file_path, G_FILE_TEST_IS_DIR))
				otb_delete_dir(file_path);
			else
				g_unlink(file_path);
			g_free(file_path);
		}
		g_dir_close(test_dir);
	}
	else
		g_error_free(error);
	g_rmdir(dir_path);
}

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
	uuid_t unique_id;
	uuid_generate(unique_id);
	char unique_id_str[UNIQUE_ID_STR_BYTES];
	uuid_unparse_lower(unique_id, unique_id_str);
	return g_build_filename(otb_test_dir_path, unique_id_str, NULL);
}

void otb_create_local_crypto_test_config_with_few_has_iteration_so_that_unit_test_does_not_take_too_long()
{
	char *config_file_path=g_build_filename(otb_get_test_dir_path(), "otb.conf", NULL);
	FILE *file=otb_open_for_write(config_file_path, "otb_create_local_crypto_test_config");
	g_free(config_file_path);
	g_assert(file!=NULL);
	g_assert(otb_write("[local-crypto]\n", 1, 15, file, "otb_create_local_crypto_test_config")==15);
	g_assert(otb_write("hash-iterations=1\n", 1, 18, file, "otb_create_local_crypto_test_config")==18);
	g_assert(otb_close(file, "otb_create_local_crypto_test_config"));
}

void otb_test_setup_local_crypto()
{
	const char *PASSPHRASE="Civilization is the progress toward a society of privacy.";
	
	otb_create_local_crypto_test_config_with_few_has_iteration_so_that_unit_test_does_not_take_too_long();
	otb_settings_set_config_directory_path(otb_get_test_dir_path());
	otb_local_crypto_create_sym_cipher(PASSPHRASE);
}
