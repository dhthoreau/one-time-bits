/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <glib/gi18n.h>
#include <locale.h>
#include <main.h>

#include "asym-cipher-tests.h"
#include "local-crypto-tests.h"
#include "friend-tests.h"
#include "pad-db-tests.h"
#include "pad-rec-tests.h"
#include "settings-tests.h"
#include "sym-cipher-tests.h"
#include "test-utils.h"
#include "unique-id-tests.h"
#include "user-tests.h"

GSList *otb_test_funcs=NULL;

static gboolean leaky=FALSE;

static GOptionEntry entries[]=
{
	{"leaky", 0, 0, G_OPTION_ARG_NONE, &leaky, "", NULL},
	{ NULL }
};

static gboolean otb_parse_input(int *p_argc, char **p_argv[])
{
	gboolean ret_val=TRUE;
	GError *error=NULL;
	GOptionContext *context=g_option_context_new("");
	g_option_context_add_main_entries(context, entries, GETTEXT_PACKAGE);
	if (!g_option_context_parse(context, p_argc, p_argv, &error))
	{
		g_print("%s\n", error->message);
		g_error_free(error);
		ret_val=FALSE;
	}
	g_option_context_free(context);
	return ret_val;
}

static void otb_call_test(const gpointer test, const gpointer user_data)
{
	GTestFunc test_func=(GTestFunc)test;
	test_func();
}

static void otb_run_tests_to_find_memory_leaks()
{
	otb_recreate_test_dir();
	g_slist_foreach(otb_test_funcs, otb_call_test, NULL);
	otb_delete_test_dir();
}

static void otb_add_tests()
{
	otb_add_unique_id_tests();
	otb_add_settings_tests();
	otb_add_sym_cipher_tests();
	otb_add_asym_cipher_tests();
	otb_add_local_crypto_tests();
	otb_add_pad_rec_tests();
	otb_add_pad_db_tests();
	otb_add_friend_tests();
	otb_add_user_tests();
}

static void otb_run_tests()
{
	otb_recreate_test_dir();
	otb_add_tests();
	g_test_run();
	otb_delete_test_dir();
	while(leaky)
		otb_run_tests_to_find_memory_leaks();
	g_slist_free(otb_test_funcs);
}

static void otb_null_log_handler(const char *log_domain, GLogLevelFlags log_level, const char *message, gpointer user_data)
{
}

int main(int argc, char *argv[])
{
	g_log_set_handler(NULL, G_LOG_LEVEL_MESSAGE, otb_null_log_handler, NULL);
	setlocale(LC_ALL, "");
	textdomain(GETTEXT_PACKAGE);
	g_test_init(&argc, &argv, NULL);
	if(!otb_parse_input(&argc, &argv))
		return 1;
	otb_run_tests(&argc, &argv);
	return 0;
}

