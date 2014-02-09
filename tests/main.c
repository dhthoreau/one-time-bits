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

#include "cipher-tests.h"
#include "local-crypto-tests.h"
#include "friend-tests.h"
#include "pad-db-tests.h"
#include "pad-rec-tests.h"
#include "settings-tests.h"
#include "test-utils.h"

GSList *otb_test_funcs=NULL;

static gboolean leaky=FALSE;

static GOptionEntry entries[]=
{
	{"leaky", 0, 0, G_OPTION_ARG_NONE, &leaky, "", NULL},
	{ NULL }
};

static gboolean parse_input(int *p_argc, char **p_argv[])
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

static void call_test(const gpointer test, const gpointer user_data)
{
	GTestFunc test_func=(GTestFunc)test;
	test_func();
}

static void run_tests_to_find_memory_leaks()
{
	otb_recreate_test_dir();
	g_slist_foreach(otb_test_funcs, call_test, NULL);
	otb_delete_test_dir();
}

static void add_tests()
{
	add_settings_tests();
	add_cipher_tests();
	add_local_crypto_tests();
	add_pad_rec_tests();
	add_pad_db_tests();
	add_friend_tests();
}

static void run_tests()
{
	otb_recreate_test_dir();
	add_tests();
	g_test_run();
	otb_delete_test_dir();
	while(leaky)
		run_tests_to_find_memory_leaks();
	g_slist_free(otb_test_funcs);
}

static void null_log_handler(const char *log_domain, GLogLevelFlags log_level, const char *message, gpointer user_data)
{
}

int main(int argc, char *argv[])
{
	g_log_set_handler(NULL, G_LOG_LEVEL_MESSAGE, null_log_handler, NULL);
	setlocale(LC_ALL, "");
	textdomain(GETTEXT_PACKAGE);
	g_test_init(&argc, &argv, NULL);
	if(!parse_input(&argc, &argv))
		return 1;
	run_tests(&argc, &argv);
	return 0;
}

