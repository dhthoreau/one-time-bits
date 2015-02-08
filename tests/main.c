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
#include <time.h>
#include <stdlib.h>

#include "asym-cipher-tests.h"
#include "protocol-tests.h"
#include "bitkeeper-tests.h"
#include "friend-tests.h"
#include "leak-tests.h"
#include "local-crypto-tests.h"
#include "pad-db-tests.h"
#include "pad-rec-tests.h"
#include "settings-tests.h"
#include "sym-cipher-tests.h"
#include "test-utils.h"
#include "unique-id-tests.h"
#include "user-tests.h"

GSList *otb_test_funcs=NULL;

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
	otb_add_bitkeeper_tests();
	otb_add_protocol_tests();
	otb_add_leak_tests();
}

static void otb_run_tests()
{
	otb_add_tests();
	g_test_run();
	g_slist_free(otb_test_funcs);
}

static void otb_null_log_handler(const char *log_domain, GLogLevelFlags log_level, const char *message, void *user_data)
{
}

int main(int argc, char *argv[])
{
	srand(time(NULL));
	g_log_set_handler(NULL, G_LOG_LEVEL_MESSAGE, otb_null_log_handler, NULL);
	setlocale(LC_ALL, "");
	textdomain(GETTEXT_PACKAGE);
	g_test_init(&argc, &argv, NULL);
	otb_run_tests(&argc, &argv);
	return 0;
}
