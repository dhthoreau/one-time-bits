/**
 * Copyright © 2015 the OTB team
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
#include "../src/local-crypto.h"
#include "../src/settings.h"

static void test_local_crypto()
{
	const char *EXPECTED_PASSPHRASE="Without music, life would be a mistake.";
	const char *NEW_PASSPHRASE="Whoever fights monsters should see to it that in the process he does not become a monster.";
	
	otb_create_local_crypto_test_config_with_few_has_iteration_so_that_unit_test_does_not_take_too_long();
	otb_initialize_settings_for_tests();
	g_assert(!otb_local_crypto_can_be_unlocked());
	g_assert(otb_local_crypto_create_sym_cipher(EXPECTED_PASSPHRASE));
	g_assert(otb_local_crypto_can_be_unlocked());
	g_assert(!otb_local_crypto_unlock_sym_cipher(NEW_PASSPHRASE));
	g_assert(otb_local_crypto_unlock_sym_cipher(EXPECTED_PASSPHRASE));
	OtbSymCipher *local_crypto_sym_cipher=otb_local_crypto_get_sym_cipher_with_ref();
	g_assert(local_crypto_sym_cipher!=NULL);
	g_object_unref(local_crypto_sym_cipher);
	g_assert(otb_local_crypto_change_passphrase(EXPECTED_PASSPHRASE, NEW_PASSPHRASE));
	g_assert(!otb_local_crypto_unlock_sym_cipher(EXPECTED_PASSPHRASE));
	g_assert(otb_local_crypto_unlock_sym_cipher(NEW_PASSPHRASE));
	local_crypto_sym_cipher=otb_local_crypto_get_sym_cipher_with_ref();
	g_assert(local_crypto_sym_cipher!=NULL);
	otb_local_crypto_lock_sym_cipher();
	g_object_unref(local_crypto_sym_cipher);
}

void otb_add_local_crypto_tests()
{
	otb_add_test_func("/local-crypto/test_local_crypto", test_local_crypto);
}
