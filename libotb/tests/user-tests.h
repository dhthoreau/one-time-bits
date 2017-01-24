/**
 * Copyright © 2015 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_USER_TESTS
#define OTB_USER_TESTS

#include "../src/asym-cipher.h"
#include "../src/unique-id.h"

#define SHORT_KEY_SIZE_THAT_DOES_NOT_MAKE_UNIT_TESTS_RUN_SLOWLY	256

void otb_setup_config_file_for_user_tests(const OtbUniqueId *unique_id, const char *sym_cipher_name, const OtbAsymCipher *asym_cipher, const char *onion_base_domain, unsigned int port);
void otb_add_user_tests();

#endif
