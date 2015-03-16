/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_USER_TESTS
#define OTB_USER_TESTS

#include "../src/asym-cipher.h"
#include "../src/unique-id.h"

void otb_setup_config_file_for_user_tests(const OtbUniqueId *unique_id, const char *sym_cipher_name, const OtbAsymCipher *asym_cipher, const char *onion_base_domain);
void otb_add_user_tests();

#endif
