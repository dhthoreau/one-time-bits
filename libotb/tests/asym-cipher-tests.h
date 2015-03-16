/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_ASYM_TESTS
#define OTB_ASYM_TESTS

#include "../src/asym-cipher.h"

void otb_generate_public_private_keys(OtbAsymCipher **asym_cipher_public_out, OtbAsymCipher **asym_cipher_private_out);
void otb_add_asym_cipher_tests();

#endif
