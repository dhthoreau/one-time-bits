/**
 * Copyright © 2015 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_FRIEND_TESTS
#define OTB_FRIEND_TESTS

#include "../src/unique-id.h"

char *otb_create_import_string(const OtbUniqueId *unique_id, const char *public_key, const char *transport_cipher_name, const char *onion_base_domain, unsigned short port, const char *dummy_value);
void otb_add_friend_tests();

#endif
