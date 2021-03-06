/**
 * Copyright © 2017 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_LOCAL_CRYPTO_H
#define OTB_LOCAL_CRYPTO_H

#include "sym-cipher.h"

gboolean otb_local_crypto_can_be_unlocked(void);
gboolean otb_local_crypto_set(OtbSymCipher *sym_cipher, const char *passphrase);
gboolean otb_local_crypto_unlock(const char *passphrase);
void otb_local_crypto_lock(void);
gboolean otb_local_crypto_change_passphrase(const char *old_passphrase, const char *new_passphrase);
OtbSymCipher *otb_local_crypto_get_sym_cipher_with_ref(void);

#endif
