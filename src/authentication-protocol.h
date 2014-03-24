/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_AUTHENTICATION_PROTOCOL_H
#define OTB_AUTHENTICATION_PROTOCOL_H

#include <stdint.h>

#include "asym-cipher.h"

typedef enum
{
	CLIENT,
	SERVER
} OtbAuthenticationStateType;

typedef struct _OtbAuthenticationState OtbAuthenticationState;

struct _OtbAuthenticationState
{
	unsigned char *message;
	gboolean authenticated;
	gboolean finished;
};

/// Using uint32_t here instead of size_t for array lengths because these are values that could be sent across the network, and we must be assured of 32-bit sized uints for cross compatibility. A size_t could be 64-bit on come CPUs, which would not work when talking to a 32-bit peer.
OtbAuthenticationState *otb_authentication_protocol_state_create(OtbAuthenticationStateType state_type);
uint32_t otb_authentication_protocol_request(OtbAuthenticationState *state, const void *response, uint32_t response_size, const OtbAsymCipher *asym_cipher, void **request_out);
uint32_t otb_authentication_protocol_respond(OtbAuthenticationState *state, const void *request, uint32_t request_size, const OtbAsymCipher *asym_cipher, void **response_out);
void otb_authentication_protocol_state_free(OtbAuthenticationState *state);

#endif
