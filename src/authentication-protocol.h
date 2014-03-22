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

typedef struct _OtbAuthenticationState OtbAuthenticationState;

struct _OtbAuthenticationState
{
	unsigned char *message;
	gboolean authenticated;
	gboolean finished;
};

OtbAuthenticationState *otb_authentication_protocol_state_create();	// FARE - Unit test.
uint32_t otb_authentication_protocol_request(OtbAuthenticationState *state, const OtbAsymCipher *asym_cipher, const void *response, uint32_t response_size, void **request_out);	// FARE - Unit test.
uint32_t otb_authentication_protocol_respond(OtbAuthenticationState *state, const void *request, uint32_t request_size, const OtbAsymCipher *asym_cipher, void **response_out);	// FARE - Unit test.
void otb_authentication_protocol_state_free(OtbAuthenticationState *state);	// FARE - Unit test.

#endif
