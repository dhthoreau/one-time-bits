/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_AUTHENTICATION_PROTOCOL_H
#define OTB_AUTHENTICATION_PROTOCOL_H

#include "asym-cipher.h"

typedef struct _OtbAuthenticationProtocolClient OtbAuthenticationProtocolClient;
typedef struct _OtbAuthenticationProtocolServer OtbAuthenticationProtocolServer;

struct _OtbAuthenticationProtocolClient
{
	int stage;
	unsigned char *message;
};

struct _OtbAuthenticationProtocolServer
{
	unsigned char *message;
};

OtbAuthenticationProtocolClient *otb_authentication_protocol_client_create();	// FARE - Unit test.
uint32_t otb_authentication_protocol_get_next_request(OtbAuthenticationProtocolClient *client, const OtbAsymCipher *asym_cipher, void **request_out);	// FARE - Unit test.
void otb_authentication_protocol_client_free(OtbAuthenticationProtocolClient *client);	// FARE - Unit test.

OtbAuthenticationProtocolServer *otb_authentication_protocol_server_create();	// FARE - Unit test.
uint32_t otb_authentication_protocol_get_response(OtbAuthenticationProtocolServer *state, unsigned char *request, uint32_t request_size, const OtbAsymCipher *asym_cipher, void **response_out);	// FARE - Unit test.
void otb_authentication_protocol_server_free(OtbAuthenticationProtocolServer *server);	// FARE - Unit test.

#endif
