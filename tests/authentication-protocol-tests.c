/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include "asym-cipher-tests.h"
#include "main.h"
#include "../src/authentication-protocol.h"

static OtbAuthenticationState *otb_authentication_protocol_state_create_with_asserts(OtbAuthenticationStateType state_type)
{
	OtbAuthenticationState *state=otb_authentication_protocol_state_create(state_type);
	if(state_type==CLIENT)
		g_assert(state->message==NULL);
	else
		g_assert(state->message!=NULL);
	g_assert(!state->authenticated);
	g_assert(!state->finished);
	return state;
}

static void test_otb_authentication_protocol_full_success()
{
	OtbAsymCipher *asym_cipher_public=NULL;
	OtbAsymCipher *asym_cipher_private=NULL;
	otb_generate_public_private_keys(&asym_cipher_public, &asym_cipher_private);
	OtbAuthenticationState *client_state=otb_authentication_protocol_state_create_with_asserts(CLIENT);
	OtbAuthenticationState *server_state=otb_authentication_protocol_state_create_with_asserts(SERVER);
	void *request=NULL;
	void *response=NULL;
	uint32_t request_size;
	uint32_t response_size;
	request_size=otb_authentication_protocol_request(client_state, asym_cipher_private, NULL, 0, &request);
	g_assert_cmpint(1, ==, request_size);
	g_assert(request!=NULL);
	g_assert_cmpint(1, ==, ((unsigned char*)request)[0]);
	g_assert(!client_state->authenticated);
	g_assert(!client_state->finished);
	response_size=otb_authentication_protocol_respond(server_state, request, request_size, asym_cipher_public, &response);
	g_assert_cmpint(1, <, response_size);
	g_assert(response!=NULL);
	g_assert_cmpint(1, ==, ((unsigned char*)response)[0]);
	g_assert(!server_state->authenticated);
	g_assert(!server_state->finished);
	g_free(request);
	request=NULL;
	request_size=otb_authentication_protocol_request(client_state, asym_cipher_private, response, response_size, &request);
	g_assert_cmpint(1, <, request_size);
	g_assert(request!=NULL);
	g_assert_cmpint(2, ==, ((unsigned char*)request)[0]);
	g_assert(!client_state->authenticated);
	g_assert(!client_state->finished);
	g_free(response);
	response=NULL;
	response_size=otb_authentication_protocol_respond(server_state, request, request_size, asym_cipher_public, &response);
	g_assert_cmpint(2, ==, response_size);
	g_assert(response!=NULL);
	g_assert_cmpint(2, ==, ((unsigned char*)response)[0]);
	g_assert(((unsigned char*)response)[1]);
	g_assert(server_state->authenticated);
	g_assert(server_state->finished);
	g_free(request);
	request=NULL;
	request_size=otb_authentication_protocol_request(client_state, asym_cipher_private, response, response_size, &request);
	g_assert_cmpint(0, ==, request_size);
	g_assert(request==NULL);
	g_assert(client_state->authenticated);
	g_assert(client_state->finished);
	g_free(response);
	otb_authentication_protocol_state_free(server_state);
	otb_authentication_protocol_state_free(client_state);
	g_object_unref(asym_cipher_private);
	g_object_unref(asym_cipher_public);
}

void otb_add_authentication_protocol_tests()
{
	otb_add_test_func("/authentication_protocol/test_otb_authentication_protocol_full_success", test_otb_authentication_protocol_full_success);
}
