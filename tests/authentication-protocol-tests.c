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

static uint32_t otb_authentication_protocol_test_encrypted_message_request(OtbAuthenticationState *client_state, OtbAsymCipher *asym_cipher_private, void **request_out)
{
	uint32_t request_size=otb_authentication_protocol_request(client_state, NULL, 0, asym_cipher_private, request_out);
	g_assert_cmpint(1, ==, request_size);
	g_assert(*request_out!=NULL);
	g_assert_cmpint(1, ==, ((unsigned char*)*request_out)[0]);
	g_assert(!client_state->authenticated);
	g_assert(!client_state->finished);
	return request_size;
}

static uint32_t otb_authentication_protocol_test_encrypted_message_response(OtbAuthenticationState *server_state, OtbAsymCipher *asym_cipher_public, void *request, uint32_t request_size, void **response_out)
{
	uint32_t response_size=otb_authentication_protocol_respond(server_state, request, request_size, asym_cipher_public, response_out);
	g_assert_cmpint(1, <, response_size);
	g_assert(*response_out!=NULL);
	g_assert_cmpint(1, ==, ((unsigned char*)*response_out)[0]);
	g_assert(!server_state->authenticated);
	g_assert(!server_state->finished);
	return response_size;
}

static uint32_t otb_authentication_protocol_test_verify_message_request(OtbAuthenticationState *client_state, const OtbAsymCipher *asym_cipher_private, const void *response, uint32_t response_size, void **request_out)
{
	uint32_t request_size=otb_authentication_protocol_request(client_state, response, response_size, asym_cipher_private, request_out);
	g_assert_cmpint(1, <, request_size);
	g_assert(*request_out!=NULL);
	g_assert_cmpint(2, ==, ((unsigned char*)*request_out)[0]);
	g_assert(!client_state->authenticated);
	g_assert(!client_state->finished);
	return request_size;
}

static uint32_t otb_authentication_protocol_test_verify_message_response(OtbAuthenticationState *server_state, const OtbAsymCipher *asym_cipher_public, const void *request, uint32_t request_size, void **response_out)
{
	uint32_t response_size=otb_authentication_protocol_respond(server_state, request, request_size, asym_cipher_public, response_out);
	g_assert_cmpint(2, ==, response_size);
	g_assert(*response_out!=NULL);
	g_assert_cmpint(2, ==, ((unsigned char*)*response_out)[0]);
	g_assert(((unsigned char*)*response_out)[1]);
	g_assert(server_state->authenticated);
	g_assert(server_state->finished);
	return response_size;
}

static void otb_authentication_protocol_test_finish_request(OtbAuthenticationState *client_state, const OtbAsymCipher *asym_cipher_private, const void *response, uint32_t response_size, void **request_out)
{
	uint32_t request_size=otb_authentication_protocol_request(client_state, response, response_size, asym_cipher_private, request_out);
	g_assert_cmpint(0, ==, request_size);
	g_assert(*request_out==NULL);
	g_assert(client_state->authenticated);
	g_assert(client_state->finished);
}

static void test_otb_authentication_protocol_full_success()
{
	OtbAsymCipher *asym_cipher_public=NULL;
	OtbAsymCipher *asym_cipher_private=NULL;
	otb_generate_public_private_keys(&asym_cipher_public, &asym_cipher_private);
	OtbAuthenticationState *client_state=otb_authentication_protocol_state_create_with_asserts(CLIENT);
	OtbAuthenticationState *server_state=otb_authentication_protocol_state_create_with_asserts(SERVER);
	void *request=NULL;
	uint32_t request_size=otb_authentication_protocol_test_encrypted_message_request(client_state, asym_cipher_private, &request);
	void *response=NULL;
	uint32_t response_size=otb_authentication_protocol_test_encrypted_message_response(server_state, asym_cipher_public, request, request_size, &response);
	g_free(request);
	request=NULL;
	request_size=otb_authentication_protocol_test_verify_message_request(client_state, asym_cipher_private, response, response_size, &request);
	g_free(response);
	response=NULL;
	response_size=otb_authentication_protocol_test_verify_message_response(server_state, asym_cipher_public, request, request_size, &response);
	g_free(request);
	request=NULL;
	otb_authentication_protocol_test_finish_request(client_state, asym_cipher_private, response, response_size, &request);
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
