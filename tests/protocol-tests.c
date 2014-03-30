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
#include "../src/protocol.h"

/*static OtbProtocolState *otb_protocol_state_create_with_asserts(OtbBitkeeper *bitkeeper)
{
	OtbProtocolState *state=otb_protocol_state_create(bitkeeper);
	g_assert(state->message!=NULL);
	g_assert(!state->authenticated);
	g_assert(!state->finished);
	return state;
}

static uint32_t otb_protocol_test_client_sends_unique_id(OtbProtocolState *client_state, OtbAsymCipher *asym_cipher_private, void **output_out)
{
	uint32_t request_size=otb_protocol_request(client_state, NULL, 0, asym_cipher_private, output_out);
	g_assert_cmpint(1, ==, request_size);
	g_assert(*request_out!=NULL);
	g_assert_cmpint(1, ==, ((unsigned char*)*request_out)[0]);
	g_assert(!client_state->authenticated);
	g_assert(!client_state->finished);
	return request_size;
}

static uint32_t otb_protocol_test_server_sends_encrypted_message(OtbProtocolState *server_state, OtbAsymCipher *asym_cipher_public, void *input, uint32_t input_size, void **output_out)
{
	uint32_t output_size=otb_protocol_server(server_state, input, input_size, asym_cipher_public, output_out);
	g_assert_cmpint(1, <, output_size);
	g_assert(*output_out!=NULL);
	g_assert_cmpint(1, ==, ((unsigned char*)*output_out)[0]);
	g_assert(!server_state->authenticated);
	g_assert(!server_state->finished);
	return output_size;
}

static uint32_t otb_protocol_test_client_sends_validate_message(OtbProtocolState *client_state, const OtbAsymCipher *asym_cipher_private, const void *response, uint32_t response_size, void **request_out)
{
	uint32_t request_size=otb_protocol_request(client_state, response, response_size, asym_cipher_private, request_out);
	g_assert_cmpint(1, <, request_size);
	g_assert(*request_out!=NULL);
	g_assert_cmpint(2, ==, ((unsigned char*)*request_out)[0]);
	g_assert(!client_state->authenticated);
	g_assert(!client_state->finished);
	return request_size;
}

static uint32_t otb_protocol_test_server_sends_confirm_validate_message(OtbProtocolState *server_state, const OtbAsymCipher *asym_cipher_public, const void *request, uint32_t request_size, void **response_out)
{
	uint32_t response_size=otb_protocol_respond(server_state, request, request_size, asym_cipher_public, response_out);
	g_assert_cmpint(2, ==, response_size);
	g_assert(*response_out!=NULL);
	g_assert_cmpint(2, ==, ((unsigned char*)*response_out)[0]);
	g_assert(((unsigned char*)*response_out)[1]);
	g_assert(server_state->authenticated);
	g_assert(server_state->finished);
	return response_size;
}

static void otb_protocol_test_finish_request(OtbProtocolState *client_state, const OtbAsymCipher *asym_cipher_private, const void *response, uint32_t response_size, void **request_out)
{
	uint32_t request_size=otb_protocol_request(client_state, response, response_size, asym_cipher_private, request_out);
	g_assert_cmpint(0, ==, request_size);
	g_assert(*request_out==NULL);
	g_assert(client_state->authenticated);
	g_assert(client_state->finished);
}

static void test_otb_protocol_full_success()
{
	OtbAsymCipher *asym_cipher_public=NULL;
	OtbAsymCipher *asym_cipher_private=NULL;
	otb_generate_public_private_keys(&asym_cipher_public, &asym_cipher_private);
	OtbProtocolState *client_state=otb_protocol_state_create_with_asserts();
	OtbProtocolState *server_state=otb_protocol_state_create_with_asserts();
	void *client=NULL;
	uint32_t client_size=otb_protocol_test_client_sends_unique_id(client_state, asym_cipher_private, &client);
	void *server=NULL;
	uint32_t server_size=otb_protocol_test_server_sends_encrypted_message(server_state, asym_cipher_public, client, client_size, &server);
	g_free(client);
	client=NULL;
	client_size=otb_protocol_test_client_sends_validate_message(client_state, asym_cipher_private, server, server_size, &client);
	g_free(server);
	server=NULL;
	server_size=otb_protocol_test_server_sends_confirm_validate_message(server_state, asym_cipher_public, client, client_size, &server);
	g_free(client);
	client=NULL;
	otb_(client_state, asym_cipher_private, server, server_size, &client);
	g_free(server);
	otb_protocol_state_free(server_state);
	otb_protocol_state_free(client_state);
	g_object_unref(asym_cipher_private);
	g_object_unref(asym_cipher_public);
}*/

void otb_add_protocol_tests()
{
//	otb_add_test_func("/protocol/test_otb_protocol_full_success", test_otb_protocol_full_success);
}
