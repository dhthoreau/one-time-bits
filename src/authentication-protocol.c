/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <endian.h>

#include "authentication-protocol.h"
#include "random.h"

#define AUTH_MESSAGE_SIZE	4096

enum OtbAuthenticationProtocolStage
{
	STAGE_REQUEST_ENCRYPTED_MESSAGE
};

enum OtbAuthenticationProtocolRequest
{
	REQUEST_ERROR,
	REQUEST_ENCRYPTED_MESSAGE
};

enum OtbAuthenticationProtocolResponse
{
	RESPONSE_ERROR,
	RESPONSE_ENCRYPTED_MESSAGE
};

typedef unsigned char OtbAuthenticationProtocolCommand;

OtbAuthenticationProtocolClient *otb_authentication_protocol_client_create()
{
	OtbAuthenticationProtocolClient *client=g_malloc(sizeof(OtbAuthenticationProtocolClient));
	client->stage=0;
	client->message=NULL;
	return client;
}

uint32_t static otb_authentication_protocol_create_basic_packet(OtbAuthenticationProtocolCommand command, void **packet_out)
{
	*packet_out=g_malloc(sizeof(OtbAuthenticationProtocolCommand));
	memcpy(*packet_out, &command, sizeof(OtbAuthenticationProtocolCommand));
	return sizeof(OtbAuthenticationProtocolCommand);
}

uint32_t otb_authentication_protocol_get_next_request(OtbAuthenticationProtocolClient *client, const OtbAsymCipher *asym_cipher, void **request_out)
{
	switch(client->stage++)
	{
		case STAGE_REQUEST_ENCRYPTED_MESSAGE:
			return otb_authentication_protocol_create_basic_packet(REQUEST_ENCRYPTED_MESSAGE, request_out);
		default:
			return otb_authentication_protocol_create_basic_packet(REQUEST_ERROR, request_out);
	}
}

void otb_authentication_protocol_client_free(OtbAuthenticationProtocolClient *client)
{
	g_free(client->message);
	g_free(client);
}

OtbAuthenticationProtocolServer *otb_authentication_protocol_server_create()
{
	OtbAuthenticationProtocolServer *server=g_malloc(sizeof(OtbAuthenticationProtocolServer));
	server->message=otb_create_random_bytes(AUTH_MESSAGE_SIZE);
	return server;
}

struct OtbProtocolResponsePacketEncryptedMessage
{
	OtbAuthenticationProtocolServer command;
	uint32_t command;
}

static uint32_t otb_authentication_protocol_send_encrypted_message(OtbAuthenticationProtocolServer *server, const OtbAsymCipher *asym_cipher, void **response_out)
{
	GBytes *encrypted_key=NULL;
	GBytes *iv=NULL;
	unsigned char *encrypted_bytes=NULL;
	uint32_t encrypted_bytes_size=otb_asym_cipher_encrypt(asym_cipher, server->message, AUTH_MESSAGE_SIZE, &encrypted_key, &iv, &encrypted_bytes);
	uint32_t response_size;
	if(encrypted_bytes_size==0)
		response_size=otb_authentication_protocol_create_basic_packet(RESPONSE_ERROR, response_out);
	else
	{
		response_size=sizeof(OtbAuthenticationProtocolCommand)+sizeof(uint32_t)+g_bytes_get_size(encrypted_key)+sizeof(uint32_t)+g_bytes_get_size(iv)+sizeof(uint32_t)+encrypted_bytes_size;
		*response_out=g_malloc(response_size);
		void *response_pointer=*response_out;
		memcpy(response_pointer, (OtbAuthenticationProtocolCommand)RESPONSE_ENCRYPTED_MESSAGE, sizeof(OtbAuthenticationProtocolCommand))
		response_pointer
	}
	g_free(encrypted_bytes);
	if(iv!=NULL)
		g_bytes_unref(iv);
	if(encrypted_key!=NULL)
		g_bytes_unref(encrypted_key);
	return response_size;
}

uint32_t otb_authentication_protocol_get_response(OtbAuthenticationProtocolServer *state, unsigned char *request, uint32_t request_size, const OtbAsymCipher *asym_cipher, void **response_out)
{
	switch(request[0])
	{
		case REQUEST_ENCRYPTED_MESSAGE:
			return otb_authentication_protocol_send_encrypted_message(state, asym_cipher, response_out);
		default:
			return otb_authentication_protocol_create_basic_packet(RESPONSE_ERROR, response_out);
	}
}

void otb_authentication_protocol_server_free(OtbAuthenticationProtocolServer *server)
{
	g_free(server->message);
	g_free(server);
}
