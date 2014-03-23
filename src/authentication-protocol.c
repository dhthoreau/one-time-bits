/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <endian.h>
#include <string.h>

#include "authentication-protocol.h"
#include "random.h"
#include "smem.h"

#define AUTH_MESSAGE_SIZE	4096

#define otb_authentication_protocol_create_error(packet_out)	otb_authentication_protocol_create_basic_packet(PROTOCOL_ERROR, packet_out)

#define PROTOCOL_ERROR				0
#define PROTOCOL_ENCRYPTED_MESSAGE	1
#define PROTOCOL_VALIDATE_MESSAGE	2

typedef unsigned char OtbAuthenticationProtocolCommand;

static uint32_t otb_authentication_protocol_create_basic_packet(OtbAuthenticationProtocolCommand command, void **packet_out)
{
	*packet_out=g_malloc(sizeof(OtbAuthenticationProtocolCommand));
	memcpy(*packet_out, &command, sizeof(OtbAuthenticationProtocolCommand));
	return sizeof(OtbAuthenticationProtocolCommand);
}

OtbAuthenticationState *otb_authentication_protocol_state_create(OtbAuthenticationStateType state_type)
{
	OtbAuthenticationState *state=g_malloc(sizeof(OtbAuthenticationState));
	state->message=(state_type==CLIENT?NULL:otb_create_random_bytes(AUTH_MESSAGE_SIZE));
	state->authenticated=FALSE;
	state->finished=FALSE;
	return state;
}

#define otb_authentication_protocol_confirm_copy_data_from_packet_is_possible(data_size, out) \
	if(packet_read_pointer+data_size>packet_read_pointer_max) \
		return otb_authentication_protocol_create_error(out);
#define otb_authentication_protocol_copy_data_from_packet(data, data_size) \
	memcpy(data, packet_read_pointer, data_size); \
	packet_read_pointer+=data_size
#define otb_authentication_protocol_copy_byte_array_from_packet(data, out) \
	uint32_t network_ ## data ## _size; \
	otb_authentication_protocol_confirm_copy_data_from_packet_is_possible(sizeof(uint32_t), out); \
	otb_authentication_protocol_copy_data_from_packet(&network_ ## data ## _size, sizeof(uint32_t)); \
	data ## _size=g_ntohl(network_ ## data ## _size); \
	otb_authentication_protocol_confirm_copy_data_from_packet_is_possible(data ## _size, out); \
	data=packet_read_pointer; \
	packet_read_pointer+=data ## _size
#define otb_authentication_protocol_copy_data_to_packet(data, data_size) \
	memcpy(packet_write_pointer, data, data_size); \
	packet_write_pointer+=data_size
#define otb_authentication_protocol_copy_gbytes_to_packet(bytes) \
	uint32_t network_ ## bytes ## _size=g_htonl(bytes ## _size); \
	otb_authentication_protocol_copy_data_to_packet(&network_ ## bytes ## _size, sizeof(uint32_t)); \
	otb_authentication_protocol_copy_data_to_packet(g_bytes_get_data(bytes, NULL), bytes ## _size);
#define otb_authentication_protocol_copy_byte_array_to_packet(bytes) \
	uint32_t network_ ## bytes ## _size=g_htonl(bytes ## _size); \
	otb_authentication_protocol_copy_data_to_packet(&network_ ## bytes ## _size, sizeof(uint32_t)); \
	otb_authentication_protocol_copy_data_to_packet(bytes, bytes ## _size);

static uint32_t otb_authentication_protocol_request_validate_message(const OtbAsymCipher *asym_cipher, const void *response, uint32_t response_size, void **request_out)
{
	const void *packet_read_pointer_max=response+response_size;
	const void *packet_read_pointer=response+sizeof(OtbAuthenticationProtocolCommand);
	const unsigned char *encrypted_key=NULL;
	const unsigned char *iv=NULL;
	const unsigned char *encrypted_message=NULL;
	uint32_t encrypted_key_size;
	uint32_t iv_size;
	uint32_t encrypted_message_size;
	otb_authentication_protocol_copy_byte_array_from_packet(encrypted_key, request_out);
	otb_authentication_protocol_copy_byte_array_from_packet(iv, request_out);
	otb_authentication_protocol_copy_byte_array_from_packet(encrypted_message, request_out);
	void *decrypted_message;
	GBytes *encrypted_key_gbytes=g_bytes_new_static(encrypted_key, encrypted_key_size);
	GBytes *iv_gbytes=g_bytes_new_static(iv, iv_size);
	uint32_t decrypted_message_size=otb_asym_cipher_decrypt(asym_cipher, encrypted_message, encrypted_message_size, encrypted_key_gbytes, iv_gbytes, &decrypted_message);
	g_bytes_unref(iv_gbytes);
	g_bytes_unref(encrypted_key_gbytes);
	uint32_t request_size;
	if(decrypted_message_size==0)
		request_size=otb_authentication_protocol_create_error(request_out);
	else
	{
		OtbAuthenticationProtocolCommand command=PROTOCOL_VALIDATE_MESSAGE;
		request_size=sizeof(OtbAuthenticationProtocolCommand)+sizeof(uint32_t)+decrypted_message_size;
		*request_out=g_malloc(request_size);
		void *packet_write_pointer=*request_out;
		otb_authentication_protocol_copy_data_to_packet(&command, sizeof(OtbAuthenticationProtocolCommand));
		otb_authentication_protocol_copy_byte_array_to_packet(decrypted_message);
	}
	return request_size;
}

static uint32_t otb_authentication_protocol_request_complete(OtbAuthenticationState *state, const void *response, uint32_t response_size, void **request_out)
{
	if(response_size==sizeof(OtbAuthenticationProtocolCommand)+sizeof(unsigned char) && *((unsigned char*)(response+sizeof(OtbAuthenticationProtocolCommand))))
		state->authenticated=TRUE;
	state->finished=TRUE;
	*request_out=NULL;
	return 0;
}

uint32_t otb_authentication_protocol_request(OtbAuthenticationState *state, const OtbAsymCipher *asym_cipher, const void *response, uint32_t response_size, void **request_out)
{
	if(response!=NULL && response_size<sizeof(OtbAuthenticationProtocolCommand))
		return otb_authentication_protocol_create_error(request_out);
	if(response==NULL)
		otb_authentication_protocol_create_basic_packet(PROTOCOL_ENCRYPTED_MESSAGE, request_out);
	else
	{
		switch(((OtbAuthenticationProtocolCommand*)response)[0])
		{
			case PROTOCOL_ENCRYPTED_MESSAGE:
				return otb_authentication_protocol_request_validate_message(asym_cipher, response, response_size, request_out);
			case PROTOCOL_VALIDATE_MESSAGE:
				return otb_authentication_protocol_request_complete(state, response, response_size, request_out);
			default:
				return otb_authentication_protocol_create_error(request_out);
		}
	}
}

static uint32_t otb_authentication_protocol_respond_send_encrypted_message(OtbAuthenticationState *state, const OtbAsymCipher *asym_cipher, void **response_out)
{
	GBytes *encrypted_key=NULL;
	GBytes *iv=NULL;
	unsigned char *encrypted_message=NULL;
	uint32_t encrypted_message_size=otb_asym_cipher_encrypt(asym_cipher, state->message, AUTH_MESSAGE_SIZE, &encrypted_key, &iv, &encrypted_message);
	uint32_t response_size;
	if(encrypted_message_size==0)
		response_size=otb_authentication_protocol_create_error(response_out);
	else
	{
		OtbAuthenticationProtocolCommand response_command=PROTOCOL_ENCRYPTED_MESSAGE;
		uint32_t encrypted_key_size=g_bytes_get_size(encrypted_key);
		uint32_t iv_size=g_bytes_get_size(iv);
		response_size=sizeof(OtbAuthenticationProtocolCommand)+sizeof(uint32_t)+encrypted_key_size+sizeof(uint32_t)+g_bytes_get_size(iv)+sizeof(uint32_t)+encrypted_message_size;
		*response_out=g_malloc(response_size);
		void *packet_write_pointer=*response_out;
		otb_authentication_protocol_copy_data_to_packet(&response_command, sizeof(OtbAuthenticationProtocolCommand));
		otb_authentication_protocol_copy_gbytes_to_packet(encrypted_key);
		otb_authentication_protocol_copy_gbytes_to_packet(iv);
		otb_authentication_protocol_copy_byte_array_to_packet(encrypted_message);
	}
	g_free(encrypted_message);
	if(iv!=NULL)
		g_bytes_unref(iv);
	if(encrypted_key!=NULL)
		g_bytes_unref(encrypted_key);
	return response_size;
}

static uint32_t otb_authentication_protocol_respond_validate_message(OtbAuthenticationState *state, const OtbAsymCipher *asym_cipher, const void *request, uint32_t request_size, void **response_out)
{
	const void *packet_read_pointer_max=request+request_size;
	const void *packet_read_pointer=request+sizeof(OtbAuthenticationProtocolCommand);
	const unsigned char *message=NULL;
	uint32_t message_size;
	otb_authentication_protocol_copy_byte_array_from_packet(message, response_out);
	unsigned char validation_result=(message_size==AUTH_MESSAGE_SIZE && smemcmp(state->message, message, AUTH_MESSAGE_SIZE)==0);
	uint32_t response_size=sizeof(OtbAuthenticationProtocolCommand)+sizeof(unsigned char);
	*response_out=g_malloc(response_size);
	void *packet_write_pointer=*response_out;
	OtbAuthenticationProtocolCommand response_command=PROTOCOL_VALIDATE_MESSAGE;
	otb_authentication_protocol_copy_data_to_packet(&response_command, sizeof(OtbAuthenticationProtocolCommand));
	otb_authentication_protocol_copy_data_to_packet(&validation_result, sizeof(unsigned char));
	if(validation_result)
		state->authenticated=TRUE;
	state->finished=TRUE;
	return response_size;
}

uint32_t otb_authentication_protocol_respond(OtbAuthenticationState *state, const void *request, uint32_t request_size, const OtbAsymCipher *asym_cipher, void **response_out)
{
	if(request_size<sizeof(OtbAuthenticationProtocolCommand))
		return otb_authentication_protocol_create_error(response_out);
	switch(((OtbAuthenticationProtocolCommand*)request)[0])
	{
		case PROTOCOL_ENCRYPTED_MESSAGE:
			return otb_authentication_protocol_respond_send_encrypted_message(state, asym_cipher, response_out);
		case PROTOCOL_VALIDATE_MESSAGE:
			return otb_authentication_protocol_respond_validate_message(state, asym_cipher, request, request_size, response_out);
		default:
			return otb_authentication_protocol_create_error(response_out);
	}
}

void otb_authentication_protocol_state_free(OtbAuthenticationState *state)
{
	g_free(state->message);
	g_free(state);
}
