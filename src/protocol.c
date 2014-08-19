/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

/**

Note: COMMAND_ERROR will be the outgoing command to server in any case where the incoming command from server is unexpected or some other problem has occurred, leading to STATE_FINISHED.


+++ Summary of Client State Transitions +++

Format: Current client state -> Incoming command from server -> Outgoing command to server -> Next state of client
Encrypted commands are in {brackets}.

STATE_INITIAL -> <null> -> COMMAND_PROTOCOL_VERSION -> STATE_ESTABLISHING_PROTOCOL_VERSION

STATE_ESTABLISHING_PROTOCOL_VERSION -> COMMAND_OK -> COMMAND_SENDING_FRIEND_ID -> STATE_ESTABLISHING_FRIEND

STATE_ESTABLISHING_FRIEND -> COMMAND_OK -> {COMMAND_SENDING_AUTHENTICATION_TOKEN} -> STATE_SERVER_AUTHENTICATION

STATE_SERVER_AUTHENTICATION -> {COMMAND_SENDING_AUTHENTICATION_TOKEN} -> COMMAND_REQUESTING_AUTHENTICATION -> STATE_CLIENT_REQUESTING_AUTHENTICATION

STATE_CLIENT_REQUESTING_AUTHENTICATION -> {COMMAND_SENDING_AUTHENTICATION_TOKEN} -> {COMMAND_SENDING_AUTHENTICATION_TOKEN} -> STATE_CLIENT_AUTHENTICATION

STATE_CLIENT_AUTHENTICATION -> COMMAND_OK -> COMMAND_REQUESTING_PAD_IDS -> STATE_CLIENT_REQUESTING_PAD_IDS_FROM_SERVER

STATE_CLIENT_REQUESTING_PAD_IDS_FROM_SERVER -> {COMMAND_SENDING_PAD_IDS} -> {COMMAND_SENDING_PAD_IDS} -> STATE_CLIENT_SENDING_PAD_IDS_TO_SERVER

STATE_CLIENT_SENDING_PAD_IDS_TO_SERVER -> COMMAND_OK -> {COMMAND_SENDING_PAD_HEADER} -> STATE_CLIENT_SENDING_PAD_HEADER_TO_SERVER
                                                        COMMAND_FINISH -> STATE_FINISHED

STATE_CLIENT_SENDING_PAD_HEADER_TO_SERVER -> COMMAND_UNABLE -> <null> -> STATE_FINISHED
                                             COMMAND_OK -> {COMMAND_SENDING_PAD_CHUNK} -> STATE_CLIENT_SENDING_PAD_CHUNK_TO_SERVER
                                                           {COMMAND_SENDING_FINAL_PAD_CHUNK} -> STATE_CLIENT_SENDING_FINAL_PAD_CHUNK_TO_SERVER

STATE_CLIENT_SENDING_PAD_CHUNK_TO_SERVER -> COMMAND_OK -> {COMMAND_SENDING_PAD_CHUNK} -> STATE_CLIENT_SENDING_PAD_CHUNK_TO_SERVER
                                                          {COMMAND_SENDING_FINAL_PAD_CHUNK} -> STATE_CLIENT_SENDING_FINAL_PAD_CHUNK_TO_SERVER

STATE_CLIENT_SENDING_FINAL_PAD_CHUNK_TO_SERVER -> COMMAND_OK -> {COMMAND_SENDING_PAD_HEADER} -> STATE_CLIENT_SENDING_PAD_HEADER_TO_SERVER
                                                                COMMAND_FINISH -> STATE_FINISHED


+++ Summary of Server State Transitions +++

Format: Current client state -> Incoming command from server -> Outgoing command to server -> Next state of client
Encrypted commands are in {brackets}.

STATE_INITIAL -> COMMAND_PROTOCOL_VERSION -> COMMAND_OK -> STATE_ESTABLISHING_PROTOCOL_VERSION

STATE_ESTABLISHING_PROTOCOL_VERSION -> COMMAND_SENDING_FRIEND_ID -> COMMAND_OK -> STATE_ESTABLISHING_FRIEND

STATE_ESTABLISHING_FRIEND -> {COMMAND_SENDING_AUTHENTICATION_TOKEN} -> {COMMAND_SENDING_AUTHENTICATION_TOKEN} -> STATE_SERVER_AUTHENTICATION

STATE_SERVER_AUTHENTICATION -> COMMAND_REQUESTING_AUTHENTICATION -> {COMMAND_SENDING_AUTHENTICATION_TOKEN} -> STATE_CLIENT_REQUESTING_AUTHENTICATION

STATE_CLIENT_REQUESTING_AUTHENTICATION ->  {COMMAND_SENDING_AUTHENTICATION_TOKEN}-> COMMAND_OK -> STATE_CLIENT_AUTHENTICATION

STATE_CLIENT_AUTHENTICATION -> COMMAND_REQUESTING_PAD_IDS -> {COMMAND_SENDING_PAD_IDS} -> STATE_CLIENT_REQUESTING_PAD_IDS_FROM_SERVER

STATE_CLIENT_REQUESTING_PAD_IDS_FROM_SERVER -> {COMMAND_SENDING_PAD_IDS} -> COMMAND_OK -> STATE_CLIENT_SENDING_PAD_IDS_TO_SERVER

STATE_CLIENT_SENDING_PAD_IDS_TO_SERVER -> COMMAND_FINISH -> <null> -> STATE_FINISHED
                                          {COMMAND_SENDING_PAD_HEADER} -> COMMAND_UNABLE -> STATE_FINISHED
                                                                          COMMAND_OK -> STATE_CLIENT_SENDING_PAD_HEADER_TO_SERVER

STATE_CLIENT_SENDING_PAD_HEADER_TO_SERVER -> COMMAND_FINISH -> <null> -> STATE_FINISHED
                                             {COMMAND_SENDING_PAD_CHUNK} -> COMMAND_OK -> STATE_CLIENT_SENDING_PAD_CHUNK_TO_SERVER
                                             {COMMAND_SENDING_FINAL_PAD_CHUNK} -> COMMAND_OK -> STATE_CLIENT_SENDING_FINAL_PAD_CHUNK_TO_SERVER

STATE_CLIENT_SENDING_PAD_CHUNK_TO_SERVER -> {COMMAND_SENDING_PAD_CHUNK} -> COMMAND_OK -> STATE_CLIENT_SENDING_PAD_CHUNK_TO_SERVER
                                            {COMMAND_SENDING_FINAL_PAD_CHUNK} -> COMMAND_OK -> STATE_CLIENT_SENDING_FINAL_PAD_CHUNK_TO_SERVER

STATE_CLIENT_SENDING_FINAL_PAD_CHUNK_TO_SERVER -> COMMAND_FINISH -> <null> -> STATE_FINISHED
                                                  {COMMAND_SENDING_PAD_HEADER} -> COMMAND_UNABLE -> STATE_FINISHED
                                                                                  COMMAND_OK -> STATE_CLIENT_SENDING_PAD_HEADER_TO_SERVER
*/

#include "../config.h"

#include <endian.h>
#include <string.h>

#include "memory.h"
#include "pad-db.h"
#include "pad-rec.h"
#include "protocol.h"
#include "random.h"
#include "settings.h"

#define CONFIG_GROUP				"protocol"
#define CONFIG_CHUNK_SIZE			"chunk-size"
#define CONFIG_DEFAULT_CHUNK_SIZE	524288

#define AUTHENTICATION_TOKEN_SIZE	4096

typedef unsigned char OtbProtocolCommand;

enum
{
	COMMAND_PROTOCOL_VERSION,
	COMMAND_ERROR,
	COMMAND_OK,
	COMMAND_ENCRYPTED,
	COMMAND_SENDING_FRIEND_ID,
	COMMAND_REQUESTING_AUTHENTICATION,
	COMMAND_SENDING_AUTHENTICATION_TOKEN,
	COMMAND_REQUESTING_PAD_IDS,
	COMMAND_SENDING_PAD_IDS,
	COMMAND_SENDING_PAD_HEADER,
	COMMAND_SENDING_PAD_CHUNK,
	COMMAND_SENDING_FINAL_PAD_CHUNK,
	COMMAND_UNABLE,
	COMMAND_FINISH
};

enum
{
	STATE_INITIAL,
	STATE_ESTABLISHING_PROTOCOL_VERSION,
	STATE_ESTABLISHING_FRIEND,
	STATE_SERVER_AUTHENTICATION,
	STATE_CLIENT_REQUESTING_AUTHENTICATION,
	STATE_CLIENT_AUTHENTICATION,
	STATE_CLIENT_REQUESTING_PAD_IDS_FROM_SERVER,
	STATE_CLIENT_SENDING_PAD_IDS_TO_SERVER,
	STATE_CLIENT_SENDING_PAD_HEADER_TO_SERVER,
	STATE_CLIENT_SENDING_PAD_CHUNK_TO_SERVER,
	STATE_CLIENT_SENDING_FINAL_PAD_CHUNK_TO_SERVER,
	STATE_FINISHED
};

static void otb_protocol_set_peer_friend_on_context(OtbProtocolContext *context, OtbFriend *peer_friend)
{
	g_object_ref(peer_friend);
	context->peer_friend=peer_friend;
	char *peer_public_key=NULL;
	char *peer_transport_cipher_name=NULL;
	g_object_get(peer_friend, OTB_FRIEND_PROP_PUBLIC_KEY, &peer_public_key, OTB_FRIEND_PROP_TRANSPORT_CIPHER_NAME, &peer_transport_cipher_name, OTB_FRIEND_PROP_OUTGOING_PADS, &context->pad_db, NULL);
	context->peer_asym_cipher=g_object_new(OTB_TYPE_ASYM_CIPHER, OTB_ASYM_CIPHER_PROP_PUBLIC_KEY, peer_public_key, OTB_ASYM_CIPHER_PROP_SYM_CIPHER_NAME, peer_transport_cipher_name, NULL);
	g_free(peer_transport_cipher_name);
	g_free(peer_public_key);
}

OtbProtocolContext *otb_protocol_context_create_client(OtbBitkeeper *bitkeeper, OtbFriend *peer_friend)
{
	OtbProtocolContext *context=g_malloc(sizeof *context);
	context->authentication_token=otb_create_random_bytes(AUTHENTICATION_TOKEN_SIZE);
	g_object_ref(bitkeeper);
	context->bitkeeper=bitkeeper;
	g_object_get(bitkeeper, OTB_BITKEEPER_PROP_USER, &context->local_user, NULL);
	g_object_get(context->local_user, OTB_USER_PROP_ASYM_CIPHER, &context->local_asym_cipher, NULL);
	if(peer_friend!=NULL)
		otb_protocol_set_peer_friend_on_context(context, peer_friend);
	else
	{
		context->peer_friend=NULL;
		context->peer_asym_cipher=NULL;
		context->pad_db=NULL;
	}
	context->pad_id=NULL;
	context->pad_io=NULL;
	context->state=STATE_INITIAL;
	return context;
}

///Basic command packet structure:
///  OtbProtocolCommand - Command
#define BASIC_COMMAND_PACKET_SIZE	(sizeof(OtbProtocolCommand))
#define PACKET_COMMAND(packet)		((packet)[0])

static uint32_t otb_protocol_create_basic_command_packet(OtbProtocolCommand command, unsigned char **packet_out)
{
	*packet_out=g_malloc(BASIC_COMMAND_PACKET_SIZE);
	PACKET_COMMAND(*packet_out)=command;
	return BASIC_COMMAND_PACKET_SIZE;
}

#define otb_protocol_create_ok_packet(packet_out)	(otb_protocol_create_basic_command_packet(COMMAND_OK, (packet_out)))

static uint32_t otb_protocol_create_error_packet(OtbProtocolContext *context, unsigned char **packet_out)
{
	context->state=STATE_FINISHED;
	return otb_protocol_create_basic_command_packet(COMMAND_ERROR, packet_out);
}

///Encrypted packet structure:
///  OtbProtocolCommand - Command
///  uint32_t - Encrypted key length
///  uint32_t - IV length
///  uint32_t - Encryted data length
///  unsigned char* - Encrypted key
///  unsigned char* - IV
///  unsigned char* - Encrypted data
#define PACKET_NUMBER(packet, position, type)				*((type*)((packet)+(position)))
#define SET_PACKET_NUMBER(packet, position, value, type)	(PACKET_NUMBER((packet), (position), type)=g_htonl(value))
#define GET_PACKET_NUMBER(packet, position, type)			(g_ntohl(PACKET_NUMBER((packet), (position), type)))
#define SET_PACKET_UINT32(packet, position, value)			(SET_PACKET_NUMBER((packet), (position), (value), uint32_t))
#define GET_PACKET_UINT32(packet, position)					(GET_PACKET_NUMBER((packet), (position), uint32_t))
#define SET_PACKET_INT64(packet, position, value)			(SET_PACKET_NUMBER((packet), (position), (value), int64_t))
#define GET_PACKET_INT64(packet, position)					(GET_PACKET_NUMBER((packet), (position), int64_t))

#define ENCRYPTED_PACKET_SET_ENCRYPTED_KEY_SIZE(packet, size)	SET_PACKET_UINT32((packet), sizeof(OtbProtocolCommand), (size))
#define ENCRYPTED_PACKET_GET_ENCRYPTED_KEY_SIZE(packet)			GET_PACKET_UINT32((packet), sizeof(OtbProtocolCommand))
#define ENCRYPTED_PACKET_SET_IV_SIZE(packet, size)				SET_PACKET_UINT32((packet), sizeof(OtbProtocolCommand)+sizeof(uint32_t), (size))
#define ENCRYPTED_PACKET_GET_IV_SIZE(packet)					GET_PACKET_UINT32((packet), sizeof(OtbProtocolCommand)+sizeof(uint32_t))
#define ENCRYPTED_PACKET_SET_ENCRYPTED_DATA_SIZE(packet, size)	SET_PACKET_UINT32((packet), sizeof(OtbProtocolCommand)+sizeof(uint32_t)+sizeof(uint32_t), (size))
#define ENCRYPTED_PACKET_GET_ENCRYPTED_DATA_SIZE(packet)		GET_PACKET_UINT32((packet), sizeof(OtbProtocolCommand)+sizeof(uint32_t)+sizeof(uint32_t))

#define ENCRYPTED_PACKET_ENCRYPTED_KEY(packet)			((packet)+sizeof(OtbProtocolCommand)+sizeof(uint32_t)+sizeof(uint32_t)+sizeof(uint32_t))
#define ENCRYPTED_PACKET_IV(packet)						((packet)+sizeof(OtbProtocolCommand)+sizeof(uint32_t)+sizeof(uint32_t)+sizeof(uint32_t)+ENCRYPTED_PACKET_GET_ENCRYPTED_KEY_SIZE(packet))
#define ENCRYPTED_PACKET_ENCRYPTED_DATA(packet)			((packet)+sizeof(OtbProtocolCommand)+sizeof(uint32_t)+sizeof(uint32_t)+sizeof(uint32_t)+ENCRYPTED_PACKET_GET_ENCRYPTED_KEY_SIZE(packet)+ENCRYPTED_PACKET_GET_IV_SIZE(packet))
#define ENCRYPTED_PACKET_IS_VALID(packet, packet_size)	(sizeof(OtbProtocolCommand)+sizeof(uint32_t)+sizeof(uint32_t)+sizeof(uint32_t)<=(packet_size) && sizeof(OtbProtocolCommand)+sizeof(uint32_t)+sizeof(uint32_t)+sizeof(uint32_t)+ENCRYPTED_PACKET_GET_ENCRYPTED_KEY_SIZE(packet)+ENCRYPTED_PACKET_GET_IV_SIZE(packet)+ENCRYPTED_PACKET_GET_ENCRYPTED_DATA_SIZE(packet)==packet_size)

static uint32_t otb_protocol_create_encrypted_packet(const OtbProtocolContext *context, const unsigned char *plain_packet, uint32_t plain_packet_size, unsigned char **packet_out)
{
	GBytes *encrypted_key=NULL;
	GBytes *iv=NULL;
	unsigned char *encrypted_data=NULL;
	uint32_t encrypted_data_size=otb_asym_cipher_encrypt(context->peer_asym_cipher, plain_packet, plain_packet_size, &encrypted_key, &iv, &encrypted_data);
	uint32_t encrypted_key_size=g_bytes_get_size(encrypted_key);
	uint32_t iv_size=g_bytes_get_size(iv);
	uint32_t packet_out_size=sizeof(OtbProtocolCommand)+sizeof(uint32_t)+sizeof(uint32_t)+sizeof(uint32_t)+encrypted_key_size+iv_size+encrypted_data_size;
	*packet_out=g_malloc(packet_out_size);
	PACKET_COMMAND(*packet_out)=COMMAND_ENCRYPTED;
	ENCRYPTED_PACKET_SET_ENCRYPTED_KEY_SIZE(*packet_out, encrypted_key_size);
	ENCRYPTED_PACKET_SET_IV_SIZE(*packet_out, iv_size);
	ENCRYPTED_PACKET_SET_ENCRYPTED_DATA_SIZE(*packet_out, encrypted_data_size);
	memcpy(ENCRYPTED_PACKET_ENCRYPTED_KEY(*packet_out), g_bytes_get_data(encrypted_key, NULL), encrypted_key_size);
	memcpy(ENCRYPTED_PACKET_IV(*packet_out), g_bytes_get_data(iv, NULL), iv_size);
	memcpy(ENCRYPTED_PACKET_ENCRYPTED_DATA(*packet_out), encrypted_data, encrypted_data_size);
	g_free(encrypted_data);
	g_bytes_unref(encrypted_key);
	g_bytes_unref(iv);
	return packet_out_size;
}

static uint32_t otb_protocol_decrypt_packet(OtbProtocolContext *context, const unsigned char *encrypted_input_packet, uint32_t encrypted_input_packet_size, unsigned char **decrypted_input_packet_out, size_t *decrypted_input_packet_buffer_size_out)
{
	if(PACKET_COMMAND(encrypted_input_packet)==COMMAND_ENCRYPTED && ENCRYPTED_PACKET_IS_VALID(encrypted_input_packet, encrypted_input_packet_size))
	{
		GBytes *encrypted_key_gbytes=g_bytes_new_static(ENCRYPTED_PACKET_ENCRYPTED_KEY(encrypted_input_packet), ENCRYPTED_PACKET_GET_ENCRYPTED_KEY_SIZE(encrypted_input_packet));
		GBytes *iv_gbytes=g_bytes_new_static(ENCRYPTED_PACKET_IV(encrypted_input_packet), ENCRYPTED_PACKET_GET_IV_SIZE(encrypted_input_packet));
		uint32_t decrypted_input_packet_size=otb_asym_cipher_decrypt(context->local_asym_cipher, ENCRYPTED_PACKET_ENCRYPTED_DATA(encrypted_input_packet), ENCRYPTED_PACKET_GET_ENCRYPTED_DATA_SIZE(encrypted_input_packet), encrypted_key_gbytes, iv_gbytes, (void**)decrypted_input_packet_out, decrypted_input_packet_buffer_size_out);
		g_bytes_unref(iv_gbytes);
		g_bytes_unref(encrypted_key_gbytes);
		return decrypted_input_packet_size;
	}
	return otb_protocol_create_error_packet(context, decrypted_input_packet_out);
}

///Protocol packet structure:
///  OtbProtocolCommand - Command
///  unsigned char - Protocol version number
#define PROTOCOL_PACKET_SIZE			(sizeof(OtbProtocolCommand)+sizeof(unsigned char))
#define PROTOCOL_PACKET_VERSION(packet)	((packet)[sizeof(OtbProtocolCommand)])
#define CURRENT_PROTOCOL_VERSION		0

static uint32_t otb_protocol_client_establish_protocol_version(OtbProtocolContext *context, unsigned char **packet_out)
{
	*packet_out=g_malloc(PROTOCOL_PACKET_SIZE);
	PACKET_COMMAND(*packet_out)=COMMAND_PROTOCOL_VERSION;
	PROTOCOL_PACKET_VERSION(*packet_out)=CURRENT_PROTOCOL_VERSION;
	context->state=STATE_ESTABLISHING_PROTOCOL_VERSION;
	return PROTOCOL_PACKET_SIZE;
}

///Establshing friend packet structure:
///  OtbProtocolCommand - Command
///  OtbUniqueId - ID of friend
#define ESTABLISHING_FRIEND_PACKET_SIZE			(sizeof(OtbProtocolCommand)+sizeof(OtbUniqueId))
#define ESTABLISHING_FRIEND_PACKET_ID(packet)	(OtbUniqueId*)((packet)+sizeof(OtbProtocolCommand))

static uint32_t otb_protocol_client_establishing_establish_friend(OtbProtocolContext *context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	if(input_packet_size==sizeof(OtbProtocolCommand) && PACKET_COMMAND(input_packet)==COMMAND_OK)
	{
		*packet_out=g_malloc(ESTABLISHING_FRIEND_PACKET_SIZE);
		PACKET_COMMAND(*packet_out)=COMMAND_SENDING_FRIEND_ID;
		OtbUniqueId *unique_id=NULL;
		g_object_get(context->local_user, OTB_USER_PROP_UNIQUE_ID, &unique_id, NULL);
		memcpy(ESTABLISHING_FRIEND_PACKET_ID(*packet_out), unique_id, sizeof *unique_id);
		g_free(unique_id);
		context->state=STATE_ESTABLISHING_FRIEND;
		return ESTABLISHING_FRIEND_PACKET_SIZE;
	}
	return otb_protocol_create_error_packet(context, packet_out);
}

///Authentication packet structure:
///  OtbProtocolCommand - Command
///  uint32_t - Token length
///  unsigned char* - Token
///Will be wrapped in an encrypted packet.
#define AUTHENTICATION_MESSAGE_PACKET_SET_TOKEN_SIZE(packet, size)	SET_PACKET_UINT32((packet), sizeof(OtbProtocolCommand), (size))
#define AUTHENTICATION_MESSAGE_PACKET_GET_TOKEN_SIZE(packet)		GET_PACKET_UINT32((packet), sizeof(OtbProtocolCommand))
#define AUTHENTICATION_MESSAGE_PACKET_TOKEN(packet)					((packet)+sizeof(OtbProtocolCommand)+sizeof(uint32_t))
#define AUTHENTICATION_MESSAGE_PACKET_IS_VALID(packet, packet_size)	(sizeof(OtbProtocolCommand)+sizeof(uint32_t)<=(packet_size) && sizeof(OtbProtocolCommand)+sizeof(uint32_t)+AUTHENTICATION_MESSAGE_PACKET_GET_TOKEN_SIZE(packet)==(packet_size))

static uint32_t otb_protocol_create_authentication_packet(const OtbProtocolContext *context, unsigned char **packet_out)
{
	uint32_t plain_packet_size=sizeof(OtbProtocolCommand)+sizeof(uint32_t)+AUTHENTICATION_TOKEN_SIZE;
	unsigned char *plain_packet=g_malloc(plain_packet_size);
	PACKET_COMMAND(plain_packet)=COMMAND_SENDING_AUTHENTICATION_TOKEN;
	AUTHENTICATION_MESSAGE_PACKET_SET_TOKEN_SIZE(plain_packet, AUTHENTICATION_TOKEN_SIZE);
	memcpy(AUTHENTICATION_MESSAGE_PACKET_TOKEN(plain_packet), context->authentication_token, AUTHENTICATION_TOKEN_SIZE);
	uint32_t packet_out_size=otb_protocol_create_encrypted_packet(context, (unsigned char*)plain_packet, plain_packet_size, packet_out);
	g_free(plain_packet);
	return packet_out_size;
}

static uint32_t otb_protocol_client_send_authentication_token_to_server(OtbProtocolContext *context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	if(input_packet_size==sizeof(OtbProtocolCommand) && PACKET_COMMAND(input_packet)==COMMAND_OK)
	{
		context->state=STATE_SERVER_AUTHENTICATION;
		return otb_protocol_create_authentication_packet(context, packet_out);
	}
	return otb_protocol_create_error_packet(context, packet_out);
}

#define AUTHENTICATION_MESSAGE_CHECK(context, packet, packet_size)	(AUTHENTICATION_MESSAGE_PACKET_IS_VALID((packet), (packet_size)) && AUTHENTICATION_MESSAGE_PACKET_GET_TOKEN_SIZE(packet)==AUTHENTICATION_TOKEN_SIZE && otb_smemcmp(context->authentication_token, AUTHENTICATION_MESSAGE_PACKET_TOKEN(packet), AUTHENTICATION_TOKEN_SIZE)==0)

static uint32_t otb_protocol_client_validate_server_authentication_token(OtbProtocolContext *context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	unsigned char *decrypted_input_packet=NULL;
	size_t decrypted_input_packet_buffer_size=0;
	uint32_t decrypted_input_packet_size=otb_protocol_decrypt_packet(context, input_packet, input_packet_size, &decrypted_input_packet, &decrypted_input_packet_buffer_size);
	uint32_t packet_out_size;
	if(AUTHENTICATION_MESSAGE_CHECK(context, decrypted_input_packet, decrypted_input_packet_size) && PACKET_COMMAND(decrypted_input_packet)==COMMAND_SENDING_AUTHENTICATION_TOKEN)
	{
		packet_out_size=otb_protocol_create_basic_command_packet(COMMAND_REQUESTING_AUTHENTICATION, packet_out);
		context->state=STATE_CLIENT_REQUESTING_AUTHENTICATION;
	}
	else
		packet_out_size=otb_protocol_create_error_packet(context, packet_out);
	otb_asym_cipher_dispose_decryption_buffer(decrypted_input_packet, decrypted_input_packet_buffer_size);
	return packet_out_size;
}

static uint32_t otb_protocol_echo_authentication_packet(OtbProtocolContext *context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	uint32_t packet_out_size;
	if(AUTHENTICATION_MESSAGE_PACKET_IS_VALID(input_packet, input_packet_size))
		packet_out_size=otb_protocol_create_encrypted_packet(context, input_packet, input_packet_size, packet_out);
	else
		packet_out_size=otb_protocol_create_error_packet(context, packet_out);
	return packet_out_size;
}

static uint32_t otb_protocol_client_authenticate_self(OtbProtocolContext *context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	unsigned char *decrypted_input_packet=NULL;
	size_t decrypted_input_packet_buffer_size=0;
	uint32_t decrypted_input_packet_size=otb_protocol_decrypt_packet(context, input_packet, input_packet_size, &decrypted_input_packet, &decrypted_input_packet_buffer_size);
	uint32_t packet_out_size;
	if(PACKET_COMMAND(decrypted_input_packet)==COMMAND_SENDING_AUTHENTICATION_TOKEN)
	{
		packet_out_size=otb_protocol_echo_authentication_packet(context, decrypted_input_packet, decrypted_input_packet_size, packet_out);
		context->state=STATE_CLIENT_AUTHENTICATION;
	}
	else
		packet_out_size=otb_protocol_create_error_packet(context, packet_out);
	otb_asym_cipher_dispose_decryption_buffer(decrypted_input_packet, decrypted_input_packet_buffer_size);
	return packet_out_size;
}

static uint32_t otb_protocol_client_request_pad_ids_from_server(OtbProtocolContext *context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	uint32_t packet_out_size;
	if(input_packet_size==sizeof(OtbProtocolCommand) && PACKET_COMMAND(input_packet)==COMMAND_OK)
	{
		context->state=STATE_CLIENT_REQUESTING_PAD_IDS_FROM_SERVER;
		packet_out_size=otb_protocol_create_basic_command_packet(COMMAND_REQUESTING_PAD_IDS, packet_out);
	}
	else
		packet_out_size=otb_protocol_create_error_packet(context, packet_out);
	return packet_out_size;
}

///Pad IDs packet structure:
///  OtbProtocolCommand - Command
///  uint32_t - Pad ID count
///  OtbUniqueId[] - Array of unique IDs of pad, repeated based on the pad ID count
#define PAD_IDS_PACKET_SET_PAD_ID_COUNT(packet, count)	SET_PACKET_UINT32((packet), sizeof(OtbProtocolCommand), (count))
#define PAD_IDS_PACKET_GET_PAD_ID_COUNT(packet)			GET_PACKET_UINT32((packet), sizeof(OtbProtocolCommand))
#define PAD_IDS_PACKET_PAD_ID(packet, index)			(OtbUniqueId*)((packet)+sizeof(OtbProtocolCommand)+sizeof(uint32_t)+index*sizeof(OtbUniqueId))
#define PAD_IDS_PACKET_IS_VALID(packet, packet_size)	(sizeof(OtbProtocolCommand)+sizeof(uint32_t)<=(packet_size) && sizeof(OtbProtocolCommand)+sizeof(uint32_t)+PAD_IDS_PACKET_GET_PAD_ID_COUNT(packet)*sizeof(OtbUniqueId)==(packet_size))

static gboolean otb_protocol_delete_missing_pad_ids(const OtbProtocolContext *context, const unsigned char *input_packet, uint32_t input_packet_size, OtbPadRecStatus pad_rec_status)
{
	gboolean ret_val=TRUE;
	if(PACKET_COMMAND(input_packet)==COMMAND_SENDING_PAD_IDS && PAD_IDS_PACKET_IS_VALID(input_packet, input_packet_size))
	{
		GSList *pad_rec_ids=otb_pad_db_get_ids_of_pads_in_status(context->pad_db, pad_rec_status);
		for(const GSList *curr_element=pad_rec_ids; ret_val && curr_element!=NULL; curr_element=(const GSList*)g_slist_next(curr_element))
		{
			const OtbUniqueId *pad_rec_id=(const OtbUniqueId*)curr_element->data;
			gboolean pad_rec_id_found_in_packet=FALSE;
			uint32_t pad_rec_count=PAD_IDS_PACKET_GET_PAD_ID_COUNT(input_packet);
			for(int packet_pad_rec_id_iter=0; !pad_rec_id_found_in_packet && packet_pad_rec_id_iter<pad_rec_count; packet_pad_rec_id_iter++)
				if(otb_unique_id_compare(pad_rec_id, PAD_IDS_PACKET_PAD_ID(input_packet, packet_pad_rec_id_iter))==0)
					pad_rec_id_found_in_packet=TRUE;
			if(!pad_rec_id_found_in_packet)
				ret_val=otb_pad_db_remove_pad(context->pad_db, pad_rec_id);
		}
		g_slist_free_full(pad_rec_ids, g_free);
	}
	else
		ret_val=FALSE;
	return ret_val;
}

static uint32_t otb_protocol_create_pad_ids_packet(const OtbProtocolContext *context, OtbPadRecStatus status1, OtbPadRecStatus status2, unsigned char **encrypted_packet_out)
{
	GSList *pad_rec_ids=otb_pad_db_get_ids_of_pads_in_status(context->pad_db, status1);
	if(status2!=OTB_PAD_REC_STATUS_OUT_OF_BOUNDS)
		pad_rec_ids=g_slist_concat(pad_rec_ids, otb_pad_db_get_ids_of_pads_in_status(context->pad_db, status2));
	uint32_t total_pad_rec_ids=g_slist_length(pad_rec_ids);
	unsigned char *plain_packet=NULL;
	uint32_t plain_packet_size=sizeof(OtbProtocolCommand)+sizeof(uint32_t)+sizeof(OtbUniqueId)*total_pad_rec_ids;
	plain_packet=g_malloc(plain_packet_size);
	PACKET_COMMAND(plain_packet)=COMMAND_SENDING_PAD_IDS;
	PAD_IDS_PACKET_SET_PAD_ID_COUNT(plain_packet, total_pad_rec_ids);
	for(uint32_t unique_id_iter=0; unique_id_iter<total_pad_rec_ids; unique_id_iter++)
		memcpy(PAD_IDS_PACKET_PAD_ID(plain_packet, unique_id_iter), g_slist_nth(pad_rec_ids, unique_id_iter)->data, sizeof(OtbUniqueId));
	g_slist_free_full(pad_rec_ids, g_free);
	uint32_t encrypted_packet_out_size=otb_protocol_create_encrypted_packet(context, (unsigned char*)plain_packet, plain_packet_size, encrypted_packet_out);
	g_free(plain_packet);
	return encrypted_packet_out_size;
}

static uint32_t otb_protocol_client_send_pad_ids_to_server(OtbProtocolContext *context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	unsigned char *decrypted_input_packet=NULL;
	size_t decrypted_input_packet_buffer_size=0;
	uint32_t decrypted_input_packet_size=otb_protocol_decrypt_packet(context, input_packet, input_packet_size, &decrypted_input_packet, &decrypted_input_packet_buffer_size);
	uint32_t packet_out_size;
	if(otb_protocol_delete_missing_pad_ids(context, decrypted_input_packet, decrypted_input_packet_size, OTB_PAD_REC_STATUS_SENT) && otb_protocol_delete_missing_pad_ids(context, decrypted_input_packet, decrypted_input_packet_size, OTB_PAD_REC_STATUS_CONSUMED))
	{
		packet_out_size=otb_protocol_create_pad_ids_packet(context, OTB_PAD_REC_STATUS_SENT, OTB_PAD_REC_STATUS_CONSUMED, packet_out);
		context->state=STATE_CLIENT_SENDING_PAD_IDS_TO_SERVER;
	}
	else
		packet_out_size=otb_protocol_create_error_packet(context, packet_out);
	otb_asym_cipher_dispose_decryption_buffer(decrypted_input_packet, decrypted_input_packet_buffer_size);
	return packet_out_size;
}

///New incoming pad packet structure:
///  OtbProtocolCommand - Command
///  OtbUniqueId pad_id
///  int64_t - pad_size
///Will be wrapped in an encrypted packet.
#define INCOMING_PAD_HEADER_PACKET_SIZE								(sizeof(OtbProtocolCommand)+sizeof(OtbUniqueId)+sizeof(int64_t))
#define INCOMING_PAD_HEADER_PACKET_PAD_ID(packet)					(OtbUniqueId*)((packet)+sizeof(OtbProtocolCommand))
#define INCOMING_PAD_HEADER_PACKET_SET_PAD_SIZE(packet, size)		SET_PACKET_INT64((packet), sizeof(OtbProtocolCommand)+sizeof(OtbUniqueId), (size))
#define INCOMING_PAD_HEADER_PACKET_GET_PAD_SIZE(packet)				GET_PACKET_INT64((packet), sizeof(OtbProtocolCommand)+sizeof(OtbUniqueId))
#define INCOMING_PAD_HEADER_PACKET_IS_VALID(packet, packet_size)	(INCOMING_PAD_HEADER_PACKET_SIZE==(packet_size))

static uint32_t otb_protocol_client_send_pad_header_to_server(OtbProtocolContext *context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	uint32_t packet_out_size;
	if(input_packet_size==sizeof(OtbProtocolCommand) && PACKET_COMMAND(input_packet)==COMMAND_OK)
	{
		g_free(context->pad_id);
		context->pad_id=otb_pad_db_fetch_random_rec_id(context->pad_db, OTB_PAD_REC_STATUS_UNSENT);
		if(context->pad_id!=NULL)
		{
			context->pad_io=otb_pad_db_open_pad_for_read(context->pad_db, context->pad_id);
			if(context->pad_io!=NULL)
			{
				unsigned char *plain_packet=g_malloc(INCOMING_PAD_HEADER_PACKET_SIZE);
				PACKET_COMMAND(plain_packet)=COMMAND_SENDING_PAD_HEADER;
				memcpy(INCOMING_PAD_HEADER_PACKET_PAD_ID(*packet_out), context->pad_id, sizeof *context->pad_id);
				INCOMING_PAD_HEADER_PACKET_SET_PAD_SIZE(plain_packet, otb_pad_db_get_pad_size(context->pad_db, context->pad_id));
				packet_out_size=otb_protocol_create_encrypted_packet(context, (unsigned char*)plain_packet, INCOMING_PAD_HEADER_PACKET_SIZE, packet_out);
				g_free(plain_packet);
				context->state=STATE_CLIENT_SENDING_PAD_HEADER_TO_SERVER;
			}
			else
				packet_out_size=otb_protocol_create_error_packet(context, packet_out);
		}
		else
		{
			packet_out_size=otb_protocol_create_basic_command_packet(COMMAND_FINISH, packet_out);
			context->state=STATE_FINISHED;
		}
	}
	else
		packet_out_size=otb_protocol_create_error_packet(context, packet_out);
	return packet_out_size;
}

#define INCOMING_PAD_PACKET_SET_PAD_CHUNK_SIZE(packet, size)	SET_PACKET_UINT32((packet), sizeof(OtbProtocolCommand), (size))
#define INCOMING_PAD_PACKET_GET_PAD_CHUNK_SIZE(packet)			GET_PACKET_UINT32((packet), sizeof(OtbProtocolCommand))
#define INCOMING_PAD_PACKET_IS_VALID(packet, packet_size)		(sizeof(OtbProtocolCommand)+sizeof(uint32_t)<=(packet_size) && sizeof(OtbProtocolCommand)+INCOMING_PAD_PACKET_GET_PAD_CHUNK_SIZE(packet)==(packet_size))

static uint32_t otb_protocol_client_send_pad_chunk_to_server(OtbProtocolContext *context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out);

static uint32_t otb_protocol_client_attempt_to_send_first_pad_chunk_to_server(OtbProtocolContext *context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	uint32_t packet_out_size;
	if(input_packet_size==sizeof(OtbProtocolCommand) && PACKET_COMMAND(input_packet)==COMMAND_UNABLE)
	{
		packet_out_size=0;
		*packet_out=NULL;
		context->state=STATE_FINISHED;
	}
	else
		packet_out_size=otb_protocol_client_send_pad_chunk_to_server(context, input_packet, input_packet_size, packet_out);
	return packet_out_size;
}

static size_t otb_protocol_get_chunk_size()
{
	size_t chunk_size=otb_settings_get_config_uint(CONFIG_GROUP, CONFIG_CHUNK_SIZE, 0);
	if(chunk_size==0)
	{
		chunk_size=CONFIG_DEFAULT_CHUNK_SIZE;
		otb_settings_set_config_uint(CONFIG_GROUP, CONFIG_CHUNK_SIZE, chunk_size);
	}
	return chunk_size;
}

static uint32_t otb_protocol_client_send_pad_chunk_to_server(OtbProtocolContext *context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	uint32_t packet_out_size;
	gboolean error=FALSE;
	if(input_packet_size==sizeof(OtbProtocolCommand) && PACKET_COMMAND(input_packet)==COMMAND_OK)
	{
		size_t buffer_size=otb_protocol_get_chunk_size();
		uint32_t plain_packet_size=sizeof(OtbProtocolCommand)+sizeof(uint32_t)+buffer_size;
		unsigned char *plain_packet=g_malloc(plain_packet_size);
		uint32_t byte_iter;
		char *curr_byte;
		for(byte_iter=0, curr_byte=plain_packet+sizeof(OtbProtocolCommand)+sizeof(uint32_t); otb_pad_has_more_bytes(context->pad_io) && byte_iter<buffer_size && !error; byte_iter++, curr_byte++)
		{
			if(!otb_pad_read_byte(context->pad_io, curr_byte))
			{
				otb_smemset(plain_packet, 0, plain_packet_size);
				g_free(plain_packet);
				packet_out_size=otb_protocol_create_error_packet(context, packet_out);
				error=TRUE;
			}
		}
		if(!error)
		{
			if(otb_pad_has_more_bytes(context->pad_io))
			{
				PACKET_COMMAND(plain_packet)=COMMAND_SENDING_PAD_CHUNK;
				context->state=STATE_CLIENT_SENDING_FINAL_PAD_CHUNK_TO_SERVER;
			}
			else
			{
				PACKET_COMMAND(plain_packet)=COMMAND_SENDING_FINAL_PAD_CHUNK;
				context->state=STATE_CLIENT_SENDING_FINAL_PAD_CHUNK_TO_SERVER;
			}
			INCOMING_PAD_PACKET_SET_PAD_CHUNK_SIZE(plain_packet, byte_iter);
			packet_out_size=otb_protocol_create_encrypted_packet(context, plain_packet, plain_packet_size, packet_out);
		}
	}
	else
		packet_out_size=otb_protocol_create_error_packet(context, packet_out);
	return packet_out_size;
}

static uint32_t otb_protocol_client_wrap_up_sending_pad(OtbProtocolContext *context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	uint32_t packet_out_size;
	if(input_packet_size==sizeof(OtbProtocolCommand) && PACKET_COMMAND(input_packet)==COMMAND_OK)
	{
		otb_pad_db_mark_pad_as_sent(context->pad_db, context->pad_id);
		g_free(context->pad_id);
		return otb_protocol_client_send_pad_header_to_server(context, input_packet, input_packet_size, packet_out);
	}
	else
		packet_out_size=otb_protocol_create_error_packet(context, packet_out);
	return packet_out_size;
}

uint32_t otb_protocol_client(OtbProtocolContext *context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	if(input_packet_size<sizeof(OtbProtocolCommand) && context->state!=STATE_INITIAL)
		return otb_protocol_create_error_packet(context, packet_out);
	if(PACKET_COMMAND(input_packet)==COMMAND_ERROR)
	{
		context->state=STATE_FINISHED;
		return 0;
	}
	switch(context->state)
	{
		case STATE_INITIAL:
			return otb_protocol_client_establish_protocol_version(context, packet_out);
		case STATE_ESTABLISHING_PROTOCOL_VERSION:
			return otb_protocol_client_establishing_establish_friend(context, input_packet, input_packet_size, packet_out);
		case STATE_ESTABLISHING_FRIEND:
			return otb_protocol_client_send_authentication_token_to_server(context, input_packet, input_packet_size, packet_out);
		case STATE_SERVER_AUTHENTICATION:
			return otb_protocol_client_validate_server_authentication_token(context, input_packet, input_packet_size, packet_out);
		case STATE_CLIENT_REQUESTING_AUTHENTICATION:
			return otb_protocol_client_authenticate_self(context, input_packet, input_packet_size, packet_out);
		case STATE_CLIENT_AUTHENTICATION:
			return otb_protocol_client_request_pad_ids_from_server(context, input_packet, input_packet_size, packet_out);
		case STATE_CLIENT_REQUESTING_PAD_IDS_FROM_SERVER:
			return otb_protocol_client_send_pad_ids_to_server(context, input_packet, input_packet_size, packet_out);
		case STATE_CLIENT_SENDING_PAD_IDS_TO_SERVER:
			return otb_protocol_client_send_pad_header_to_server(context, input_packet, input_packet_size, packet_out);
		case STATE_CLIENT_SENDING_PAD_HEADER_TO_SERVER:
			return otb_protocol_client_attempt_to_send_first_pad_chunk_to_server(context, input_packet, input_packet_size, packet_out);
		case STATE_CLIENT_SENDING_PAD_CHUNK_TO_SERVER:
			return otb_protocol_client_send_pad_chunk_to_server(context, input_packet, input_packet_size, packet_out);
		case STATE_CLIENT_SENDING_FINAL_PAD_CHUNK_TO_SERVER:
			otb_protocol_client_wrap_up_sending_pad(context, input_packet, input_packet_size, packet_out);
		default:
			return otb_protocol_create_error_packet(context, packet_out);
	}
}

static uint32_t otb_protocol_server_establish_protocol_version(OtbProtocolContext *context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	uint32_t packet_out_size;
	if(input_packet_size==PROTOCOL_PACKET_SIZE && PACKET_COMMAND(input_packet)==COMMAND_PROTOCOL_VERSION && PROTOCOL_PACKET_VERSION(input_packet)==CURRENT_PROTOCOL_VERSION)
	{
		context->state=STATE_ESTABLISHING_PROTOCOL_VERSION;
		packet_out_size=otb_protocol_create_ok_packet(packet_out);
	}
	else
		packet_out_size=otb_protocol_create_error_packet(context, packet_out);
	return packet_out_size;
}

static uint32_t otb_protocol_server_establish_friend(OtbProtocolContext *context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	uint32_t packet_out_size;
	if(input_packet_size==ESTABLISHING_FRIEND_PACKET_SIZE && PACKET_COMMAND(input_packet)==COMMAND_SENDING_FRIEND_ID)
	{
		OtbFriend *peer_friend=otb_bitkeeper_get_friend(context->bitkeeper, ESTABLISHING_FRIEND_PACKET_ID(input_packet));
		if(peer_friend==NULL)
			packet_out_size=otb_protocol_create_error_packet(context, packet_out);
		else
		{
			otb_protocol_set_peer_friend_on_context(context, peer_friend);
			g_object_get(peer_friend, OTB_FRIEND_PROP_INCOMING_PADS, &context->pad_db, NULL);
			context->state=STATE_ESTABLISHING_FRIEND;
			packet_out_size=otb_protocol_create_ok_packet(packet_out);
		}
	}
	else
		packet_out_size=otb_protocol_create_error_packet(context, packet_out);
	return packet_out_size;
}

static uint32_t otb_protocol_server_authenticate_self(OtbProtocolContext *context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	unsigned char *decrypted_input_packet=NULL;
	size_t decrypted_input_packet_buffer_size=0;
	uint32_t decrypted_input_packet_size=otb_protocol_decrypt_packet(context, input_packet, input_packet_size, &decrypted_input_packet, &decrypted_input_packet_buffer_size);
	uint32_t packet_out_size;
	if(PACKET_COMMAND(input_packet)==COMMAND_SENDING_AUTHENTICATION_TOKEN)
	{
		packet_out_size=otb_protocol_echo_authentication_packet(context, decrypted_input_packet, decrypted_input_packet_size, packet_out);
		context->state=STATE_SERVER_AUTHENTICATION;
	}
	else
		packet_out_size=otb_protocol_create_error_packet(context, packet_out);
	otb_asym_cipher_dispose_decryption_buffer(decrypted_input_packet, decrypted_input_packet_buffer_size);
	return packet_out_size;
}

static uint32_t otb_protocol_server_send_authentication_token_to_client(OtbProtocolContext *context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	uint32_t packet_out_size;
	if(input_packet_size==sizeof(OtbProtocolCommand) && PACKET_COMMAND(input_packet)==COMMAND_REQUESTING_AUTHENTICATION)
	{
		context->state=STATE_CLIENT_REQUESTING_AUTHENTICATION;
		packet_out_size=otb_protocol_create_authentication_packet(context, packet_out);
	}
	else
		packet_out_size=otb_protocol_create_error_packet(context, packet_out);
	return packet_out_size;
}

static uint32_t otb_protocol_server_state_validate_client_authentication_token(OtbProtocolContext *context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	unsigned char *decrypted_input_packet=NULL;
	size_t decrypted_input_packet_buffer_size=0;
	uint32_t decrypted_input_packet_size=otb_protocol_decrypt_packet(context, input_packet, input_packet_size, &decrypted_input_packet, &decrypted_input_packet_buffer_size);
	uint32_t packet_out_size;
	if(PACKET_COMMAND(decrypted_input_packet)==COMMAND_SENDING_AUTHENTICATION_TOKEN && AUTHENTICATION_MESSAGE_CHECK(context, decrypted_input_packet, decrypted_input_packet_size))
	{
		packet_out_size=otb_protocol_create_ok_packet(packet_out);
		context->state=STATE_CLIENT_AUTHENTICATION;
	}
	else
		packet_out_size=otb_protocol_create_error_packet(context, packet_out);
	otb_asym_cipher_dispose_decryption_buffer(decrypted_input_packet, decrypted_input_packet_buffer_size);
	return packet_out_size;
}

static uint32_t otb_protocol_server_send_pad_ids_to_client(OtbProtocolContext *context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	uint32_t packet_out_size;
	if(input_packet_size==sizeof(OtbProtocolCommand) && PACKET_COMMAND(input_packet)==COMMAND_REQUESTING_PAD_IDS)
	{
		packet_out_size=otb_protocol_create_pad_ids_packet(context, OTB_PAD_REC_STATUS_RECEIVED, OTB_PAD_REC_STATUS_OUT_OF_BOUNDS, packet_out);
		context->state=STATE_CLIENT_REQUESTING_PAD_IDS_FROM_SERVER;
	}
	else
		packet_out_size=otb_protocol_create_error_packet(context, packet_out);
	return packet_out_size;
}

static uint32_t otb_protocol_server_receive_pad_ids_from_client(OtbProtocolContext *context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	unsigned char *decrypted_input_packet=NULL;
	size_t decrypted_input_packet_buffer_size=0;
	uint32_t decrypted_input_packet_size=otb_protocol_decrypt_packet(context, input_packet, input_packet_size, &decrypted_input_packet, &decrypted_input_packet_buffer_size);
	uint32_t packet_out_size;
	if(otb_protocol_delete_missing_pad_ids(context, decrypted_input_packet, decrypted_input_packet_size, OTB_PAD_REC_STATUS_RECEIVED))
	{
		packet_out_size=otb_protocol_create_ok_packet(packet_out);
		context->state=STATE_CLIENT_SENDING_PAD_IDS_TO_SERVER;
	}
	else
		packet_out_size=otb_protocol_create_error_packet(context, packet_out);
	otb_asym_cipher_dispose_decryption_buffer(decrypted_input_packet, decrypted_input_packet_buffer_size);
	return packet_out_size;
}

enum
{
	ADD_NEW_PAD_ID_SUCCESS,
	ADD_NEW_PAD_ID_UNABLE,
	ADD_NEW_PAD_ID_ERROR
};

static int otb_protocol_add_new_pad_id(OtbProtocolContext *context, const unsigned char *input_packet, uint32_t input_packet_size)
{
	int add_new_pad_status;
	if(!INCOMING_PAD_HEADER_PACKET_IS_VALID(input_packet, input_packet_size))
		add_new_pad_status=ADD_NEW_PAD_ID_ERROR;
	else
	{
		g_free(context->pad_id);
		context->pad_id=otb_unique_id_duplicate(INCOMING_PAD_HEADER_PACKET_PAD_ID(input_packet));
		context->pad_bytes_received=0;
		context->pad_size=INCOMING_PAD_HEADER_PACKET_GET_PAD_SIZE(input_packet);
		context->pad_io=otb_pad_db_add_incoming_pad(context->pad_db, context->pad_id, context->pad_size);
		if(context->pad_io==NULL)
			add_new_pad_status=ADD_NEW_PAD_ID_UNABLE;
		else
			add_new_pad_status=ADD_NEW_PAD_ID_SUCCESS;
	}
	return add_new_pad_status;
}

static uint32_t otb_protocol_server_receive_pad_header_from_client(OtbProtocolContext *context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	unsigned char *decrypted_input_packet=NULL;
	size_t decrypted_input_packet_buffer_size=0;
	uint32_t decrypted_input_packet_size=otb_protocol_decrypt_packet(context, input_packet, input_packet_size, &decrypted_input_packet, &decrypted_input_packet_buffer_size);
	uint32_t packet_out_size;
	int add_new_pad_id_status=otb_protocol_add_new_pad_id(context, decrypted_input_packet, decrypted_input_packet_size);
	switch(add_new_pad_id_status)
	{
		case ADD_NEW_PAD_ID_SUCCESS:
			packet_out_size=otb_protocol_create_ok_packet(packet_out);
			context->state=STATE_CLIENT_SENDING_PAD_HEADER_TO_SERVER;
			break;
		case ADD_NEW_PAD_ID_UNABLE:
			packet_out_size=otb_protocol_create_basic_command_packet(COMMAND_UNABLE, packet_out);
			context->state=STATE_CLIENT_SENDING_PAD_HEADER_TO_SERVER;
			break;
		default:
			packet_out_size=otb_protocol_create_error_packet(context, packet_out);
	}
	otb_asym_cipher_dispose_decryption_buffer(decrypted_input_packet, decrypted_input_packet_buffer_size);
	return packet_out_size;
}

static uint32_t otb_protocol_server_receive_pad_chunk_from_client(OtbProtocolContext *context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out);

static uint32_t otb_protocol_server_receive_first_pad_chunk_from_client(OtbProtocolContext *context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	uint32_t packet_out_size;
	if(PACKET_COMMAND(input_packet)==STATE_FINISHED)
	{
		packet_out_size=0;
		*packet_out=NULL;
		context->state=STATE_FINISHED;
	}
	else
		otb_protocol_server_receive_pad_chunk_from_client(context, input_packet, input_packet_size, packet_out);
	return packet_out_size;
}

static uint32_t otb_protocol_server_receive_pad_chunk_from_client(OtbProtocolContext *context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	uint32_t packet_out_size;
	unsigned char *decrypted_input_packet=NULL;
	size_t decrypted_input_packet_buffer_size=0;
	uint32_t decrypted_input_packet_size=otb_protocol_decrypt_packet(context, input_packet, input_packet_size, &decrypted_input_packet, &decrypted_input_packet_buffer_size);
	if(INCOMING_PAD_PACKET_IS_VALID(decrypted_input_packet, decrypted_input_packet_size) && PACKET_COMMAND(decrypted_input_packet)==STATE_CLIENT_SENDING_PAD_CHUNK_TO_SERVER || PACKET_COMMAND(decrypted_input_packet)==STATE_CLIENT_SENDING_FINAL_PAD_CHUNK_TO_SERVER)
	{
		packet_out_size=otb_protocol_create_ok_packet(packet_out);
		context->state=(PACKET_COMMAND(decrypted_input_packet)==STATE_CLIENT_SENDING_FINAL_PAD_CHUNK_TO_SERVER?STATE_CLIENT_SENDING_FINAL_PAD_CHUNK_TO_SERVER:STATE_CLIENT_SENDING_PAD_CHUNK_TO_SERVER);
	}
	otb_asym_cipher_dispose_decryption_buffer(decrypted_input_packet, decrypted_input_packet_buffer_size);
	return packet_out_size;
}

uint32_t otb_protocol_server(OtbProtocolContext *context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	if(input_packet_size>0 || PACKET_COMMAND(input_packet)==COMMAND_ERROR)
	{
		context->state=STATE_FINISHED;
		return 0;
	}
	switch(context->state)
	{
		case STATE_INITIAL:
			return otb_protocol_server_establish_protocol_version(context, input_packet, input_packet_size, packet_out);
		case STATE_ESTABLISHING_PROTOCOL_VERSION:
			return otb_protocol_server_establish_friend(context, input_packet, input_packet_size, packet_out);
		case STATE_ESTABLISHING_FRIEND:
			return otb_protocol_server_authenticate_self(context, input_packet, input_packet_size, packet_out);
		case STATE_SERVER_AUTHENTICATION:
			return otb_protocol_server_send_authentication_token_to_client(context, input_packet, input_packet_size, packet_out);
		case STATE_CLIENT_REQUESTING_AUTHENTICATION:
			return otb_protocol_server_state_validate_client_authentication_token(context, input_packet, input_packet_size, packet_out);
		case STATE_CLIENT_AUTHENTICATION:
			return otb_protocol_server_send_pad_ids_to_client(context, input_packet, input_packet_size, packet_out);
		case STATE_CLIENT_REQUESTING_PAD_IDS_FROM_SERVER:
			return otb_protocol_server_receive_pad_ids_from_client(context, input_packet, input_packet_size, packet_out);
		case STATE_CLIENT_SENDING_PAD_IDS_TO_SERVER:
		case STATE_CLIENT_SENDING_FINAL_PAD_CHUNK_TO_SERVER:
			return otb_protocol_server_receive_pad_header_from_client(context, input_packet, input_packet_size, packet_out);
		case STATE_CLIENT_SENDING_PAD_HEADER_TO_SERVER:
			return otb_protocol_server_receive_first_pad_chunk_from_client(context, input_packet, input_packet_size, packet_out);
		case STATE_CLIENT_SENDING_PAD_CHUNK_TO_SERVER:
			return otb_protocol_server_receive_pad_chunk_from_client(context, input_packet, input_packet_size, packet_out);
		default:
			return otb_protocol_create_error_packet(context, packet_out);
	}
}

void otb_protocol_context_free(OtbProtocolContext *context)
{
	g_free(context->authentication_token);
	g_object_unref(context->bitkeeper);
	g_object_unref(context->local_user);
	g_object_unref(context->local_asym_cipher);
	if(context->peer_friend!=NULL)
		g_object_unref(context->peer_friend);
	if(context->peer_asym_cipher!=NULL)
		g_object_unref(context->peer_asym_cipher);
	g_free(context->pad_id);
	if(context->pad_io!=NULL)
		otb_pad_db_close_pad(context->pad_db);
	g_free(context);
}
