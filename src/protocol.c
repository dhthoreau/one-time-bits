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

STATE_CLIENT_AUTHENTICATION -> COMMAND_OK -> COMMAND_REQUESTING_PAD_UNIQUE_IDS -> STATE_CLIENT_REQUESTING_PAD_UNIQUE_IDS_FROM_SERVER

STATE_CLIENT_REQUESTING_PAD_UNIQUE_IDS_FROM_SERVER -> {COMMAND_SENDING_PAD_UNIQUE_IDS} -> {COMMAND_SENDING_PAD_UNIQUE_IDS} -> STATE_CLIENT_SENDING_PAD_UNIQUE_IDS_TO_SERVER

STATE_CLIENT_SENDING_PAD_UNIQUE_IDS_TO_SERVER -> COMMAND_OK -> {COMMAND_SENDING_PAD_HEADER} -> STATE_CLIENT_SENDING_PAD_HEADER_TO_SERVER
                                                        COMMAND_FINISH -> STATE_FINISHED

STATE_CLIENT_SENDING_PAD_HEADER_TO_SERVER -> COMMAND_UNABLE -> <null> -> STATE_FINISHED
                                             COMMAND_OK -> {COMMAND_SENDING_PAD_CHUNK} -> STATE_CLIENT_SENDING_PAD_CHUNK_TO_SERVER
                                                           {COMMAND_SENDING_FINAL_PAD_CHUNK} -> STATE_CLIENT_SENDING_FINAL_PAD_CHUNK_TO_SERVER

STATE_CLIENT_SENDING_PAD_CHUNK_TO_SERVER -> COMMAND_OK -> {COMMAND_SENDING_PAD_CHUNK} -> STATE_CLIENT_SENDING_PAD_CHUNK_TO_SERVER
                                                          {COMMAND_SENDING_FINAL_PAD_CHUNK} -> STATE_CLIENT_SENDING_FINAL_PAD_CHUNK_TO_SERVER

STATE_CLIENT_SENDING_FINAL_PAD_CHUNK_TO_SERVER -> COMMAND_OK -> {COMMAND_SENDING_PAD_HEADER} -> STATE_CLIENT_SENDING_PAD_HEADER_TO_SERVER
                                                                COMMAND_FINISH -> STATE_FINISHED


+++ Summary of Server State Transitions +++

Format: Current server state -> Incoming command from client -> Outgoing command to server -> Next state of server
Encrypted commands are in {brackets}.

STATE_INITIAL -> COMMAND_PROTOCOL_VERSION -> COMMAND_OK -> STATE_ESTABLISHING_PROTOCOL_VERSION

STATE_ESTABLISHING_PROTOCOL_VERSION -> COMMAND_SENDING_FRIEND_ID -> COMMAND_OK -> STATE_ESTABLISHING_FRIEND

STATE_ESTABLISHING_FRIEND -> {COMMAND_SENDING_AUTHENTICATION_TOKEN} -> {COMMAND_SENDING_AUTHENTICATION_TOKEN} -> STATE_SERVER_AUTHENTICATION

STATE_SERVER_AUTHENTICATION -> COMMAND_REQUESTING_AUTHENTICATION -> {COMMAND_SENDING_AUTHENTICATION_TOKEN} -> STATE_CLIENT_REQUESTING_AUTHENTICATION

STATE_CLIENT_REQUESTING_AUTHENTICATION ->  {COMMAND_SENDING_AUTHENTICATION_TOKEN}-> COMMAND_OK -> STATE_CLIENT_AUTHENTICATION

STATE_CLIENT_AUTHENTICATION -> COMMAND_REQUESTING_PAD_UNIQUE_IDS -> {COMMAND_SENDING_PAD_UNIQUE_IDS} -> STATE_CLIENT_REQUESTING_PAD_UNIQUE_IDS_FROM_SERVER

STATE_CLIENT_REQUESTING_PAD_UNIQUE_IDS_FROM_SERVER -> {COMMAND_SENDING_PAD_UNIQUE_IDS} -> COMMAND_OK -> STATE_CLIENT_SENDING_PAD_UNIQUE_IDS_TO_SERVER

STATE_CLIENT_SENDING_PAD_UNIQUE_IDS_TO_SERVER -> COMMAND_FINISH -> <null> -> STATE_FINISHED
                                          {COMMAND_SENDING_PAD_HEADER} -> COMMAND_UNABLE -> STATE_FINISHED
                                                                          COMMAND_OK -> STATE_CLIENT_SENDING_PAD_HEADER_TO_SERVER

STATE_CLIENT_SENDING_PAD_HEADER_TO_SERVER -> {COMMAND_SENDING_PAD_CHUNK} -> COMMAND_OK -> STATE_CLIENT_SENDING_PAD_CHUNK_TO_SERVER
                                             {COMMAND_SENDING_FINAL_PAD_CHUNK} -> COMMAND_OK -> STATE_CLIENT_SENDING_FINAL_PAD_CHUNK_TO_SERVER

STATE_CLIENT_SENDING_PAD_CHUNK_TO_SERVER -> {COMMAND_SENDING_PAD_CHUNK} -> COMMAND_OK -> STATE_CLIENT_SENDING_PAD_CHUNK_TO_SERVER
                                            {COMMAND_SENDING_FINAL_PAD_CHUNK} -> COMMAND_OK -> STATE_CLIENT_SENDING_FINAL_PAD_CHUNK_TO_SERVER

STATE_CLIENT_SENDING_FINAL_PAD_CHUNK_TO_SERVER -> COMMAND_FINISH -> <null> -> STATE_FINISHED
                                                  {COMMAND_SENDING_PAD_HEADER} -> COMMAND_UNABLE -> STATE_FINISHED
                                                                                  COMMAND_OK -> STATE_CLIENT_SENDING_PAD_HEADER_TO_SERVER
*/

#include "../config.h"

#include <endian.h>
#include <glib.h>
#include <string.h>

#include "memory.h"
#include "pad-db.h"
#include "pad-rec.h"
#include "protocol.h"
#include "random.h"
#include "settings.h"

#define CONFIG_GROUP				"protocol"
#define CONFIG_CHUNK_SIZE			"chunk-size"
#define CONFIG_DEFAULT_CHUNK_SIZE	10240

#define AUTHENTICATION_TOKEN_SIZE	4096

typedef unsigned char OtbProtocolState;
typedef unsigned char OtbProtocolCommand;

struct _OtbProtocolContext
{
	OtbProtocolState state;
	unsigned char *authentication_token;
	OtbBitkeeper *bitkeeper;
	OtbUser *local_user;
	OtbAsymCipher *local_asym_cipher;
	OtbFriend *peer_friend;
	OtbAsymCipher *peer_asym_cipher;
	OtbPadDb *pad_db;
	off_t pad_size;
	off_t pad_bytes_transferred;
	OtbUniqueId *pad_unique_id;
	OtbPadIO *pad_io;
};

enum
{
	COMMAND_PROTOCOL_VERSION,
	COMMAND_ERROR,
	COMMAND_OK,
	COMMAND_ENCRYPTED,
	COMMAND_SENDING_FRIEND_ID,
	COMMAND_REQUESTING_AUTHENTICATION,
	COMMAND_SENDING_AUTHENTICATION_TOKEN,
	COMMAND_REQUESTING_PAD_UNIQUE_IDS,
	COMMAND_SENDING_PAD_UNIQUE_IDS,
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
	STATE_CLIENT_REQUESTING_PAD_UNIQUE_IDS_FROM_SERVER,
	STATE_CLIENT_SENDING_PAD_UNIQUE_IDS_TO_SERVER,
	STATE_CLIENT_SENDING_PAD_HEADER_TO_SERVER,
	STATE_CLIENT_SENDING_PAD_CHUNK_TO_SERVER,
	STATE_CLIENT_SENDING_FINAL_PAD_CHUNK_TO_SERVER,
	STATE_FINISHED
};

static void otb_protocol_set_peer_friend_on_context(OtbProtocolContext *protocol_context, OtbFriend *peer_friend)
{
	g_object_ref(peer_friend);
	protocol_context->peer_friend=peer_friend;
	char *peer_public_key=NULL;
	char *peer_transport_cipher_name=NULL;
	g_object_get(peer_friend, OTB_FRIEND_PROP_PUBLIC_KEY, &peer_public_key, OTB_FRIEND_PROP_TRANSPORT_CIPHER_NAME, &peer_transport_cipher_name, OTB_FRIEND_PROP_OUTGOING_PAD_DB, &protocol_context->pad_db, NULL);
	protocol_context->peer_asym_cipher=g_object_new(OTB_TYPE_ASYM_CIPHER, OTB_ASYM_CIPHER_PROP_PUBLIC_KEY, peer_public_key, OTB_ASYM_CIPHER_PROP_SYM_CIPHER_NAME, peer_transport_cipher_name, NULL);
	g_free(peer_transport_cipher_name);
	g_free(peer_public_key);
}

OtbProtocolContext *otb_protocol_context_create_client(OtbBitkeeper *bitkeeper, OtbFriend *peer_friend)
{
	OtbProtocolContext *protocol_context=g_malloc(sizeof *protocol_context);
	protocol_context->authentication_token=otb_create_random_bytes(AUTHENTICATION_TOKEN_SIZE);
	g_object_ref(bitkeeper);
	protocol_context->bitkeeper=bitkeeper;
	g_object_get(bitkeeper, OTB_BITKEEPER_PROP_USER, &protocol_context->local_user, NULL);
	g_object_get(protocol_context->local_user, OTB_USER_PROP_ASYM_CIPHER, &protocol_context->local_asym_cipher, NULL);
	if(peer_friend!=NULL)
		otb_protocol_set_peer_friend_on_context(protocol_context, peer_friend);
	else
	{
		protocol_context->peer_friend=NULL;
		protocol_context->peer_asym_cipher=NULL;
		protocol_context->pad_db=NULL;
	}
	protocol_context->pad_unique_id=NULL;
	protocol_context->pad_io=NULL;
	protocol_context->state=STATE_INITIAL;
	return protocol_context;
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

static uint32_t otb_protocol_create_error_packet(OtbProtocolContext *protocol_context, unsigned char **packet_out)
{
	protocol_context->state=STATE_FINISHED;
	return otb_protocol_create_basic_command_packet(COMMAND_ERROR, packet_out);
}

///Encrypted packet structure:
///  OtbProtocolCommand - Command
///  uint32_t - Encrypted key size
///  uint32_t - IV size
///  uint32_t - Encryted data size
///  unsigned char* - Encrypted key
///  unsigned char* - IV
///  unsigned char* - Encrypted data
#define PACKET_NUMBER(packet, position, type)				(*((type*)((packet)+(position))))

#define SET_PACKET_NUMBER32(packet, position, type, value)	(PACKET_NUMBER((packet), (position), type)=g_htonl(value))
#define GET_PACKET_NUMBER32(packet, position, type)			(g_ntohl(PACKET_NUMBER((packet), (position), type)))

#define SET_PACKET_NUMBER64(packet, position, type, value)	(PACKET_NUMBER((packet), (position), type)=GINT64_TO_BE(value))
#define GET_PACKET_NUMBER64(packet, position, type)			(GINT64_FROM_BE(PACKET_NUMBER((packet), (position), type)))

#define SET_PACKET_UINT32(packet, position, value)			(SET_PACKET_NUMBER32((packet), (position), uint32_t, (value)))
#define GET_PACKET_UINT32(packet, position)					(GET_PACKET_NUMBER32((packet), (position), uint32_t))
#define SET_PACKET_INT32(packet, position, value)			(SET_PACKET_NUMBER32((packet), (position), int32_t, (value)))
#define GET_PACKET_INT32(packet, position)					(GET_PACKET_NUMBER32((packet), (position), int32_t))

#define SET_PACKET_INT64(packet, position, value)			(SET_PACKET_NUMBER64((packet), (position), int64_t, (value)))
#define GET_PACKET_INT64(packet, position)					(GET_PACKET_NUMBER64((packet), (position), int64_t))

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

static uint32_t otb_protocol_create_encrypted_packet(const OtbProtocolContext *protocol_context, const unsigned char *plain_packet, uint32_t plain_packet_size, unsigned char **packet_out)
{
	GBytes *encrypted_key=NULL;
	GBytes *iv=NULL;
	uint32_t encrypted_data_size=0;
	unsigned char *encrypted_data=otb_asym_cipher_encrypt(protocol_context->peer_asym_cipher, plain_packet, plain_packet_size, &encrypted_key, &iv, &encrypted_data_size);
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

static uint32_t otb_protocol_decrypt_packet(OtbProtocolContext *protocol_context, const unsigned char *encrypted_input_packet, uint32_t encrypted_input_packet_size, unsigned char **decrypted_input_packet_out)
{
	uint32_t decrypted_input_packet_out_size;
	if(G_LIKELY(PACKET_COMMAND(encrypted_input_packet)==COMMAND_ENCRYPTED && ENCRYPTED_PACKET_IS_VALID(encrypted_input_packet, encrypted_input_packet_size)))
	{
		GBytes *encrypted_key_gbytes=g_bytes_new_static(ENCRYPTED_PACKET_ENCRYPTED_KEY(encrypted_input_packet), ENCRYPTED_PACKET_GET_ENCRYPTED_KEY_SIZE(encrypted_input_packet));
		GBytes *iv_gbytes=g_bytes_new_static(ENCRYPTED_PACKET_IV(encrypted_input_packet), ENCRYPTED_PACKET_GET_IV_SIZE(encrypted_input_packet));
		decrypted_input_packet_out_size=0;
		*decrypted_input_packet_out=otb_asym_cipher_decrypt(protocol_context->local_asym_cipher, ENCRYPTED_PACKET_ENCRYPTED_DATA(encrypted_input_packet), ENCRYPTED_PACKET_GET_ENCRYPTED_DATA_SIZE(encrypted_input_packet), encrypted_key_gbytes, iv_gbytes, &decrypted_input_packet_out_size);
		g_bytes_unref(iv_gbytes);
		g_bytes_unref(encrypted_key_gbytes);
	}
	else
	{
		decrypted_input_packet_out_size=0;
		*decrypted_input_packet_out=NULL;
	}
	return decrypted_input_packet_out_size;
}

#define otb_protocol_free_decrypted_packet(decrypted_input_packet)	if((decrypted_input_packet)!=NULL) otb_asym_cipher_dispose_decryption_buffer(decrypted_input_packet);

///Protocol packet structure:
///  OtbProtocolCommand - Command
///  unsigned char - Protocol version number
#define PROTOCOL_PACKET_SIZE			(sizeof(OtbProtocolCommand)+sizeof(unsigned char))
#define PROTOCOL_PACKET_VERSION(packet)	((packet)[sizeof(OtbProtocolCommand)])
#define CURRENT_PROTOCOL_VERSION		0

static uint32_t otb_protocol_client_establish_protocol_version(OtbProtocolContext *protocol_context, unsigned char **packet_out)
{
	*packet_out=g_malloc(PROTOCOL_PACKET_SIZE);
	PACKET_COMMAND(*packet_out)=COMMAND_PROTOCOL_VERSION;
	PROTOCOL_PACKET_VERSION(*packet_out)=CURRENT_PROTOCOL_VERSION;
	protocol_context->state=STATE_ESTABLISHING_PROTOCOL_VERSION;
	return PROTOCOL_PACKET_SIZE;
}

///Establishing friend packet structure:
///  OtbProtocolCommand - Command
///  OtbUniqueId - ID of friend
#define ESTABLISHING_FRIEND_PACKET_SIZE						(sizeof(OtbProtocolCommand)+OTB_UNIQUE_ID_BYTES_SIZE)
#define ESTABLISHING_FRIEND_PACKET_UNIQUE_ID_BYTES(packet)	((packet)+sizeof(OtbProtocolCommand))

static uint32_t otb_protocol_client_establishing_establish_friend(OtbProtocolContext *protocol_context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	uint32_t packet_out_size;
	if(G_LIKELY(input_packet_size==sizeof(OtbProtocolCommand) && PACKET_COMMAND(input_packet)==COMMAND_OK))
	{
		*packet_out=g_malloc(ESTABLISHING_FRIEND_PACKET_SIZE);
		PACKET_COMMAND(*packet_out)=COMMAND_SENDING_FRIEND_ID;
		OtbUniqueId *unique_id=NULL;
		g_object_get(protocol_context->local_user, OTB_USER_PROP_UNIQUE_ID, &unique_id, NULL);
		memcpy(ESTABLISHING_FRIEND_PACKET_UNIQUE_ID_BYTES(*packet_out), otb_unique_id_get_bytes(unique_id), OTB_UNIQUE_ID_BYTES_SIZE);
		otb_unique_id_unref(unique_id);
		protocol_context->state=STATE_ESTABLISHING_FRIEND;
		packet_out_size=ESTABLISHING_FRIEND_PACKET_SIZE;
	}
	else
		packet_out_size=otb_protocol_create_error_packet(protocol_context, packet_out);
	return packet_out_size;
}

///Authentication packet structure:
///  OtbProtocolCommand - Command
///  uint32_t - Token size
///  unsigned char* - Token
///Will be wrapped in an encrypted packet.
#define AUTHENTICATION_MESSAGE_PACKET_SET_TOKEN_SIZE(packet, size)	SET_PACKET_UINT32((packet), sizeof(OtbProtocolCommand), (size))
#define AUTHENTICATION_MESSAGE_PACKET_GET_TOKEN_SIZE(packet)		GET_PACKET_UINT32((packet), sizeof(OtbProtocolCommand))
#define AUTHENTICATION_MESSAGE_PACKET_TOKEN(packet)					((packet)+sizeof(OtbProtocolCommand)+sizeof(uint32_t))
#define AUTHENTICATION_MESSAGE_PACKET_IS_VALID(packet, packet_size)	(sizeof(OtbProtocolCommand)+sizeof(uint32_t)<=(packet_size) && sizeof(OtbProtocolCommand)+sizeof(uint32_t)+AUTHENTICATION_MESSAGE_PACKET_GET_TOKEN_SIZE(packet)==(packet_size))

static uint32_t otb_protocol_create_authentication_packet(const OtbProtocolContext *protocol_context, unsigned char **packet_out)
{
	uint32_t plain_packet_size=sizeof(OtbProtocolCommand)+sizeof(uint32_t)+AUTHENTICATION_TOKEN_SIZE;
	unsigned char *plain_packet=g_malloc(plain_packet_size);
	PACKET_COMMAND(plain_packet)=COMMAND_SENDING_AUTHENTICATION_TOKEN;
	AUTHENTICATION_MESSAGE_PACKET_SET_TOKEN_SIZE(plain_packet, AUTHENTICATION_TOKEN_SIZE);
	memcpy(AUTHENTICATION_MESSAGE_PACKET_TOKEN(plain_packet), protocol_context->authentication_token, AUTHENTICATION_TOKEN_SIZE);
	uint32_t packet_out_size=otb_protocol_create_encrypted_packet(protocol_context, (unsigned char*)plain_packet, plain_packet_size, packet_out);
	g_free(plain_packet);
	return packet_out_size;
}

static uint32_t otb_protocol_client_send_authentication_token_to_server(OtbProtocolContext *protocol_context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	if(G_LIKELY(input_packet_size==sizeof(OtbProtocolCommand) && PACKET_COMMAND(input_packet)==COMMAND_OK))
	{
		protocol_context->state=STATE_SERVER_AUTHENTICATION;
		return otb_protocol_create_authentication_packet(protocol_context, packet_out);
	}
	return otb_protocol_create_error_packet(protocol_context, packet_out);
}

#define AUTHENTICATION_MESSAGE_CHECK(protocol_context, packet, packet_size)	(AUTHENTICATION_MESSAGE_PACKET_IS_VALID((packet), (packet_size)) && AUTHENTICATION_MESSAGE_PACKET_GET_TOKEN_SIZE(packet)==AUTHENTICATION_TOKEN_SIZE && otb_smemcmp(protocol_context->authentication_token, AUTHENTICATION_MESSAGE_PACKET_TOKEN(packet), AUTHENTICATION_TOKEN_SIZE)==0)

static uint32_t otb_protocol_client_validate_server_authentication_token(OtbProtocolContext *protocol_context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	unsigned char *decrypted_input_packet=NULL;
	uint32_t decrypted_input_packet_size=otb_protocol_decrypt_packet(protocol_context, input_packet, input_packet_size, &decrypted_input_packet);
	uint32_t packet_out_size;
	if(G_LIKELY(decrypted_input_packet!=NULL && AUTHENTICATION_MESSAGE_CHECK(protocol_context, decrypted_input_packet, decrypted_input_packet_size) && PACKET_COMMAND(decrypted_input_packet)==COMMAND_SENDING_AUTHENTICATION_TOKEN))
	{
		packet_out_size=otb_protocol_create_basic_command_packet(COMMAND_REQUESTING_AUTHENTICATION, packet_out);
		protocol_context->state=STATE_CLIENT_REQUESTING_AUTHENTICATION;
	}
	else
		packet_out_size=otb_protocol_create_error_packet(protocol_context, packet_out);
	otb_protocol_free_decrypted_packet(decrypted_input_packet);
	return packet_out_size;
}

static uint32_t otb_protocol_echo_authentication_packet(OtbProtocolContext *protocol_context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	uint32_t packet_out_size;
	if(G_LIKELY(AUTHENTICATION_MESSAGE_PACKET_IS_VALID(input_packet, input_packet_size)))
		packet_out_size=otb_protocol_create_encrypted_packet(protocol_context, input_packet, input_packet_size, packet_out);
	else
		packet_out_size=otb_protocol_create_error_packet(protocol_context, packet_out);
	return packet_out_size;
}

static uint32_t otb_protocol_client_authenticate_self(OtbProtocolContext *protocol_context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	unsigned char *decrypted_input_packet=NULL;
	uint32_t decrypted_input_packet_size=otb_protocol_decrypt_packet(protocol_context, input_packet, input_packet_size, &decrypted_input_packet);
	uint32_t packet_out_size;
	if(G_LIKELY(decrypted_input_packet!=NULL && PACKET_COMMAND(decrypted_input_packet)==COMMAND_SENDING_AUTHENTICATION_TOKEN))
	{
		packet_out_size=otb_protocol_echo_authentication_packet(protocol_context, decrypted_input_packet, decrypted_input_packet_size, packet_out);
		protocol_context->state=STATE_CLIENT_AUTHENTICATION;
	}
	else
		packet_out_size=otb_protocol_create_error_packet(protocol_context, packet_out);
	otb_protocol_free_decrypted_packet(decrypted_input_packet);
	return packet_out_size;
}

static uint32_t otb_protocol_client_request_pad_unique_ids_from_server(OtbProtocolContext *protocol_context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	uint32_t packet_out_size;
	if(G_LIKELY(input_packet_size==sizeof(OtbProtocolCommand) && PACKET_COMMAND(input_packet)==COMMAND_OK))
	{
		protocol_context->state=STATE_CLIENT_REQUESTING_PAD_UNIQUE_IDS_FROM_SERVER;
		packet_out_size=otb_protocol_create_basic_command_packet(COMMAND_REQUESTING_PAD_UNIQUE_IDS, packet_out);
	}
	else
		packet_out_size=otb_protocol_create_error_packet(protocol_context, packet_out);
	return packet_out_size;
}

///Pad IDs packet structure:
///  OtbProtocolCommand - Command
///  uint32_t - Pad unique ID count
///  OtbUniqueId[] - Array of unique IDs of pad, repeated based on the pad unique ID count
#define PAD_UNIQUE_IDS_PACKET_SET_PAD_UNIQUE_ID_COUNT(packet, count)	SET_PACKET_UINT32((packet), sizeof(OtbProtocolCommand), (count))
#define PAD_UNIQUE_IDS_PACKET_GET_PAD_UNIQUE_ID_COUNT(packet)			GET_PACKET_UINT32((packet), sizeof(OtbProtocolCommand))
#define PAD_UNIQUE_IDS_PACKET_PAD_UNIQUE_ID_BYTES(packet, index)		((packet)+sizeof(OtbProtocolCommand)+sizeof(uint32_t)+(index)*OTB_UNIQUE_ID_BYTES_SIZE)
#define PAD_UNIQUE_IDS_PACKET_IS_VALID(packet, packet_size)				(sizeof(OtbProtocolCommand)+sizeof(uint32_t)<=(packet_size) && sizeof(OtbProtocolCommand)+sizeof(uint32_t)+PAD_UNIQUE_IDS_PACKET_GET_PAD_UNIQUE_ID_COUNT(packet)*OTB_UNIQUE_ID_BYTES_SIZE==(packet_size))

static gboolean otb_protocol_delete_missing_pad_unique_ids(const OtbProtocolContext *protocol_context, const unsigned char *input_packet, uint32_t input_packet_size, OtbPadRecStatus pad_rec_status)
{
	gboolean ret_val=TRUE;
	if(G_LIKELY(PACKET_COMMAND(input_packet)==COMMAND_SENDING_PAD_UNIQUE_IDS && PAD_UNIQUE_IDS_PACKET_IS_VALID(input_packet, input_packet_size)))
	{
		GSList *pad_unique_ids=otb_pad_db_get_ids_of_pads_in_status(protocol_context->pad_db, pad_rec_status);
		for(const GSList *curr_element=pad_unique_ids; ret_val && curr_element!=NULL; curr_element=g_slist_next(curr_element))
		{
			const OtbUniqueId *pad_unique_id=(const OtbUniqueId*)curr_element->data;
			gboolean pad_id_found_in_packet=FALSE;
			uint32_t pad_rec_count=PAD_UNIQUE_IDS_PACKET_GET_PAD_UNIQUE_ID_COUNT(input_packet);
			for(int packet_pad_unique_id_iter=0; !pad_id_found_in_packet && packet_pad_unique_id_iter<pad_rec_count; packet_pad_unique_id_iter++)
				if(memcmp(otb_unique_id_get_bytes(pad_unique_id), PAD_UNIQUE_IDS_PACKET_PAD_UNIQUE_ID_BYTES(input_packet, packet_pad_unique_id_iter), OTB_UNIQUE_ID_BYTES_SIZE)==0)
					pad_id_found_in_packet=TRUE;
			if(!pad_id_found_in_packet)
				ret_val=otb_pad_db_remove_pad(protocol_context->pad_db, pad_unique_id);
		}
		g_slist_free_full(pad_unique_ids, (GDestroyNotify)otb_unique_id_unref);
	}
	else
		ret_val=FALSE;
	return ret_val;
}

static uint32_t otb_protocol_create_pad_unique_ids_packet(const OtbProtocolContext *protocol_context, OtbPadRecStatus status1, OtbPadRecStatus status2, unsigned char **encrypted_packet_out)
{
	GSList *pad_unique_ids=otb_pad_db_get_ids_of_pads_in_status(protocol_context->pad_db, status1);
	if(status2<OTB_PAD_REC_STATUS_OUT_OF_BOUNDS)
		pad_unique_ids=g_slist_concat(pad_unique_ids, otb_pad_db_get_ids_of_pads_in_status(protocol_context->pad_db, status2));
	uint32_t total_pad_unique_ids=g_slist_length(pad_unique_ids);
	unsigned char *plain_packet=NULL;
	uint32_t plain_packet_size=sizeof(OtbProtocolCommand)+sizeof(uint32_t)+OTB_UNIQUE_ID_BYTES_SIZE*total_pad_unique_ids;
	plain_packet=g_malloc(plain_packet_size);
	PACKET_COMMAND(plain_packet)=COMMAND_SENDING_PAD_UNIQUE_IDS;
	PAD_UNIQUE_IDS_PACKET_SET_PAD_UNIQUE_ID_COUNT(plain_packet, total_pad_unique_ids);
	for(uint32_t unique_id_iter=0; unique_id_iter<total_pad_unique_ids; unique_id_iter++)
		memcpy(PAD_UNIQUE_IDS_PACKET_PAD_UNIQUE_ID_BYTES(plain_packet, unique_id_iter), otb_unique_id_get_bytes(g_slist_nth(pad_unique_ids, unique_id_iter)->data), OTB_UNIQUE_ID_BYTES_SIZE);
	g_slist_free_full(pad_unique_ids, (GDestroyNotify)otb_unique_id_unref);
	uint32_t encrypted_packet_out_size=otb_protocol_create_encrypted_packet(protocol_context, (unsigned char*)plain_packet, plain_packet_size, encrypted_packet_out);
	g_free(plain_packet);
	return encrypted_packet_out_size;
}

static uint32_t otb_protocol_client_send_pad_unique_ids_to_server(OtbProtocolContext *protocol_context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	unsigned char *decrypted_input_packet=NULL;
	uint32_t decrypted_input_packet_size=otb_protocol_decrypt_packet(protocol_context, input_packet, input_packet_size, &decrypted_input_packet);
	uint32_t packet_out_size;
	if(G_LIKELY(decrypted_input_packet!=NULL && otb_protocol_delete_missing_pad_unique_ids(protocol_context, decrypted_input_packet, decrypted_input_packet_size, OTB_PAD_REC_STATUS_SENT) && otb_protocol_delete_missing_pad_unique_ids(protocol_context, decrypted_input_packet, decrypted_input_packet_size, OTB_PAD_REC_STATUS_CONSUMED)))
	{
		packet_out_size=otb_protocol_create_pad_unique_ids_packet(protocol_context, OTB_PAD_REC_STATUS_SENT, OTB_PAD_REC_STATUS_CONSUMED, packet_out);
		protocol_context->state=STATE_CLIENT_SENDING_PAD_UNIQUE_IDS_TO_SERVER;
	}
	else
		packet_out_size=otb_protocol_create_error_packet(protocol_context, packet_out);
	otb_protocol_free_decrypted_packet(decrypted_input_packet);
	return packet_out_size;
}

///New incoming pad packet structure:
///  OtbProtocolCommand - Command
///  OtbUniqueId pad_id
///  int32_t - pad_size
///  int64_t - pad_expiration (seconds that have elapsed since 1970-01-01 00:00:00 UTC)
///Will be wrapped in an encrypted packet.
#define INCOMING_PAD_HEADER_PACKET_SIZE										(sizeof(OtbProtocolCommand)+OTB_UNIQUE_ID_BYTES_SIZE+sizeof(int32_t)+sizeof(int64_t))
#define INCOMING_PAD_HEADER_PACKET_PAD_UNIQUE_ID_BYTES(packet)				((packet)+sizeof(OtbProtocolCommand))
#define INCOMING_PAD_HEADER_PACKET_SET_PAD_SIZE(packet, size)				SET_PACKET_INT32((packet), sizeof(OtbProtocolCommand)+OTB_UNIQUE_ID_BYTES_SIZE, (size))
#define INCOMING_PAD_HEADER_PACKET_GET_PAD_SIZE(packet)						GET_PACKET_INT32((packet), sizeof(OtbProtocolCommand)+OTB_UNIQUE_ID_BYTES_SIZE)
#define INCOMING_PAD_HEADER_PACKET_SET_PAD_EXPIRATION(packet, expiration)	SET_PACKET_INT64((packet), sizeof(OtbProtocolCommand)+OTB_UNIQUE_ID_BYTES_SIZE+sizeof(int32_t), (expiration))
#define INCOMING_PAD_HEADER_PACKET_GET_PAD_EXPIRATION(packet)				GET_PACKET_INT64((packet), sizeof(OtbProtocolCommand)+OTB_UNIQUE_ID_BYTES_SIZE+sizeof(int32_t))
#define INCOMING_PAD_HEADER_PACKET_IS_VALID(packet, packet_size)			(INCOMING_PAD_HEADER_PACKET_SIZE==(packet_size))

static uint32_t otb_protocol_client_send_pad_header_to_server(OtbProtocolContext *protocol_context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	uint32_t packet_out_size;
	if(G_LIKELY(input_packet_size==sizeof(OtbProtocolCommand) && PACKET_COMMAND(input_packet)==COMMAND_OK))
	{
		otb_unique_id_unref(protocol_context->pad_unique_id);
		protocol_context->pad_unique_id=otb_pad_db_fetch_random_rec_id(protocol_context->pad_db, OTB_PAD_REC_STATUS_UNSENT);
		if(protocol_context->pad_unique_id!=NULL)
		{
			protocol_context->pad_io=otb_pad_db_open_pad_for_read(protocol_context->pad_db, protocol_context->pad_unique_id);
			if(G_LIKELY(protocol_context->pad_io!=NULL))
			{
				unsigned char *plain_packet=g_malloc(INCOMING_PAD_HEADER_PACKET_SIZE);
				PACKET_COMMAND(plain_packet)=COMMAND_SENDING_PAD_HEADER;
				memcpy(INCOMING_PAD_HEADER_PACKET_PAD_UNIQUE_ID_BYTES(plain_packet), otb_unique_id_get_bytes(protocol_context->pad_unique_id), OTB_UNIQUE_ID_BYTES_SIZE);
				protocol_context->pad_size=otb_pad_db_get_pad_size(protocol_context->pad_db, protocol_context->pad_unique_id);
				INCOMING_PAD_HEADER_PACKET_SET_PAD_SIZE(plain_packet, protocol_context->pad_size);
				long long pad_expiration=otb_pad_db_get_pad_expiration(protocol_context->pad_db, protocol_context->pad_unique_id);
				INCOMING_PAD_HEADER_PACKET_SET_PAD_EXPIRATION(plain_packet, pad_expiration);
				packet_out_size=otb_protocol_create_encrypted_packet(protocol_context, (unsigned char*)plain_packet, INCOMING_PAD_HEADER_PACKET_SIZE, packet_out);
				protocol_context->pad_bytes_transferred=0;
				protocol_context->state=STATE_CLIENT_SENDING_PAD_HEADER_TO_SERVER;
				g_free(plain_packet);
			}
			else
				packet_out_size=otb_protocol_create_error_packet(protocol_context, packet_out);
		}
		else
		{
			packet_out_size=otb_protocol_create_basic_command_packet(COMMAND_FINISH, packet_out);
			protocol_context->state=STATE_FINISHED;
		}
	}
	else
		packet_out_size=otb_protocol_create_error_packet(protocol_context, packet_out);
	return packet_out_size;
}

///Pad chunk packet structure:
///  OtbProtocolCommand - Command
///  int32_t - pad_chunk_size
///  unsigned char* - pad_chunk
///Will be wrapped in an encrypted packet.
#define INCOMING_PAD_PACKET_SET_PAD_CHUNK_SIZE(packet, size)	SET_PACKET_UINT32((packet), sizeof(OtbProtocolCommand), (size))
#define INCOMING_PAD_PACKET_GET_PAD_CHUNK_SIZE(packet)			GET_PACKET_UINT32((packet), sizeof(OtbProtocolCommand))
#define INCOMING_PAD_PACKET_PAD_CHUNK(packet)					((packet)+sizeof(OtbProtocolCommand)+sizeof(uint32_t))
#define INCOMING_PAD_PACKET_IS_VALID(packet, packet_size)		(sizeof(OtbProtocolCommand)+sizeof(uint32_t)<=(packet_size) && sizeof(OtbProtocolCommand)+sizeof(uint32_t)+INCOMING_PAD_PACKET_GET_PAD_CHUNK_SIZE(packet)==(packet_size))

static uint32_t otb_protocol_client_send_pad_chunk_to_server(OtbProtocolContext *protocol_context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out);

static uint32_t otb_protocol_client_attempt_to_send_first_pad_chunk_to_server(OtbProtocolContext *protocol_context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	uint32_t packet_out_size;
	if(G_LIKELY(input_packet_size==sizeof(OtbProtocolCommand) && PACKET_COMMAND(input_packet)==COMMAND_UNABLE))
	{
		packet_out_size=0;
		*packet_out=NULL;
		protocol_context->state=STATE_FINISHED;
	}
	else
		packet_out_size=otb_protocol_client_send_pad_chunk_to_server(protocol_context, input_packet, input_packet_size, packet_out);
	return packet_out_size;
}

static size_t otb_protocol_get_chunk_size()
{
	size_t chunk_size=otb_settings_get_config_uint(CONFIG_GROUP, CONFIG_CHUNK_SIZE, 0);
	if(G_UNLIKELY(chunk_size==0))
	{
		chunk_size=CONFIG_DEFAULT_CHUNK_SIZE;
		otb_settings_set_config_uint(CONFIG_GROUP, CONFIG_CHUNK_SIZE, chunk_size);
	}
	return chunk_size;
}

static uint32_t otb_protocol_client_send_pad_chunk_to_server(OtbProtocolContext *protocol_context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	uint32_t packet_out_size;
	gboolean error=FALSE;
	if(G_LIKELY(input_packet_size==sizeof(OtbProtocolCommand) && PACKET_COMMAND(input_packet)==COMMAND_OK))
	{
		size_t buffer_size=MIN(protocol_context->pad_size-protocol_context->pad_bytes_transferred, otb_protocol_get_chunk_size());
		uint32_t plain_packet_size=sizeof(OtbProtocolCommand)+sizeof(uint32_t)+buffer_size;
		unsigned char *plain_packet=otb_malloc_locked(plain_packet_size);
		uint32_t byte_count;
		unsigned char *curr_byte;
		for(byte_count=0, curr_byte=INCOMING_PAD_PACKET_PAD_CHUNK(plain_packet); otb_pad_has_more_bytes(protocol_context->pad_io) && byte_count<buffer_size && !error; byte_count++, curr_byte++)
		{
			if(G_UNLIKELY(!otb_pad_read_byte(protocol_context->pad_io, curr_byte)))
			{
				packet_out_size=otb_protocol_create_error_packet(protocol_context, packet_out);
				error=TRUE;
			}
		}
		if(G_LIKELY(!error))
		{
			protocol_context->pad_bytes_transferred+=byte_count;
			if(otb_pad_has_more_bytes(protocol_context->pad_io))
			{
				PACKET_COMMAND(plain_packet)=COMMAND_SENDING_PAD_CHUNK;
				protocol_context->state=STATE_CLIENT_SENDING_PAD_CHUNK_TO_SERVER;
			}
			else if(G_LIKELY(otb_pad_db_close_pad(protocol_context->pad_db, protocol_context->pad_io)))
			{
				PACKET_COMMAND(plain_packet)=COMMAND_SENDING_FINAL_PAD_CHUNK;
				protocol_context->state=STATE_CLIENT_SENDING_FINAL_PAD_CHUNK_TO_SERVER;
			}
			else
				error=TRUE;
			if(G_LIKELY(!error))
			{
				INCOMING_PAD_PACKET_SET_PAD_CHUNK_SIZE(plain_packet, byte_count);
				packet_out_size=otb_protocol_create_encrypted_packet(protocol_context, plain_packet, plain_packet_size, packet_out);
			}
		}
		otb_free_locked(plain_packet);
	}
	else
		error=TRUE;
	if(G_UNLIKELY(error))
		packet_out_size=otb_protocol_create_error_packet(protocol_context, packet_out);
	return packet_out_size;
}

static uint32_t otb_protocol_client_wrap_up_sending_pad(OtbProtocolContext *protocol_context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	uint32_t packet_out_size;
	if(G_LIKELY(input_packet_size==sizeof(OtbProtocolCommand) && PACKET_COMMAND(input_packet)==COMMAND_OK))
	{
		otb_pad_db_mark_pad_as_sent(protocol_context->pad_db, protocol_context->pad_unique_id);
		otb_unique_id_unref(protocol_context->pad_unique_id);
		protocol_context->pad_unique_id=NULL;
		packet_out_size=otb_protocol_client_send_pad_header_to_server(protocol_context, input_packet, input_packet_size, packet_out);
	}
	else
		packet_out_size=otb_protocol_create_error_packet(protocol_context, packet_out);
	return packet_out_size;
}

uint32_t otb_protocol_client(OtbProtocolContext *protocol_context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	if(G_UNLIKELY(input_packet_size<sizeof(OtbProtocolCommand) && protocol_context->state!=STATE_INITIAL))
		return otb_protocol_create_error_packet(protocol_context, packet_out);
	if(G_UNLIKELY((input_packet_size==0 && protocol_context->state!=STATE_INITIAL) || (input_packet_size!=0 && PACKET_COMMAND(input_packet)==COMMAND_ERROR)))
	{
		protocol_context->state=STATE_FINISHED;
		return 0;
	}
	switch(protocol_context->state)
	{
		case STATE_INITIAL:
			return otb_protocol_client_establish_protocol_version(protocol_context, packet_out);
		case STATE_ESTABLISHING_PROTOCOL_VERSION:
			return otb_protocol_client_establishing_establish_friend(protocol_context, input_packet, input_packet_size, packet_out);
		case STATE_ESTABLISHING_FRIEND:
			return otb_protocol_client_send_authentication_token_to_server(protocol_context, input_packet, input_packet_size, packet_out);
		case STATE_SERVER_AUTHENTICATION:
			return otb_protocol_client_validate_server_authentication_token(protocol_context, input_packet, input_packet_size, packet_out);
		case STATE_CLIENT_REQUESTING_AUTHENTICATION:
			return otb_protocol_client_authenticate_self(protocol_context, input_packet, input_packet_size, packet_out);
		case STATE_CLIENT_AUTHENTICATION:
			return otb_protocol_client_request_pad_unique_ids_from_server(protocol_context, input_packet, input_packet_size, packet_out);
		case STATE_CLIENT_REQUESTING_PAD_UNIQUE_IDS_FROM_SERVER:
			return otb_protocol_client_send_pad_unique_ids_to_server(protocol_context, input_packet, input_packet_size, packet_out);
		case STATE_CLIENT_SENDING_PAD_UNIQUE_IDS_TO_SERVER:
			return otb_protocol_client_send_pad_header_to_server(protocol_context, input_packet, input_packet_size, packet_out);
		case STATE_CLIENT_SENDING_PAD_HEADER_TO_SERVER:
			return otb_protocol_client_attempt_to_send_first_pad_chunk_to_server(protocol_context, input_packet, input_packet_size, packet_out);
		case STATE_CLIENT_SENDING_PAD_CHUNK_TO_SERVER:
			return otb_protocol_client_send_pad_chunk_to_server(protocol_context, input_packet, input_packet_size, packet_out);
		case STATE_CLIENT_SENDING_FINAL_PAD_CHUNK_TO_SERVER:
			return otb_protocol_client_wrap_up_sending_pad(protocol_context, input_packet, input_packet_size, packet_out);
		default:
			return otb_protocol_create_error_packet(protocol_context, packet_out);
	}
}

static uint32_t otb_protocol_server_establish_protocol_version(OtbProtocolContext *protocol_context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	uint32_t packet_out_size;
	if(G_LIKELY(input_packet_size==PROTOCOL_PACKET_SIZE && PACKET_COMMAND(input_packet)==COMMAND_PROTOCOL_VERSION && PROTOCOL_PACKET_VERSION(input_packet)==CURRENT_PROTOCOL_VERSION))
	{
		protocol_context->state=STATE_ESTABLISHING_PROTOCOL_VERSION;
		packet_out_size=otb_protocol_create_ok_packet(packet_out);
	}
	else
		packet_out_size=otb_protocol_create_error_packet(protocol_context, packet_out);
	return packet_out_size;
}

static uint32_t otb_protocol_server_establish_friend(OtbProtocolContext *protocol_context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	uint32_t packet_out_size;
	if(G_LIKELY(input_packet_size==ESTABLISHING_FRIEND_PACKET_SIZE && PACKET_COMMAND(input_packet)==COMMAND_SENDING_FRIEND_ID))
	{
		OtbUniqueId *friend_unique_id=otb_unique_id_from_bytes(ESTABLISHING_FRIEND_PACKET_UNIQUE_ID_BYTES(input_packet));
		OtbFriend *peer_friend=otb_bitkeeper_get_friend(protocol_context->bitkeeper, friend_unique_id);
		if(G_UNLIKELY(peer_friend==NULL))
			packet_out_size=otb_protocol_create_error_packet(protocol_context, packet_out);
		else
		{
			otb_protocol_set_peer_friend_on_context(protocol_context, peer_friend);
			if(protocol_context->pad_db!=NULL)
				g_object_unref(protocol_context->pad_db);
			g_object_get(peer_friend, OTB_FRIEND_PROP_INCOMING_PAD_DB, &protocol_context->pad_db, NULL);
			protocol_context->state=STATE_ESTABLISHING_FRIEND;
			packet_out_size=otb_protocol_create_ok_packet(packet_out);
			g_object_unref(peer_friend);
		}
		otb_unique_id_unref(friend_unique_id);
	}
	else
		packet_out_size=otb_protocol_create_error_packet(protocol_context, packet_out);
	return packet_out_size;
}

static uint32_t otb_protocol_server_authenticate_self(OtbProtocolContext *protocol_context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	unsigned char *decrypted_input_packet=NULL;
	uint32_t decrypted_input_packet_size=otb_protocol_decrypt_packet(protocol_context, input_packet, input_packet_size, &decrypted_input_packet);
	uint32_t packet_out_size;
	if(G_LIKELY(decrypted_input_packet!=NULL && AUTHENTICATION_MESSAGE_PACKET_IS_VALID(decrypted_input_packet, decrypted_input_packet_size) && PACKET_COMMAND(decrypted_input_packet)==COMMAND_SENDING_AUTHENTICATION_TOKEN))
	{
		packet_out_size=otb_protocol_echo_authentication_packet(protocol_context, decrypted_input_packet, decrypted_input_packet_size, packet_out);
		protocol_context->state=STATE_SERVER_AUTHENTICATION;
	}
	else
		packet_out_size=otb_protocol_create_error_packet(protocol_context, packet_out);
	otb_protocol_free_decrypted_packet(decrypted_input_packet);
	return packet_out_size;
}

static uint32_t otb_protocol_server_send_authentication_token_to_client(OtbProtocolContext *protocol_context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	uint32_t packet_out_size;
	if(G_LIKELY(input_packet_size==sizeof(OtbProtocolCommand) && PACKET_COMMAND(input_packet)==COMMAND_REQUESTING_AUTHENTICATION))
	{
		protocol_context->state=STATE_CLIENT_REQUESTING_AUTHENTICATION;
		packet_out_size=otb_protocol_create_authentication_packet(protocol_context, packet_out);
	}
	else
		packet_out_size=otb_protocol_create_error_packet(protocol_context, packet_out);
	return packet_out_size;
}

static uint32_t otb_protocol_server_state_validate_client_authentication_token(OtbProtocolContext *protocol_context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	unsigned char *decrypted_input_packet=NULL;
	uint32_t decrypted_input_packet_size=otb_protocol_decrypt_packet(protocol_context, input_packet, input_packet_size, &decrypted_input_packet);
	uint32_t packet_out_size;
	if(G_LIKELY(decrypted_input_packet!=NULL && PACKET_COMMAND(decrypted_input_packet)==COMMAND_SENDING_AUTHENTICATION_TOKEN && AUTHENTICATION_MESSAGE_CHECK(protocol_context, decrypted_input_packet, decrypted_input_packet_size)))
	{
		packet_out_size=otb_protocol_create_ok_packet(packet_out);
		protocol_context->state=STATE_CLIENT_AUTHENTICATION;
	}
	else
		packet_out_size=otb_protocol_create_error_packet(protocol_context, packet_out);
	otb_protocol_free_decrypted_packet(decrypted_input_packet);
	return packet_out_size;
}

static uint32_t otb_protocol_server_send_pad_unique_ids_to_client(OtbProtocolContext *protocol_context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	uint32_t packet_out_size;
	if(G_LIKELY(input_packet_size==sizeof(OtbProtocolCommand) && PACKET_COMMAND(input_packet)==COMMAND_REQUESTING_PAD_UNIQUE_IDS))
	{
		packet_out_size=otb_protocol_create_pad_unique_ids_packet(protocol_context, OTB_PAD_REC_STATUS_RECEIVED, OTB_PAD_REC_STATUS_OUT_OF_BOUNDS, packet_out);
		protocol_context->state=STATE_CLIENT_REQUESTING_PAD_UNIQUE_IDS_FROM_SERVER;
	}
	else
		packet_out_size=otb_protocol_create_error_packet(protocol_context, packet_out);
	return packet_out_size;
}

static uint32_t otb_protocol_server_receive_pad_unique_ids_from_client(OtbProtocolContext *protocol_context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	unsigned char *decrypted_input_packet=NULL;
	uint32_t decrypted_input_packet_size=otb_protocol_decrypt_packet(protocol_context, input_packet, input_packet_size, &decrypted_input_packet);
	uint32_t packet_out_size;
	if(G_LIKELY(decrypted_input_packet!=NULL && otb_protocol_delete_missing_pad_unique_ids(protocol_context, decrypted_input_packet, decrypted_input_packet_size, OTB_PAD_REC_STATUS_RECEIVED)))
	{
		packet_out_size=otb_protocol_create_ok_packet(packet_out);
		protocol_context->state=STATE_CLIENT_SENDING_PAD_UNIQUE_IDS_TO_SERVER;
	}
	else
		packet_out_size=otb_protocol_create_error_packet(protocol_context, packet_out);
	otb_protocol_free_decrypted_packet(decrypted_input_packet);
	return packet_out_size;
}

enum
{
	ADD_NEW_PAD_ID_SUCCESS,
	ADD_NEW_PAD_ID_UNABLE,
	ADD_NEW_PAD_ID_ERROR
};

static int otb_protocol_server_add_new_pad_id(OtbProtocolContext *protocol_context, const unsigned char *input_packet, uint32_t input_packet_size)
{
	int add_new_pad_status;
	if(G_LIKELY(input_packet!=NULL && INCOMING_PAD_HEADER_PACKET_IS_VALID(input_packet, input_packet_size)))
	{
		otb_unique_id_unref(protocol_context->pad_unique_id);
		protocol_context->pad_unique_id=otb_unique_id_from_bytes(INCOMING_PAD_HEADER_PACKET_PAD_UNIQUE_ID_BYTES(input_packet));
		protocol_context->pad_bytes_transferred=0;
		protocol_context->pad_size=INCOMING_PAD_HEADER_PACKET_GET_PAD_SIZE(input_packet);
		long long pad_expiration=INCOMING_PAD_HEADER_PACKET_GET_PAD_EXPIRATION(input_packet);
		protocol_context->pad_io=otb_pad_db_add_incoming_pad(protocol_context->pad_db, protocol_context->pad_unique_id, protocol_context->pad_size, pad_expiration);
		if(protocol_context->pad_io==NULL)
			add_new_pad_status=ADD_NEW_PAD_ID_UNABLE;
		else
			add_new_pad_status=ADD_NEW_PAD_ID_SUCCESS;
	}
	else
		add_new_pad_status=ADD_NEW_PAD_ID_ERROR;
	return add_new_pad_status;
}

static uint32_t otb_protocol_server_receive_finish_from_client(OtbProtocolContext *protocol_context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	uint32_t packet_out_size;
	if(G_LIKELY(input_packet_size==sizeof(OtbProtocolCommand)))
	{
		packet_out_size=0;
		*packet_out=NULL;
	}
	else
		packet_out_size=otb_protocol_create_error_packet(protocol_context, packet_out);
	return packet_out_size;
}

static uint32_t otb_protocol_server_receive_pad_header_from_client(OtbProtocolContext *protocol_context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	uint32_t packet_out_size;
	unsigned char *decrypted_input_packet=NULL;
	uint32_t decrypted_input_packet_size=otb_protocol_decrypt_packet(protocol_context, input_packet, input_packet_size, &decrypted_input_packet);
	int add_new_pad_id_status=otb_protocol_server_add_new_pad_id(protocol_context, decrypted_input_packet, decrypted_input_packet_size);
	switch(add_new_pad_id_status)
	{
		case ADD_NEW_PAD_ID_SUCCESS:
			packet_out_size=otb_protocol_create_ok_packet(packet_out);
			protocol_context->state=STATE_CLIENT_SENDING_PAD_HEADER_TO_SERVER;
			break;
		case ADD_NEW_PAD_ID_UNABLE:
			packet_out_size=otb_protocol_create_basic_command_packet(COMMAND_UNABLE, packet_out);
			protocol_context->state=STATE_CLIENT_SENDING_PAD_HEADER_TO_SERVER;
			break;
		default:
			packet_out_size=otb_protocol_create_error_packet(protocol_context, packet_out);
	}
	otb_protocol_free_decrypted_packet(decrypted_input_packet);
	return packet_out_size;
}

static uint32_t otb_protocol_server_receive_pad_header_or_finish_from_client(OtbProtocolContext *protocol_context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	uint32_t packet_out_size;
	if(PACKET_COMMAND(input_packet)==COMMAND_FINISH)
		packet_out_size=otb_protocol_server_receive_finish_from_client(protocol_context, input_packet, input_packet_size, packet_out);
	else
		packet_out_size=otb_protocol_server_receive_pad_header_from_client(protocol_context, input_packet, input_packet_size, packet_out);
	return packet_out_size;
}

static uint32_t otb_protocol_server_receive_pad_chunk_from_client(OtbProtocolContext *protocol_context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out);

static uint32_t otb_protocol_server_receive_first_pad_chunk_from_client(OtbProtocolContext *protocol_context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	uint32_t packet_out_size;
	if(PACKET_COMMAND(input_packet)==STATE_FINISHED)
	{
		packet_out_size=0;
		*packet_out=NULL;
		protocol_context->state=STATE_FINISHED;
	}
	else
		packet_out_size=otb_protocol_server_receive_pad_chunk_from_client(protocol_context, input_packet, input_packet_size, packet_out);
	return packet_out_size;
}

static uint32_t otb_protocol_server_receive_pad_chunk_from_client(OtbProtocolContext *protocol_context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	uint32_t packet_out_size;
	unsigned char *decrypted_input_packet=NULL;
	uint32_t decrypted_input_packet_size=otb_protocol_decrypt_packet(protocol_context, input_packet, input_packet_size, &decrypted_input_packet);
	if(G_LIKELY(decrypted_input_packet!=NULL && INCOMING_PAD_PACKET_IS_VALID(decrypted_input_packet, decrypted_input_packet_size) && (PACKET_COMMAND(decrypted_input_packet)==COMMAND_SENDING_PAD_CHUNK || PACKET_COMMAND(decrypted_input_packet)==COMMAND_SENDING_FINAL_PAD_CHUNK)))
	{
		packet_out_size=otb_protocol_create_ok_packet(packet_out);
		protocol_context->state=(PACKET_COMMAND(decrypted_input_packet)==COMMAND_SENDING_FINAL_PAD_CHUNK?STATE_CLIENT_SENDING_FINAL_PAD_CHUNK_TO_SERVER:STATE_CLIENT_SENDING_PAD_CHUNK_TO_SERVER);
		otb_pad_write(protocol_context->pad_io, INCOMING_PAD_PACKET_PAD_CHUNK(decrypted_input_packet), INCOMING_PAD_PACKET_GET_PAD_CHUNK_SIZE(decrypted_input_packet));
		if(PACKET_COMMAND(decrypted_input_packet)==COMMAND_SENDING_FINAL_PAD_CHUNK)
			otb_pad_db_close_pad(protocol_context->pad_db, protocol_context->pad_io);
	}
	else
		packet_out_size=otb_protocol_create_error_packet(protocol_context, packet_out);
	otb_protocol_free_decrypted_packet(decrypted_input_packet);
	return packet_out_size;
}

uint32_t otb_protocol_server(OtbProtocolContext *protocol_context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **packet_out)
{
	if(G_UNLIKELY(input_packet_size==0 || PACKET_COMMAND(input_packet)==COMMAND_ERROR))
	{
		protocol_context->state=STATE_FINISHED;
		return 0;
	}
	switch(protocol_context->state)
	{
		case STATE_INITIAL:
			return otb_protocol_server_establish_protocol_version(protocol_context, input_packet, input_packet_size, packet_out);
		case STATE_ESTABLISHING_PROTOCOL_VERSION:
			return otb_protocol_server_establish_friend(protocol_context, input_packet, input_packet_size, packet_out);
		case STATE_ESTABLISHING_FRIEND:
			return otb_protocol_server_authenticate_self(protocol_context, input_packet, input_packet_size, packet_out);
		case STATE_SERVER_AUTHENTICATION:
			return otb_protocol_server_send_authentication_token_to_client(protocol_context, input_packet, input_packet_size, packet_out);
		case STATE_CLIENT_REQUESTING_AUTHENTICATION:
			return otb_protocol_server_state_validate_client_authentication_token(protocol_context, input_packet, input_packet_size, packet_out);
		case STATE_CLIENT_AUTHENTICATION:
			return otb_protocol_server_send_pad_unique_ids_to_client(protocol_context, input_packet, input_packet_size, packet_out);
		case STATE_CLIENT_REQUESTING_PAD_UNIQUE_IDS_FROM_SERVER:
			return otb_protocol_server_receive_pad_unique_ids_from_client(protocol_context, input_packet, input_packet_size, packet_out);
		case STATE_CLIENT_SENDING_PAD_UNIQUE_IDS_TO_SERVER:
		case STATE_CLIENT_SENDING_FINAL_PAD_CHUNK_TO_SERVER:
			return otb_protocol_server_receive_pad_header_or_finish_from_client(protocol_context, input_packet, input_packet_size, packet_out);
		case STATE_CLIENT_SENDING_PAD_HEADER_TO_SERVER:
			return otb_protocol_server_receive_first_pad_chunk_from_client(protocol_context, input_packet, input_packet_size, packet_out);
		case STATE_CLIENT_SENDING_PAD_CHUNK_TO_SERVER:
			return otb_protocol_server_receive_pad_chunk_from_client(protocol_context, input_packet, input_packet_size, packet_out);
		default:
			return otb_protocol_create_error_packet(protocol_context, packet_out);
	}
}

#define PROTOCOL_BUFFER_SIZE	1024

///Protocol meta-packet structure:
///  uint32_t - packet size
///  unsigned char* - packet
#define PROTOCOL_META_PACKET_SET_PACKET_SIZE(packet, size)		SET_PACKET_UINT32((packet), 0, (size))
#define PROTOCOL_META_PACKET_GET_PACKET_SIZE(packet)			GET_PACKET_UINT32((packet), 0)
#define PROTOCOL_META_PACKET_PACKET(packet)						((packet)+sizeof(uint32_t))
#define PROTOCOL_META_PACKET_IS_RECEIVED(packet, packet_size)	(sizeof(uint32_t)<=(packet_size) && sizeof(uint32_t)+PROTOCOL_META_PACKET_GET_PACKET_SIZE(packet)<=(packet_size))

static gboolean otb_protocol_process_request_packet(OtbProtocolContext *protocol_context, ProtocolFunc protocol_func, GByteArray *request_packet_byte_array, GOutputStream *output_stream)
{
	uint32_t packet_size=(request_packet_byte_array==NULL?0:PROTOCOL_META_PACKET_GET_PACKET_SIZE(request_packet_byte_array->data));
	unsigned char *response_packet=NULL;
	uint32_t response_packet_size=protocol_func(protocol_context, request_packet_byte_array==NULL?NULL:request_packet_byte_array->data+sizeof(uint32_t), packet_size, &response_packet);
	if(request_packet_byte_array!=NULL)
		g_byte_array_remove_range(request_packet_byte_array, 0, request_packet_byte_array->len);
	unsigned int expected_bytes_written=sizeof response_packet_size+response_packet_size;
	unsigned char *response_meta_packet=g_malloc(expected_bytes_written);
	PROTOCOL_META_PACKET_SET_PACKET_SIZE(response_meta_packet, response_packet_size);
	memcpy(PROTOCOL_META_PACKET_PACKET(response_meta_packet), response_packet, response_packet_size);
	unsigned int actual_bytes_written=-1;
	gboolean ret_val=g_output_stream_write_all(output_stream, response_meta_packet, expected_bytes_written, &actual_bytes_written, NULL, NULL);
	ret_val=(ret_val && expected_bytes_written==actual_bytes_written);
	g_free(response_meta_packet);
	g_free(response_packet);
	return ret_val;
}

void otb_protocol_execute(OtbProtocolContext *protocol_context, ProtocolFunc protocol_func, GInputStream *input_stream, GOutputStream *output_stream, gboolean initiate_communication)
{
	GByteArray *request_packet_byte_array=g_byte_array_new();
	gboolean error=FALSE;
	if(initiate_communication)
		error=!otb_protocol_process_request_packet(protocol_context, protocol_func, NULL, output_stream);
	while(G_LIKELY(protocol_context->state!=STATE_FINISHED && !g_input_stream_is_closed(input_stream) && !g_output_stream_is_closed(output_stream) && !error))
	{
		unsigned char input_buffer[PROTOCOL_BUFFER_SIZE];
		signed long input_buffer_bytes_received=g_input_stream_read(input_stream, input_buffer, PROTOCOL_BUFFER_SIZE, NULL, NULL);
		if(G_UNLIKELY(input_buffer_bytes_received==G_IO_ERROR_CANCELLED))
			error=TRUE;
		else
		{
			g_byte_array_append(request_packet_byte_array, input_buffer, input_buffer_bytes_received);
			if(PROTOCOL_META_PACKET_IS_RECEIVED(request_packet_byte_array->data, request_packet_byte_array->len))
				error=!otb_protocol_process_request_packet(protocol_context, protocol_func, request_packet_byte_array, output_stream);
		}
	}
	g_byte_array_unref(request_packet_byte_array);
}

void otb_protocol_context_free(OtbProtocolContext *protocol_context)
{
	g_free(protocol_context->authentication_token);
	g_object_unref(protocol_context->bitkeeper);
	g_object_unref(protocol_context->local_user);
	g_object_unref(protocol_context->local_asym_cipher);
	if(protocol_context->peer_friend!=NULL)
		g_object_unref(protocol_context->peer_friend);
	if(protocol_context->peer_asym_cipher!=NULL)
		g_object_unref(protocol_context->peer_asym_cipher);
	otb_unique_id_unref(protocol_context->pad_unique_id);
	if(protocol_context->pad_io!=NULL)
		otb_pad_db_close_pad(protocol_context->pad_db, protocol_context->pad_io);
	if(protocol_context->pad_db!=NULL)
		g_object_unref(protocol_context->pad_db);
	g_free(protocol_context);
}
