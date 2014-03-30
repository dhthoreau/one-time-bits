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

#include "pad-db.h"
#include "pad-rec.h"
#include "protocol.h"
#include "random.h"
#include "smem.h"

#define AUTHENTICATION_TOKEN_SIZE	4096

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
};


enum
{
	COMMAND_ERROR,
	COMMAND_OK,
	COMMAND_ENCRYPTED,
	COMMAND_SENDING_FRIEND_ID,
	COMMAND_REQUESTING_AUTHENTICATION,
	COMMAND_SENDING_AUTHENTICATION_TOKEN,
	COMMAND_REQUESTING_PAD_IDS,
	COMMAND_SENDING_PAD_IDS
};

enum
{
	STATE_INITIAL,
	STATE_ESTABLISHING_FRIEND,
	STATE_SERVER_AUTHENTICATION,
	STATE_CLIENT_REQUESTING_AUTHENTICATION,
	STATE_CLIENT_AUTHENTICATION,
	STATE_CLIENT_REQUESTING_PAD_IDS_FROM_SERVER,
	STATE_CLIENT_SENDING_PAD_IDS_TO_SERVER,
	STATE_CLIENT_SENDING_PADS_TO_SERVER,
	STATE_FINISHED
};

OtbProtocolContext *otb_protocol_context_create_client(OtbBitkeeper *bitkeeper, OtbFriend *peer_friend)
{
	OtbProtocolContext *context=g_malloc(sizeof(OtbProtocolContext));
	context->state=STATE_INITIAL;
	context->authentication_token=otb_create_random_bytes(AUTHENTICATION_TOKEN_SIZE);
	g_object_ref(bitkeeper);
	context->bitkeeper=bitkeeper;
	g_object_get(bitkeeper, OTB_BITKEEPER_PROP_USER, &context->local_user, NULL);
	g_object_get(context->local_user, OTB_USER_PROP_ASYM_CIPHER, &context->local_asym_cipher, NULL);
	if(peer_friend!=NULL)
	{
		g_object_ref(peer_friend);
		context->peer_friend=peer_friend;
		g_object_get(peer_friend, OTB_FRIEND_PROP_PUBLIC_KEY, &context->peer_asym_cipher, OTB_FRIEND_PROP_OUTGOING_PADS, &context->pad_db, NULL);
	}
	else
	{
		context->peer_friend=NULL;
		context->peer_asym_cipher=NULL;
		context->pad_db=NULL;
	}
	return context;
}

static uint32_t otb_protocol_create_basic_command_packet(OtbProtocolCommand command, void **packet_out)
{
	uint32_t packet_size=sizeof(OtbProtocolCommand);
	*packet_out=g_malloc(packet_size);
	*((OtbProtocolCommand*)*packet_out)=command;
	return packet_size;
}

#define otb_protocol_create_ok_packet(packet_out)	(otb_protocol_create_basic_command_packet(COMMAND_OK, (packet_out)))

static uint32_t otb_protocol_create_error_packet(OtbProtocolContext *context, void **packet_out)
{
	context->state=STATE_FINISHED;
	return otb_protocol_create_basic_command_packet(COMMAND_ERROR, packet_out);
}

#define ENCRYPTED_PACKET_ENCRYPTED_KEY(packet)			(unsigned char*)(&(packet)+sizeof(OtbEncryptedPacket))
#define ENCRYPTED_PACKET_IV(packet)						(unsigned char*)(&(packet)+sizeof(OtbEncryptedPacket)+g_ntohl((packet)->encrypted_key_size))
#define ENCRYPTED_PACKET_ENCRYPTED_DATA(packet)			(unsigned char*)(&(packet)+sizeof(OtbEncryptedPacket)+g_ntohl((packet)->encrypted_key_size)+g_ntohl((packet)->iv_size))
#define ENCRYPTED_PACKET_IS_VALID(packet, packet_size)	(sizeof(OtbEncryptedPacket)+g_ntohl((packet)->encrypted_key_size)+g_ntohl((packet)->iv_size)+g_ntohl((packet)->encrypted_data_size)==(packet_size))

typedef struct
{
	OtbProtocolCommand command;
	uint32_t encrypted_key_size;
	uint32_t iv_size;
	uint32_t encrypted_data_size;
} OtbEncryptedPacket;

static uint32_t otb_protocol_create_encrypted_packet(const OtbProtocolContext *context, const void *plain_packet, uint32_t plain_packet_size, void **packet_out)
{
	GBytes *encrypted_key=NULL;
	GBytes *iv=NULL;
	unsigned char *encrypted_data=NULL;
	uint32_t encrypted_data_size=otb_asym_cipher_encrypt(context->peer_asym_cipher, plain_packet, plain_packet_size, &encrypted_key, &iv, &encrypted_data);
	uint32_t encrypted_key_size=g_bytes_get_size(encrypted_key);
	uint32_t iv_size=g_bytes_get_size(iv);
	uint32_t packet_out_size=sizeof(OtbEncryptedPacket)+encrypted_key_size+iv_size+encrypted_data_size;
	*packet_out=g_malloc(packet_out_size);
	OtbEncryptedPacket *output_packet=(OtbEncryptedPacket*)*packet_out;
	output_packet->command=COMMAND_ENCRYPTED;
	output_packet->encrypted_key_size=g_htonl(encrypted_key_size);
	output_packet->iv_size=g_htonl(iv_size);
	output_packet->encrypted_data_size=g_htonl(encrypted_data_size);
	memcpy(ENCRYPTED_PACKET_ENCRYPTED_KEY(output_packet), g_bytes_get_data(encrypted_key, NULL), encrypted_key_size);
	memcpy(ENCRYPTED_PACKET_IV(output_packet), g_bytes_get_data(iv, NULL), iv_size);
	memcpy(ENCRYPTED_PACKET_ENCRYPTED_DATA(output_packet), encrypted_data, encrypted_data_size);
	g_bytes_unref(encrypted_key);
	g_bytes_unref(iv);
	return packet_out_size;
}

uint32_t otb_protocol_decrypt_packet(OtbProtocolContext *context, const void *encrypted_input_packet, uint32_t encrypted_input_packet_size, void **decrypted_input_packet)
{
	const OtbEncryptedPacket *encrypted_packet=encrypted_input_packet;
	if(encrypted_packet->command!=COMMAND_ENCRYPTED)
		return otb_protocol_create_error_packet(context, decrypted_input_packet);
	GBytes *encrypted_key_gbytes=g_bytes_new_static(ENCRYPTED_PACKET_ENCRYPTED_KEY(encrypted_packet), g_ntohl(encrypted_packet->encrypted_key_size));
	GBytes *iv_gbytes=g_bytes_new_static(ENCRYPTED_PACKET_IV(encrypted_packet), g_ntohl(encrypted_packet->iv_size));
	uint32_t decrypted_input_packet_size=otb_asym_cipher_decrypt(context->local_asym_cipher, ENCRYPTED_PACKET_ENCRYPTED_DATA(encrypted_packet), encrypted_packet->encrypted_data_size, encrypted_key_gbytes, iv_gbytes, decrypted_input_packet);
	g_bytes_unref(iv_gbytes);
	g_bytes_unref(encrypted_key_gbytes);
	return decrypted_input_packet_size;
}

typedef struct
{
	OtbProtocolCommand command;
	OtbUniqueId unique_id;
} OtbPacketClientId;

static uint32_t otb_protocol_client_state_initial(OtbProtocolContext *context, void **packet_out)
{
	context->state=STATE_ESTABLISHING_FRIEND;
	uint32_t packet_size=sizeof(OtbPacketClientId);
	*packet_out=g_malloc(packet_size);
	OtbPacketClientId *packet=*packet_out;
	packet->command=COMMAND_SENDING_FRIEND_ID;
	OtbUniqueId *unique_id=NULL;
	g_object_get(context->local_user, OTB_USER_PROP_UNIQUE_ID, &unique_id, NULL);
	memcpy(&packet->unique_id, unique_id, sizeof(OtbUniqueId));
	g_free(unique_id);
	return packet_size;
}

#define AUTHENTICATION_MESSAGE_PACKET_TOKEN(packet)					(&(packet)+sizeof(OtbPacketAuthenticationMessage))
#define AUTHENTICATION_MESSAGE_PACKET_IS_VALID(packet, packet_size)	(sizeof(OtbPacketAuthenticationMessage)+g_ntohl((packet)->token_size)==(packet_size))

typedef struct
{
	OtbProtocolCommand command;
	uint32_t token_size;
} OtbPacketAuthenticationMessage;

static uint32_t otb_protocol_create_authentication_packet(const OtbProtocolContext *context, void **packet_out)
{
	uint32_t packet_size=sizeof(OtbPacketAuthenticationMessage)+AUTHENTICATION_TOKEN_SIZE;
	OtbPacketAuthenticationMessage *packet=g_malloc(packet_size);
	packet->command=COMMAND_SENDING_AUTHENTICATION_TOKEN;
	packet->token_size=g_htonl(AUTHENTICATION_TOKEN_SIZE);
	memcpy(AUTHENTICATION_MESSAGE_PACKET_TOKEN(packet), context->authentication_token, AUTHENTICATION_TOKEN_SIZE);
	uint32_t packet_out_size=otb_protocol_create_encrypted_packet(context, packet, packet_size, packet_out);
	g_free(packet);
	return packet_out_size;
}

static uint32_t otb_protocol_client_state_establishing_friend(OtbProtocolContext *context, const void *input_packet, uint32_t input_packet_size, void **packet_out)
{
	context->state=STATE_SERVER_AUTHENTICATION;
	OtbProtocolCommand incoming_command=*(OtbProtocolCommand*)input_packet;
	if(incoming_command==COMMAND_OK)
	{
		if(input_packet_size!=sizeof(OtbPacketClientId))
			return otb_protocol_create_error_packet(context, packet_out);
		return otb_protocol_create_authentication_packet(context, packet_out);
	}
	return otb_protocol_create_error_packet(context, packet_out);
}

#define AUTHENTICATION_MESSAGE_CHECK(context, packet)	(AUTHENTICATION_MESSAGE_PACKET_IS_VALID((OtbPacketAuthenticationMessage*)(packet), decrypted_input_packet_size) && g_ntohl(((OtbPacketAuthenticationMessage*)(packet))->token_size)==AUTHENTICATION_TOKEN_SIZE && smemcmp(context->authentication_token, AUTHENTICATION_MESSAGE_PACKET_TOKEN(packet), AUTHENTICATION_TOKEN_SIZE)==0)

static uint32_t otb_protocol_client_state_server_authentication(OtbProtocolContext *context, const void *input_packet, uint32_t input_packet_size, void **packet_out)
{
	context->state=STATE_CLIENT_REQUESTING_AUTHENTICATION;
	void *decrypted_input_packet=NULL;
	uint32_t decrypted_input_packet_size=otb_protocol_decrypt_packet(context, input_packet, input_packet_size, &decrypted_input_packet);
	OtbProtocolCommand incoming_command=*(OtbProtocolCommand*)decrypted_input_packet;
	uint32_t packet_out_size;
	if(incoming_command==COMMAND_SENDING_AUTHENTICATION_TOKEN && AUTHENTICATION_MESSAGE_CHECK(context, decrypted_input_packet))
		packet_out_size=otb_protocol_create_basic_command_packet(COMMAND_REQUESTING_AUTHENTICATION, packet_out);
	else
		packet_out_size=otb_protocol_create_error_packet(context, packet_out);
	g_free(decrypted_input_packet);
	return packet_out_size;
}

static uint32_t otb_protocol_echo_authentication_packet(OtbProtocolContext *context, const void *input_packet, uint32_t input_packet_size, void **packet_out)
{
	const OtbPacketAuthenticationMessage *packet=input_packet;
	if(AUTHENTICATION_MESSAGE_PACKET_IS_VALID(packet, input_packet_size))
		return otb_protocol_create_encrypted_packet(context, input_packet, input_packet_size, packet_out);
	return otb_protocol_create_error_packet(context, packet_out);
}

static uint32_t otb_protocol_client_state_client_requesting_authentication(OtbProtocolContext *context, const void *input_packet, uint32_t input_packet_size, void **packet_out)
{
	context->state=STATE_CLIENT_AUTHENTICATION;
	void *decrypted_input_packet=NULL;
	uint32_t decrypted_input_packet_size=otb_protocol_decrypt_packet(context, input_packet, input_packet_size, &decrypted_input_packet);
	OtbProtocolCommand incoming_command=*(OtbProtocolCommand*)decrypted_input_packet;
	uint32_t packet_out_size;
	if(incoming_command==COMMAND_SENDING_AUTHENTICATION_TOKEN)
		packet_out_size=otb_protocol_echo_authentication_packet(context, decrypted_input_packet, decrypted_input_packet_size, packet_out);
	else
		packet_out_size=otb_protocol_create_error_packet(context, packet_out);
	g_free(decrypted_input_packet);
	return packet_out_size;
}

static uint32_t otb_protocol_client_state_client_authentication(OtbProtocolContext *context, const void *input_packet, uint32_t input_packet_size, void **packet_out)
{
	context->state=STATE_CLIENT_REQUESTING_PAD_IDS_FROM_SERVER;
	OtbProtocolCommand incoming_command=*(OtbProtocolCommand*)input_packet;
	if(incoming_command==COMMAND_OK && input_packet_size==sizeof(OtbPacketClientId))
		return otb_protocol_create_basic_command_packet(COMMAND_REQUESTING_PAD_IDS, packet_out);
	return otb_protocol_create_error_packet(context, packet_out);
}

#define PAD_IDS_PACKET_PAD_ID(packet, index)			(&((OtbUniqueId*)((packet)+sizeof(OtbPacketPadIds)))[(index)])
#define PAD_IDS_PACKET_IS_VALID(packet, packet_size)	(sizeof(OtbPacketPadIds)+g_ntohl((packet)->unique_id_count)*sizeof(OtbUniqueId)==(packet_size))

typedef struct
{
	OtbProtocolCommand command;
	uint32_t unique_id_count;
} OtbPacketPadIds;

static gboolean otb_protocol_delete_missing_pad_ids(const OtbProtocolContext *context, const OtbPacketPadIds *packet, OtbPadRecStatus pad_rec_status)
{
	gboolean ret_val=TRUE;
	GSList *pad_rec_ids=otb_pad_db_get_ids_of_pads_in_status(context->pad_db, pad_rec_status);
	for(const GSList *curr_element=pad_rec_ids; ret_val && curr_element!=NULL; curr_element=(const GSList*)g_slist_next(curr_element))
	{
		const OtbUniqueId *pad_rec_id=(const OtbUniqueId*)curr_element->data;
		gboolean pad_rec_id_found_in_packet=FALSE;
		for(int packet_pad_rec_id_iter=0; !pad_rec_id_found_in_packet && packet_pad_rec_id_iter<packet->unique_id_count; packet_pad_rec_id_iter++)
			if(otb_unique_id_compare(pad_rec_id, PAD_IDS_PACKET_PAD_ID(packet, packet_pad_rec_id_iter))==0)
				pad_rec_id_found_in_packet=TRUE;
		if(!pad_rec_id_found_in_packet)
			ret_val=otb_pad_db_remove_pad(context->pad_db, pad_rec_id);
	}
	g_slist_free_full(pad_rec_ids, g_free);
	return ret_val;
}

static uint32_t otb_protocol_create_pad_ids_packet(const OtbProtocolContext *context, OtbPadRecStatus status1, OtbPadRecStatus status2, void **packet_out)
{
	GSList *pad_rec_ids=otb_pad_db_get_ids_of_pads_in_status(context->pad_db, status1);
	if(status2!=OTB_PAD_REC_STATUS_OUT_OF_BOUNDS)
	{
		GSList *pad_rec_ids2=otb_pad_db_get_ids_of_pads_in_status(context->pad_db, status2);
		pad_rec_ids=g_slist_concat(pad_rec_ids, pad_rec_ids2);
		g_slist_free(pad_rec_ids2);
	}
	uint32_t total_pad_rec_ids=g_slist_length(pad_rec_ids);
	uint32_t packet_size=sizeof(OtbPacketPadIds)+sizeof(OtbUniqueId)*total_pad_rec_ids;
	OtbPacketPadIds *packet=g_malloc(packet_size);
	packet->command=COMMAND_SENDING_PAD_IDS;
	packet->unique_id_count=g_htonl(total_pad_rec_ids);
	for(uint32_t unique_id_iter=0; unique_id_iter<total_pad_rec_ids; unique_id_iter++)
		memcpy(PAD_IDS_PACKET_PAD_ID(packet, unique_id_iter), g_slist_nth(pad_rec_ids, unique_id_iter)->data, sizeof(OtbUniqueId));
	g_slist_free_full(pad_rec_ids, g_free);
	uint32_t packet_out_size=otb_protocol_create_encrypted_packet(context, packet, packet_size, packet_out);
	g_free(packet);
	return packet_out_size;
}

static uint32_t otb_protocol_client_state_client_requesting_pad_ids_from_server(OtbProtocolContext *context, const void *input_packet, uint32_t input_packet_size, void **packet_out)
{
	context->state=STATE_CLIENT_SENDING_PAD_IDS_TO_SERVER;
	void *decrypted_input_packet=NULL;
	uint32_t decrypted_input_packet_size=otb_protocol_decrypt_packet(context, input_packet, input_packet_size, &decrypted_input_packet);
	OtbProtocolCommand incoming_command=*(OtbProtocolCommand*)decrypted_input_packet;
	uint32_t packet_out_size;
	if(incoming_command==COMMAND_SENDING_PAD_IDS && PAD_IDS_PACKET_IS_VALID((OtbPacketPadIds*)decrypted_input_packet, decrypted_input_packet_size) && otb_protocol_delete_missing_pad_ids(context, (OtbPacketPadIds*)decrypted_input_packet, OTB_PAD_REC_STATUS_SENT) && otb_protocol_delete_missing_pad_ids(context, (OtbPacketPadIds*)decrypted_input_packet, OTB_PAD_REC_STATUS_CONSUMED))
		packet_out_size=otb_protocol_create_pad_ids_packet(context, OTB_PAD_REC_STATUS_SENT, OTB_PAD_REC_STATUS_CONSUMED, packet_out);
	else
		packet_out_size=otb_protocol_create_error_packet(context, packet_out);
	g_free(decrypted_input_packet);
	return packet_out_size;
}

uint32_t otb_protocol_client(OtbProtocolContext *context, const void *input_packet, uint32_t input_packet_size, void **packet_out)
{
	if(input_packet_size<sizeof(OtbProtocolCommand) && context->state!=STATE_INITIAL)
		return otb_protocol_create_error_packet(context, packet_out);
	if(*(OtbProtocolCommand*)input_packet==COMMAND_ERROR)
	{
		context->state=STATE_FINISHED;
		return 0;
	}
	switch(context->state)
	{
		case STATE_INITIAL:
			return otb_protocol_client_state_initial(context, packet_out);
		case STATE_ESTABLISHING_FRIEND:
			return otb_protocol_client_state_establishing_friend(context, input_packet, input_packet_size, packet_out);
		case STATE_SERVER_AUTHENTICATION:
			return otb_protocol_client_state_server_authentication(context, input_packet, input_packet_size, packet_out);
		case STATE_CLIENT_REQUESTING_AUTHENTICATION:
			return otb_protocol_client_state_client_requesting_authentication(context, input_packet, input_packet_size, packet_out);
		case STATE_CLIENT_AUTHENTICATION:
			return otb_protocol_client_state_client_authentication(context, input_packet, input_packet_size, packet_out);
		case STATE_CLIENT_REQUESTING_PAD_IDS_FROM_SERVER:
			return otb_protocol_client_state_client_requesting_pad_ids_from_server(context, input_packet, input_packet_size, packet_out);
		case STATE_CLIENT_SENDING_PAD_IDS_TO_SERVER:
			// FARE...
		default:
			return otb_protocol_create_error_packet(context, packet_out);
	}
}

static uint32_t otb_protocol_server_state_initial(OtbProtocolContext *context, const void *input_packet, uint32_t input_packet_size, void **packet_out)
{
	context->state=STATE_ESTABLISHING_FRIEND;
	OtbProtocolCommand incoming_command=*(OtbProtocolCommand*)input_packet;
	if(incoming_command==COMMAND_SENDING_FRIEND_ID && input_packet_size==sizeof(OtbPacketClientId))
	{
		const OtbPacketClientId *client_id_packet=input_packet;
		OtbFriend *friend=otb_bitkeeper_get_friend(context->bitkeeper, &client_id_packet->unique_id);
		if(friend==NULL)
			return otb_protocol_create_error_packet(context, packet_out);
		context->peer_friend=friend;
		g_object_get(friend, OTB_FRIEND_PROP_PUBLIC_KEY, &context->peer_asym_cipher, NULL);
		g_object_get(friend, OTB_FRIEND_PROP_INCOMING_PADS, &context->pad_db, NULL);
		return otb_protocol_create_ok_packet(packet_out);
	}
	return otb_protocol_create_error_packet(context, packet_out);
}

static uint32_t otb_protocol_server_state_establishing_friend(OtbProtocolContext *context, const void *input_packet, uint32_t input_packet_size, void **packet_out)
{
	context->state=STATE_SERVER_AUTHENTICATION;
	void *decrypted_input_packet=NULL;
	uint32_t decrypted_input_packet_size=otb_protocol_decrypt_packet(context, input_packet, input_packet_size, &decrypted_input_packet);
	OtbProtocolCommand incoming_command=*(OtbProtocolCommand*)decrypted_input_packet;
	uint32_t packet_out_size;
	if(incoming_command==COMMAND_SENDING_AUTHENTICATION_TOKEN)
		packet_out_size=otb_protocol_echo_authentication_packet(context, decrypted_input_packet, decrypted_input_packet_size, packet_out);
	else
		packet_out_size=otb_protocol_create_error_packet(context, packet_out);
	g_free(decrypted_input_packet);
	return packet_out_size;
}

static uint32_t otb_protocol_server_state_server_authentication(OtbProtocolContext *context, const void *input_packet, uint32_t input_packet_size, void **packet_out)
{
	context->state=STATE_CLIENT_REQUESTING_AUTHENTICATION;
	OtbProtocolCommand incoming_command=*(OtbProtocolCommand*)input_packet;
	if(incoming_command==COMMAND_REQUESTING_AUTHENTICATION && input_packet_size==sizeof(OtbPacketClientId))
		return otb_protocol_create_authentication_packet(context, packet_out);
	return otb_protocol_create_error_packet(context, packet_out);
}

static uint32_t otb_protocol_server_state_client_requesting_authentication(OtbProtocolContext *context, const void *input_packet, uint32_t input_packet_size, void **packet_out)
{
	context->state=STATE_CLIENT_AUTHENTICATION;
	void *decrypted_input_packet=NULL;
	uint32_t decrypted_input_packet_size=otb_protocol_decrypt_packet(context, input_packet, input_packet_size, &decrypted_input_packet);
	OtbProtocolCommand incoming_command=*(OtbProtocolCommand*)decrypted_input_packet;
	uint32_t packet_out_size;
	if(incoming_command==COMMAND_SENDING_AUTHENTICATION_TOKEN && AUTHENTICATION_MESSAGE_CHECK(context, decrypted_input_packet))
		packet_out_size=otb_protocol_create_ok_packet(packet_out);
	else
		packet_out_size=otb_protocol_create_error_packet(context, packet_out);
	g_free(decrypted_input_packet);
	return packet_out_size;
}

static uint32_t otb_protocol_server_state_client_authentication(OtbProtocolContext *context, const void *input_packet, uint32_t input_packet_size, void **packet_out)
{
	context->state=STATE_CLIENT_REQUESTING_PAD_IDS_FROM_SERVER;
	OtbProtocolCommand incoming_command=*(OtbProtocolCommand*)input_packet;
	if(incoming_command==COMMAND_REQUESTING_PAD_IDS && input_packet_size==sizeof(OtbProtocolCommand))
		return otb_protocol_create_pad_ids_packet(context, OTB_PAD_REC_STATUS_RECEIVED, OTB_PAD_REC_STATUS_OUT_OF_BOUNDS, packet_out);
	return otb_protocol_create_error_packet(context, packet_out);
}

static uint32_t otb_protocol_server_state_client_requesting_pad_ids_from_server(OtbProtocolContext *context, const void *input_packet, uint32_t input_packet_size, void **packet_out)
{
	context->state=STATE_CLIENT_SENDING_PAD_IDS_TO_SERVER;
	void *decrypted_input_packet=NULL;
	uint32_t decrypted_input_packet_size=otb_protocol_decrypt_packet(context, input_packet, input_packet_size, &decrypted_input_packet);
	OtbProtocolCommand incoming_command=*(OtbProtocolCommand*)decrypted_input_packet;
	uint32_t packet_out_size;
	if(incoming_command==COMMAND_SENDING_PAD_IDS && PAD_IDS_PACKET_IS_VALID((OtbPacketPadIds*)decrypted_input_packet, decrypted_input_packet_size) && otb_protocol_delete_missing_pad_ids(context, (OtbPacketPadIds*)decrypted_input_packet, OTB_PAD_REC_STATUS_RECEIVED))
		packet_out_size=otb_protocol_create_ok_packet(packet_out);
	else
		packet_out_size=otb_protocol_create_error_packet(context, packet_out);
	g_free(decrypted_input_packet);
	return packet_out_size;
}

uint32_t otb_protocol_server(OtbProtocolContext *context, const void *input_packet, uint32_t input_packet_size, void **packet_out)
{
	if(*(OtbProtocolCommand*)input_packet==COMMAND_ERROR)
	{
		context->state=STATE_FINISHED;
		return 0;
	}
	switch(context->state)
	{
		case STATE_INITIAL:
			return otb_protocol_server_state_initial(context, input_packet, input_packet_size, packet_out);
		case STATE_ESTABLISHING_FRIEND:
			return otb_protocol_server_state_establishing_friend(context, input_packet, input_packet_size, packet_out);
		case STATE_SERVER_AUTHENTICATION:
			return otb_protocol_server_state_server_authentication(context, input_packet, input_packet_size, packet_out);
		case STATE_CLIENT_REQUESTING_AUTHENTICATION:
			return otb_protocol_server_state_client_requesting_authentication(context, input_packet, input_packet_size, packet_out);
		case STATE_CLIENT_AUTHENTICATION:
			return otb_protocol_server_state_client_authentication(context, input_packet, input_packet_size, packet_out);
		case STATE_CLIENT_REQUESTING_PAD_IDS_FROM_SERVER:
			return otb_protocol_server_state_client_requesting_pad_ids_from_server(context, input_packet, input_packet_size, packet_out);
		case STATE_CLIENT_SENDING_PAD_IDS_TO_SERVER:
			// FARE...
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
	g_free(context);
}
