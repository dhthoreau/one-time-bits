/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <stdlib.h>
#include <string.h>

#include "asym-cipher-tests.h"
#include "bitkeeper-tests.h"
#include "main.h"
#include "pad-db-tests.h"
#include "test-utils.h"
#include "../src/protocol.h"
#include "../src/random.h"

#define EXPECTED_COMMAND_PROTOCOL_VERSION				0
#define EXPECTED_COMMAND_ERROR							1
#define EXPECTED_COMMAND_OK								2
#define EXPECTED_COMMAND_ENCRYPTED						3
#define EXPECTED_COMMAND_SENDING_FRIEND_ID				4
#define EXPECTED_COMMAND_REQUESTING_AUTHENTICATION		5
#define EXPECTED_COMMAND_SENDING_AUTHENTICATION_TOKEN	6
#define EXPECTED_COMMAND_REQUESTING_PAD_IDS				7
#define EXPECTED_COMMAND_SENDING_PAD_IDS				8
#define EXPECTED_COMMAND_SENDING_PAD_HEADER				9
#define EXPECTED_COMMAND_SENDING_PAD_CHUNK				10
#define EXPECTED_COMMAND_SENDING_FINAL_PAD_CHUNK		11
#define EXPECTED_COMMAND_UNABLE							12
#define EXPECTED_COMMAND_FINISH							13

#define EXPECTED_DEFAULT_CHUNK_SIZE	10240

#define EXPECTED_EXPIRATION_SPAN	MICROSECONDS_PER_MONTH*11

typedef unsigned char ProtocolParams[6];

typedef struct
{
	unsigned char state;
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
} OtbTestProtocolContext;

#define TEST_PROTOCOL_CONTEXT(protocol_context)	((OtbTestProtocolContext*)(protocol_context))

#define CLIENT	0
#define SERVER	1

#define CLIENT_SERVER(params)		((params)[0])
#define UNSENT_PAD_COUNT(params)	((params)[1])
#define SENT_PAD_COUNT(params)		((params)[2])
#define CONSUMED_PAD_COUNT(params)	((params)[3])
#define RECEIVED_PAD_COUNT(params)	((params)[4])
#define PAD_CHUNKS(params)			((params)[5])
#define PAD_SIZE(params)			((PAD_CHUNKS(params)-1)*EXPECTED_DEFAULT_CHUNK_SIZE+1024)

static uint32_t otb_decrypt_packet(const OtbAsymCipher *peer_asym_cipher, const unsigned char* encrypted_packet, uint32_t encrypted_packet_size, unsigned char **decrypted_packet_out, size_t *decrypted_packet_buffer_size_out)
{
	g_assert_cmpint(EXPECTED_COMMAND_ENCRYPTED, ==, encrypted_packet[0]);
	uint32_t encrypted_key_size=g_ntohl(*(uint32_t*)(encrypted_packet+1));
	uint32_t iv_size=g_ntohl(*(uint32_t*)(encrypted_packet+5));
	uint32_t encrypted_data_size=g_ntohl(*(uint32_t*)(encrypted_packet+9));
	g_assert_cmpint(encrypted_packet_size, ==, 13+encrypted_key_size+iv_size+encrypted_data_size);
	GBytes *encrypted_key=g_bytes_new_static(encrypted_packet+13, encrypted_key_size);
	GBytes *iv=g_bytes_new_static(encrypted_packet+13+encrypted_key_size, iv_size);
	uint32_t decrypted_packet_size=otb_asym_cipher_decrypt(peer_asym_cipher, encrypted_packet+13+encrypted_key_size+iv_size, encrypted_data_size, encrypted_key, iv, (void**)decrypted_packet_out, decrypted_packet_buffer_size_out);
	g_assert_cmpint(0, <, decrypted_packet_size);
	g_assert(*decrypted_packet_out!=NULL);
	g_bytes_unref(iv);
	g_bytes_unref(encrypted_key);
	return decrypted_packet_size;
}

static void otb_do_client_receive_unexpected_command(const ProtocolParams params, OtbProtocolContext *protocol_context, const OtbAsymCipher *peer_asym_cipher)
{
	uint32_t server_response_packet_size=1;
	unsigned char *server_response_packet=g_malloc(server_response_packet_size);
	server_response_packet[0]=255;
	unsigned char *client_packet=NULL;
	uint32_t client_packet_size=otb_protocol_client(protocol_context, server_response_packet, server_response_packet_size, &client_packet);
	g_assert(client_packet!=NULL);
	g_assert_cmpint(1, ==, client_packet_size);
	g_assert_cmpint(client_packet[0], ==, EXPECTED_COMMAND_ERROR);
	g_free(client_packet);
	g_free(server_response_packet);
}

static void otb_do_client_receive_malformed_packet(const ProtocolParams params, OtbProtocolContext *protocol_context, const OtbAsymCipher *peer_asym_cipher)
{
	uint32_t server_response_packet_size=10000;
	unsigned char *server_response_packet=g_malloc(server_response_packet_size);
	server_response_packet[0]=EXPECTED_COMMAND_OK;
	unsigned char *client_packet=NULL;
	uint32_t client_packet_size=otb_protocol_client(protocol_context, server_response_packet, server_response_packet_size, &client_packet);
	g_assert(client_packet!=NULL);
	g_assert_cmpint(1, ==, client_packet_size);
	g_assert_cmpint(client_packet[0], ==, EXPECTED_COMMAND_ERROR);
	g_free(client_packet);
	g_free(server_response_packet);
}

static void otb_do_client_establish_protocol_version(const ProtocolParams params, OtbProtocolContext *protocol_context, const OtbAsymCipher *peer_asym_cipher)
{
	unsigned char expected_protocol_version=0;
	unsigned char *client_packet=NULL;
	uint32_t client_packet_size=otb_protocol_client(protocol_context, NULL, 0, &client_packet);
	g_assert(client_packet!=NULL);
	g_assert_cmpint(2, ==, client_packet_size);
	g_assert_cmpint(EXPECTED_COMMAND_PROTOCOL_VERSION, ==, client_packet[0]);
	g_assert_cmpint(expected_protocol_version, ==, client_packet[1]);
	g_free(client_packet);
}

static uint32_t otb_create_ok_packet(unsigned char **packet)
{
	uint32_t packet_size=1;
	*packet=g_malloc(packet_size);
	*packet[0]=EXPECTED_COMMAND_OK;
	return packet_size;
}

static void otb_do_client_establish_friend(const ProtocolParams params, OtbProtocolContext *protocol_context, const OtbAsymCipher *peer_asym_cipher)
{
	unsigned char *server_response_packet=NULL;
	uint32_t server_response_packet_size=otb_create_ok_packet(&server_response_packet);
	unsigned char *client_packet=NULL;
	uint32_t client_packet_size=otb_protocol_client(protocol_context, server_response_packet, server_response_packet_size, &client_packet);
	g_assert(client_packet!=NULL);
	g_assert_cmpint(17, ==, client_packet_size);
	g_assert_cmpint(client_packet[0], ==, EXPECTED_COMMAND_SENDING_FRIEND_ID);
	OtbUniqueId *expected_friend_unique_id=NULL;
	g_object_get(TEST_PROTOCOL_CONTEXT(protocol_context)->local_user, OTB_USER_PROP_UNIQUE_ID, &expected_friend_unique_id, NULL);
	g_assert_cmpint(0, ==, memcmp(otb_unique_id_get_bytes(expected_friend_unique_id), client_packet+1, 16));
	otb_unique_id_unref(expected_friend_unique_id);
	g_free(client_packet);
	g_free(server_response_packet);
}

#define EXPECTED_AUTHENTICATION_TOKEN_SIZE	4096

static void otb_assert_sending_authentication_token(const OtbAsymCipher *asym_cipher, unsigned char *encrypted_packet, uint32_t encrypted_packet_size, unsigned char *expected_authentication_token)
{
	g_assert(encrypted_packet!=NULL);
	g_assert_cmpint(4157, ==, encrypted_packet_size);
	unsigned char *plain_packet=NULL;
	size_t plain_packet_buffer_size=0;
	uint32_t plain_packet_size=otb_decrypt_packet(asym_cipher, encrypted_packet, encrypted_packet_size, &plain_packet, &plain_packet_buffer_size);
	g_assert_cmpint(4112, ==, plain_packet_buffer_size);
	g_assert_cmpint(5+EXPECTED_AUTHENTICATION_TOKEN_SIZE, ==, plain_packet_size);
	g_assert(plain_packet!=NULL);
	g_assert_cmpint(EXPECTED_COMMAND_SENDING_AUTHENTICATION_TOKEN, ==, plain_packet[0]);
	g_assert_cmpint(EXPECTED_AUTHENTICATION_TOKEN_SIZE, ==, g_ntohl(*(uint32_t*)(plain_packet+1)));
	g_assert_cmpint(0, ==, memcmp(expected_authentication_token, plain_packet+5, EXPECTED_AUTHENTICATION_TOKEN_SIZE));
	otb_asym_cipher_dispose_decryption_buffer(plain_packet, plain_packet_buffer_size);
}

static void otb_do_client_send_authentication_token_to_server_for_server_authentication(const ProtocolParams params, OtbProtocolContext *protocol_context, const OtbAsymCipher *peer_asym_cipher)
{
	unsigned char *server_response_packet=NULL;
	uint32_t server_response_packet_size=otb_create_ok_packet(&server_response_packet);
	unsigned char *encrypted_client_packet=NULL;
	uint32_t encrypted_client_packet_size=otb_protocol_client(protocol_context, server_response_packet, server_response_packet_size, &encrypted_client_packet);
	otb_assert_sending_authentication_token(peer_asym_cipher, encrypted_client_packet, encrypted_client_packet_size, TEST_PROTOCOL_CONTEXT(protocol_context)->authentication_token);
	g_free(encrypted_client_packet);
	g_free(server_response_packet);
}

static uint32_t otb_make_encrypted_packet(const OtbAsymCipher *asym_cipher, const unsigned char *plain_packet, uint32_t plain_packet_size, unsigned char **encrypted_packet_out)
{
	GBytes *encrypted_key=NULL;
	GBytes *iv=NULL;
	unsigned char *encrypted_data=NULL;
	uint32_t encrypted_data_size=otb_asym_cipher_encrypt(asym_cipher, plain_packet, plain_packet_size, &encrypted_key, &iv, &encrypted_data);
	uint32_t encrypted_packet_size=13+g_bytes_get_size(encrypted_key)+g_bytes_get_size(iv)+encrypted_data_size;
	*encrypted_packet_out=g_malloc(encrypted_packet_size);
	*encrypted_packet_out[0]=EXPECTED_COMMAND_ENCRYPTED;
	*(uint32_t*)(*encrypted_packet_out+1)=g_htonl(g_bytes_get_size(encrypted_key));
	*(uint32_t*)(*encrypted_packet_out+5)=g_htonl(g_bytes_get_size(iv));
	*(uint32_t*)(*encrypted_packet_out+9)=g_htonl(encrypted_data_size);
	memcpy(*encrypted_packet_out+13, g_bytes_get_data(encrypted_key, NULL), g_bytes_get_size(encrypted_key));
	memcpy(*encrypted_packet_out+13+g_bytes_get_size(encrypted_key), g_bytes_get_data(iv, NULL), g_bytes_get_size(iv));
	memcpy(*encrypted_packet_out+13+g_bytes_get_size(encrypted_key)+g_bytes_get_size(iv), encrypted_data, encrypted_data_size);
	g_bytes_unref(encrypted_key);
	g_bytes_unref(iv);
	g_free(encrypted_data);
	return encrypted_packet_size;
}

static uint32_t otb_create_sending_authentication_token_packet_plain(const ProtocolParams params, const unsigned char *authentication_token, unsigned char **packet_out)
{
	const uint32_t packet_out_size=5+EXPECTED_AUTHENTICATION_TOKEN_SIZE;
	*packet_out=g_malloc(packet_out_size);
	*packet_out[0]=EXPECTED_COMMAND_SENDING_AUTHENTICATION_TOKEN;
	*(uint32_t*)(*packet_out+1)=g_htonl(EXPECTED_AUTHENTICATION_TOKEN_SIZE);
	memcpy(*packet_out+5, authentication_token, EXPECTED_AUTHENTICATION_TOKEN_SIZE);
	return packet_out_size;
}

static uint32_t otb_create_sending_authentication_token_packet_encrypted(const ProtocolParams params, unsigned char *authentication_token, const OtbAsymCipher *asym_cipher, unsigned char **encrypted_packet_out)
{
	unsigned char *plain_packet=NULL;
	uint32_t plain_packet_size=otb_create_sending_authentication_token_packet_plain(params, authentication_token, &plain_packet);
	uint32_t encrypted_packet_out_size=otb_make_encrypted_packet(asym_cipher, plain_packet, plain_packet_size, encrypted_packet_out);
	g_free(plain_packet);
	return encrypted_packet_out_size;
}

static void otb_do_client_request_authentication_from_server(const ProtocolParams params, OtbProtocolContext *protocol_context, const OtbAsymCipher *peer_asym_cipher)
{
	unsigned char *server_response_packet=NULL;
	uint32_t server_response_packet_size=otb_create_sending_authentication_token_packet_encrypted(params, TEST_PROTOCOL_CONTEXT(protocol_context)->authentication_token, TEST_PROTOCOL_CONTEXT(protocol_context)->local_asym_cipher, &server_response_packet);
	unsigned char *client_packet=NULL;
	uint32_t client_packet_size=otb_protocol_client(protocol_context, server_response_packet, server_response_packet_size, &client_packet);
	g_assert_cmpint(1, ==, client_packet_size);
	g_assert(client_packet!=NULL);
	g_assert_cmpint(EXPECTED_COMMAND_REQUESTING_AUTHENTICATION, ==, client_packet[0]);
	g_free(client_packet);
	g_free(server_response_packet);
}

static void otb_do_client_send_authentication_token_to_server_for_client_authentication(const ProtocolParams params, OtbProtocolContext *protocol_context, const OtbAsymCipher *peer_asym_cipher)
{
	unsigned char expected_authentication_token[EXPECTED_AUTHENTICATION_TOKEN_SIZE];
	otb_random_bytes(expected_authentication_token, EXPECTED_AUTHENTICATION_TOKEN_SIZE);
	unsigned char *server_response_packet=NULL;
	uint32_t server_response_packet_size=otb_create_sending_authentication_token_packet_encrypted(params, expected_authentication_token, TEST_PROTOCOL_CONTEXT(protocol_context)->local_asym_cipher, &server_response_packet);
	unsigned char *encrypted_client_packet=NULL;
	uint32_t encrypted_client_packet_size=otb_protocol_client(protocol_context, server_response_packet, server_response_packet_size, &encrypted_client_packet);
	otb_assert_sending_authentication_token(peer_asym_cipher, encrypted_client_packet, encrypted_client_packet_size, expected_authentication_token);
	g_free(encrypted_client_packet);
	g_free(server_response_packet);
}

static void otb_do_client_request_pad_ids_from_server(const ProtocolParams params, OtbProtocolContext *protocol_context, const OtbAsymCipher *peer_asym_cipher)
{
	unsigned char *server_response_packet=NULL;
	uint32_t server_response_packet_size=otb_create_ok_packet(&server_response_packet);
	unsigned char *client_packet=NULL;
	uint32_t client_packet_size=otb_protocol_client(protocol_context, server_response_packet, server_response_packet_size, &client_packet);
	g_assert(client_packet!=NULL);
	g_assert_cmpint(1, ==, client_packet_size);
	g_assert_cmpint(client_packet[0], ==, EXPECTED_COMMAND_REQUESTING_PAD_IDS);
	g_free(client_packet);
	g_free(server_response_packet);
}

static uint32_t otb_create_pad_ids_packet_plain(GSList *pad_ids, unsigned char **packet_out)
{
	unsigned int pad_ids_count=g_slist_length(pad_ids);
	uint32_t packet_size=5+16*pad_ids_count;
	*packet_out=g_malloc(packet_size);
	*packet_out[0]=EXPECTED_COMMAND_SENDING_PAD_IDS;
	*(uint32_t*)(*packet_out+1)=g_htonl(pad_ids_count);
	for(GSList *pad_ids_iter=pad_ids; pad_ids_iter!=NULL; pad_ids_iter=g_slist_next(pad_ids_iter))
		memcpy(*packet_out+5+16*g_slist_position(pad_ids, pad_ids_iter), otb_unique_id_get_bytes(pad_ids_iter->data), 16);
	return packet_size;
}

static uint32_t otb_create_pad_ids_packet_encrypted(const OtbTestProtocolContext *protocol_context, GSList *pad_ids, unsigned char **encrypted_packet_out)
{
	unsigned char *plain_packet=NULL;
	uint32_t plain_packet_size=otb_create_pad_ids_packet_plain(pad_ids, &plain_packet);
	uint32_t encrypted_packet_out_size=otb_make_encrypted_packet(protocol_context->local_asym_cipher, plain_packet, plain_packet_size, encrypted_packet_out);
	g_free(plain_packet);
	return encrypted_packet_out_size;
}

static GSList *otb_pad_db_get_ids_of_pads_in_status_missing_one(OtbPadDb *pad_db, OtbPadRecStatus status)
{
	GSList *pad_ids=otb_pad_db_get_ids_of_pads_in_status(pad_db, status);
	size_t pad_count=g_slist_length(pad_ids);
	if(pad_count>0)
	{
		GSList *node_to_remove=g_slist_nth(pad_ids, ((size_t)rand())%g_slist_length(pad_ids));
		pad_ids=g_slist_remove_link(pad_ids, node_to_remove);
		g_slist_free_full(node_to_remove, (GDestroyNotify)otb_unique_id_unref);
	}
	return pad_ids;
}

static void otb_assert_appropriate_pads_deleted_after_receiving_pad_ids_from_peer(const ProtocolParams params, const OtbPadDb *pad_db, GSList *expected_pad_ids)
{
	GSList *unsent_pad_ids=otb_pad_db_get_ids_of_pads_in_status(pad_db, OTB_PAD_REC_STATUS_UNSENT);
	g_assert_cmpint(UNSENT_PAD_COUNT(params), ==, g_slist_length(unsent_pad_ids));
	GSList *sent_pad_ids=otb_pad_db_get_ids_of_pads_in_status(pad_db, OTB_PAD_REC_STATUS_SENT);
	g_assert_cmpint(SENT_PAD_COUNT(params)?SENT_PAD_COUNT(params)-1:0, ==, g_slist_length(sent_pad_ids));
	GSList *consumed_pad_ids=otb_pad_db_get_ids_of_pads_in_status(pad_db, OTB_PAD_REC_STATUS_CONSUMED);
	g_assert_cmpint(CONSUMED_PAD_COUNT(params)?CONSUMED_PAD_COUNT(params)-1:0, ==, g_slist_length(consumed_pad_ids));
	GSList *received_pad_ids=otb_pad_db_get_ids_of_pads_in_status(pad_db, OTB_PAD_REC_STATUS_RECEIVED);
	g_assert_cmpint(RECEIVED_PAD_COUNT(params)?RECEIVED_PAD_COUNT(params)-1:0, ==, g_slist_length(received_pad_ids));
	for(GSList *expected_pad_id_iter=expected_pad_ids; expected_pad_id_iter!=NULL; expected_pad_id_iter=g_slist_next(expected_pad_id_iter))
	{
		GSList **source_of_matched_pad_id=NULL;
		GSList *matched_pad_id_link=g_slist_find_custom(sent_pad_ids, expected_pad_id_iter->data, (GCompareFunc)otb_unique_id_compare);
		if(matched_pad_id_link!=NULL)
			source_of_matched_pad_id=&sent_pad_ids;
		else if((matched_pad_id_link=g_slist_find_custom(consumed_pad_ids, expected_pad_id_iter->data, (GCompareFunc)otb_unique_id_compare))!=NULL)
			source_of_matched_pad_id=&consumed_pad_ids;
		else if((matched_pad_id_link=g_slist_find_custom(received_pad_ids, expected_pad_id_iter->data, (GCompareFunc)otb_unique_id_compare))!=NULL)
			source_of_matched_pad_id=&received_pad_ids;
		g_assert(source_of_matched_pad_id!=NULL);
		*source_of_matched_pad_id=g_slist_remove_link(*source_of_matched_pad_id, matched_pad_id_link);
		g_slist_free_full(matched_pad_id_link, (GDestroyNotify)otb_unique_id_unref);
	}
	g_assert_cmpint(0, ==, g_slist_length(sent_pad_ids));
	g_assert_cmpint(0, ==, g_slist_length(consumed_pad_ids));
	g_assert_cmpint(0, ==, g_slist_length(received_pad_ids));
	g_slist_free_full(consumed_pad_ids, (GDestroyNotify)otb_unique_id_unref);
	g_slist_free_full(sent_pad_ids, (GDestroyNotify)otb_unique_id_unref);
	g_slist_free_full(unsent_pad_ids, (GDestroyNotify)otb_unique_id_unref);
	g_slist_free_full(received_pad_ids, (GDestroyNotify)otb_unique_id_unref);
}

static void otb_assert_pad_ids_in_packet(GSList *expected_pad_unique_ids, const unsigned char *plain_client_packet_pad_unique_id_start, unsigned int actual_packet_pad_unique_id_count)
{
	for(unsigned int actual_packet_pad_unique_id_iter=0; actual_packet_pad_unique_id_iter<actual_packet_pad_unique_id_count; actual_packet_pad_unique_id_iter++)
	{
		OtbUniqueId *actual_packet_pad_unique_id=otb_unique_id_from_bytes(plain_client_packet_pad_unique_id_start+actual_packet_pad_unique_id_iter*16);
		g_assert(g_slist_find_custom(expected_pad_unique_ids, actual_packet_pad_unique_id, (GCompareFunc)otb_unique_id_compare)!=NULL);
		otb_unique_id_unref(actual_packet_pad_unique_id);
	}
}

static void otb_do_client_send_pad_ids_to_server(const ProtocolParams params, OtbProtocolContext *protocol_context, const OtbAsymCipher *peer_asym_cipher)
{
	OtbPadDb *outgoing_pad_db=NULL;
	g_object_get(TEST_PROTOCOL_CONTEXT(protocol_context)->peer_friend, OTB_FRIEND_PROP_OUTGOING_PAD_DB, &outgoing_pad_db, NULL);
	g_assert(outgoing_pad_db!=NULL);
	GSList *expected_pad_ids=otb_pad_db_get_ids_of_pads_in_status_missing_one(outgoing_pad_db, OTB_PAD_REC_STATUS_SENT);
	expected_pad_ids=g_slist_concat(expected_pad_ids, otb_pad_db_get_ids_of_pads_in_status_missing_one(outgoing_pad_db, OTB_PAD_REC_STATUS_CONSUMED));
	size_t expected_pad_id_count=(CONSUMED_PAD_COUNT(params)?CONSUMED_PAD_COUNT(params)-1:0)+(SENT_PAD_COUNT(params)?SENT_PAD_COUNT(params)-1:0);
	size_t additional_expected_bytes=16*expected_pad_id_count;
	unsigned char *server_response_packet=NULL;
	uint32_t server_response_packet_size=otb_create_pad_ids_packet_encrypted(TEST_PROTOCOL_CONTEXT(protocol_context), expected_pad_ids, &server_response_packet);
	unsigned char *encrypted_client_packet=NULL;
	uint32_t encrypted_client_packet_size=otb_protocol_client(protocol_context, server_response_packet, server_response_packet_size, &encrypted_client_packet);
	g_assert(encrypted_client_packet!=NULL);
	unsigned char *plain_client_packet=NULL;
	size_t plain_client_packet_buffer_size=0;
	uint32_t plain_client_packet_size=otb_decrypt_packet(peer_asym_cipher, encrypted_client_packet, encrypted_client_packet_size, &plain_client_packet, &plain_client_packet_buffer_size);
	g_assert_cmpint(5+additional_expected_bytes, ==, plain_client_packet_size);
	g_assert(plain_client_packet!=NULL);
	g_assert_cmpint(EXPECTED_COMMAND_SENDING_PAD_IDS, ==, plain_client_packet[0]);
	unsigned int actual_packet_pad_id_count=g_ntohl(*(uint32_t*)(plain_client_packet+1));
	g_assert_cmpint(expected_pad_id_count, ==, actual_packet_pad_id_count);
	g_assert(outgoing_pad_db!=NULL);
	otb_assert_pad_ids_in_packet(expected_pad_ids, plain_client_packet+5, actual_packet_pad_id_count);
	otb_assert_appropriate_pads_deleted_after_receiving_pad_ids_from_peer(params, outgoing_pad_db, expected_pad_ids);
	otb_asym_cipher_dispose_decryption_buffer(plain_client_packet, plain_client_packet_buffer_size);
	g_free(encrypted_client_packet);
	g_free(server_response_packet);
	g_slist_free_full(expected_pad_ids, (GDestroyNotify)otb_unique_id_unref);
	g_object_unref(outgoing_pad_db);
}

static void otb_do_client_send_pad_header_to_server(const ProtocolParams params, OtbProtocolContext *protocol_context, const OtbAsymCipher *peer_asym_cipher)
{
	OtbPadDb *outgoing_pad_db=NULL;
	g_object_get(TEST_PROTOCOL_CONTEXT(protocol_context)->peer_friend, OTB_FRIEND_PROP_OUTGOING_PAD_DB, &outgoing_pad_db, NULL);
	g_assert(outgoing_pad_db!=NULL);
	GSList *potential_expected_pad_ids=NULL;
	g_assert((potential_expected_pad_ids=otb_pad_db_get_ids_of_pads_in_status(outgoing_pad_db, OTB_PAD_REC_STATUS_UNSENT))!=NULL);
	unsigned char *server_response_packet=NULL;
	uint32_t server_response_packet_size=otb_create_ok_packet(&server_response_packet);
	unsigned char *encrypted_client_packet=NULL;
	uint32_t encrypted_client_packet_size=otb_protocol_client(protocol_context, server_response_packet, server_response_packet_size, &encrypted_client_packet);
	g_assert(encrypted_client_packet!=NULL);
	g_assert_cmpint(85, ==, encrypted_client_packet_size);
	unsigned char *plain_client_packet=NULL;
	size_t plain_client_packet_buffer_size=0;
	uint32_t plain_client_packet_size=otb_decrypt_packet(peer_asym_cipher, encrypted_client_packet, encrypted_client_packet_size, &plain_client_packet, &plain_client_packet_buffer_size);
	g_assert_cmpint(40, ==, plain_client_packet_buffer_size);
	g_assert_cmpint(29, ==, plain_client_packet_size);
	g_assert(plain_client_packet!=NULL);
	g_assert_cmpint(EXPECTED_COMMAND_SENDING_PAD_HEADER, ==, plain_client_packet[0]);
	OtbUniqueId *actual_packet_pad_unique_id=otb_unique_id_from_bytes(plain_client_packet+1);
	GSList *potential_expected_pad_unique_id_iter=NULL;
	for(potential_expected_pad_unique_id_iter=potential_expected_pad_ids; potential_expected_pad_unique_id_iter!=NULL; potential_expected_pad_unique_id_iter=g_slist_next(potential_expected_pad_unique_id_iter))
		if(memcmp(otb_unique_id_get_bytes(potential_expected_pad_unique_id_iter->data), otb_unique_id_get_bytes(actual_packet_pad_unique_id), OTB_UNIQUE_ID_BYTES_SIZE)==0)
			break;
	g_assert(potential_expected_pad_unique_id_iter!=NULL);
	g_assert_cmpint(PAD_SIZE(params), ==, g_ntohl(*(int32_t*)(plain_client_packet+17)));
	g_assert_cmpint((g_get_real_time()+EXPECTED_EXPIRATION_SPAN)/MICROSECONDS_PER_MONTH, ==, GINT64_FROM_BE(*(int64_t*)(plain_client_packet+21))/MICROSECONDS_PER_MONTH);
	otb_asym_cipher_dispose_decryption_buffer(plain_client_packet, plain_client_packet_buffer_size);
	otb_unique_id_unref(actual_packet_pad_unique_id);
	g_free(encrypted_client_packet);
	g_free(server_response_packet);
	g_slist_free_full(potential_expected_pad_ids, (GDestroyNotify)otb_unique_id_unref);
	g_object_unref(outgoing_pad_db);
}

static void otb_do_client_receive_unable_command(const ProtocolParams params, OtbProtocolContext *protocol_context, const OtbAsymCipher *peer_asym_cipher)
{
	OtbPadDb *outgoing_pad_db=NULL;
	g_object_get(TEST_PROTOCOL_CONTEXT(protocol_context)->peer_friend, OTB_FRIEND_PROP_OUTGOING_PAD_DB, &outgoing_pad_db, NULL);
	g_assert(outgoing_pad_db!=NULL);
	uint32_t server_response_packet_size=1;
	unsigned char *server_response_packet=g_malloc(server_response_packet_size);
	server_response_packet[0]=EXPECTED_COMMAND_UNABLE;
	unsigned char *client_packet=NULL;
	uint32_t client_packet_size=otb_protocol_client(protocol_context, server_response_packet, server_response_packet_size, &client_packet);
	g_assert_cmpint(0, ==, client_packet_size);
	g_assert(client_packet==NULL);
	g_free(server_response_packet);
	g_object_unref(outgoing_pad_db);
}

static GByteArray *transmitted_pad_byte_array=NULL;

static void otb_transmit_pad_bytes_from_packet(unsigned char *plain_client_packet, uint32_t plain_client_packet_size)
{
	if(transmitted_pad_byte_array==NULL)
		transmitted_pad_byte_array=g_byte_array_new();
	g_byte_array_append(transmitted_pad_byte_array, plain_client_packet+5, plain_client_packet_size-5);
}

static void otb_do_client_send_pad_chunk_to_server(const ProtocolParams params, OtbProtocolContext *protocol_context, const OtbAsymCipher *peer_asym_cipher)
{
	OtbPadDb *outgoing_pad_db=NULL;
	g_object_get(TEST_PROTOCOL_CONTEXT(protocol_context)->peer_friend, OTB_FRIEND_PROP_OUTGOING_PAD_DB, &outgoing_pad_db, NULL);
	g_assert(outgoing_pad_db!=NULL);
	unsigned char *server_response_packet=NULL;
	uint32_t server_response_packet_size=otb_create_ok_packet(&server_response_packet);
	unsigned char *encrypted_client_packet=NULL;
	uint32_t encrypted_client_packet_size=otb_protocol_client(protocol_context, server_response_packet, server_response_packet_size, &encrypted_client_packet);
	g_assert(encrypted_client_packet!=NULL);
	g_assert_cmpint(EXPECTED_DEFAULT_CHUNK_SIZE+61, ==, encrypted_client_packet_size);
	unsigned char *plain_client_packet=NULL;
	size_t plain_client_packet_buffer_size=0;
	uint32_t plain_client_packet_size=otb_decrypt_packet(peer_asym_cipher, encrypted_client_packet, encrypted_client_packet_size, &plain_client_packet, &plain_client_packet_buffer_size);
	g_assert_cmpint(EXPECTED_DEFAULT_CHUNK_SIZE+16, ==, plain_client_packet_buffer_size);
	g_assert_cmpint(EXPECTED_DEFAULT_CHUNK_SIZE+5, ==, plain_client_packet_size);
	g_assert(plain_client_packet!=NULL);
	g_assert_cmpint(EXPECTED_COMMAND_SENDING_PAD_CHUNK, ==, plain_client_packet[0]);
	g_assert_cmpint(EXPECTED_DEFAULT_CHUNK_SIZE, ==, g_ntohl(*(int32_t*)(plain_client_packet+1)));
	otb_transmit_pad_bytes_from_packet(plain_client_packet, plain_client_packet_size);
	otb_asym_cipher_dispose_decryption_buffer(plain_client_packet, plain_client_packet_buffer_size);
	g_free(encrypted_client_packet);
	g_free(server_response_packet);
	g_object_unref(outgoing_pad_db);
}

static void otb_assert_transmitted_pad(OtbTestProtocolContext *context, OtbPadDb *pad_db)
{
	OtbPadIO *pad_io=otb_pad_db_open_pad_for_read(pad_db, context->pad_unique_id);
	const unsigned char *current_transmitted_byte;
	const unsigned char *final_transmitted_byte=transmitted_pad_byte_array->data+transmitted_pad_byte_array->len;
	for(current_transmitted_byte=transmitted_pad_byte_array->data; current_transmitted_byte<final_transmitted_byte && otb_pad_has_more_bytes(pad_io); current_transmitted_byte++)
	{
		unsigned char expected_byte;
		g_assert(otb_pad_read_byte(pad_io, &expected_byte));
		g_assert_cmpint(expected_byte, ==, *current_transmitted_byte);
	}
	g_assert(final_transmitted_byte==current_transmitted_byte);
	g_assert(otb_pad_db_close_pad(pad_db, pad_io));
	g_byte_array_unref(transmitted_pad_byte_array);
	transmitted_pad_byte_array=NULL;
}

static void otb_do_client_send_final_pad_chunk_to_server(const ProtocolParams params, OtbProtocolContext *protocol_context, const OtbAsymCipher *peer_asym_cipher)
{
	OtbPadDb *outgoing_pad_db=NULL;
	g_object_get(TEST_PROTOCOL_CONTEXT(protocol_context)->peer_friend, OTB_FRIEND_PROP_OUTGOING_PAD_DB, &outgoing_pad_db, NULL);
	g_assert(outgoing_pad_db!=NULL);
	unsigned char *server_response_packet=NULL;
	uint32_t server_response_packet_size=otb_create_ok_packet(&server_response_packet);
	unsigned char *encrypted_client_packet=NULL;
	uint32_t encrypted_client_packet_size=otb_protocol_client(protocol_context, server_response_packet, server_response_packet_size, &encrypted_client_packet);
	g_assert(encrypted_client_packet!=NULL);
	g_assert_cmpint(1085, ==, encrypted_client_packet_size);
	unsigned char *plain_client_packet=NULL;
	size_t plain_client_packet_buffer_size=0;
	uint32_t plain_client_packet_size=otb_decrypt_packet(peer_asym_cipher, encrypted_client_packet, encrypted_client_packet_size, &plain_client_packet, &plain_client_packet_buffer_size);
	g_assert_cmpint(1040, ==, plain_client_packet_buffer_size);
	g_assert_cmpint(1029, ==, plain_client_packet_size);
	g_assert(plain_client_packet!=NULL);
	g_assert_cmpint(EXPECTED_COMMAND_SENDING_FINAL_PAD_CHUNK, ==, plain_client_packet[0]);
	g_assert_cmpint(ABSOLUTE_MIN_PAD_SIZE, ==, g_ntohl(*(int32_t*)(plain_client_packet+1)));
	otb_transmit_pad_bytes_from_packet(plain_client_packet, plain_client_packet_size);
	otb_assert_transmitted_pad(TEST_PROTOCOL_CONTEXT(protocol_context), outgoing_pad_db);
	otb_asym_cipher_dispose_decryption_buffer(plain_client_packet, plain_client_packet_buffer_size);
	g_free(encrypted_client_packet);
	g_free(server_response_packet);
	g_object_unref(outgoing_pad_db);
}

static void otb_do_client_send_finish_to_server(const ProtocolParams params, OtbProtocolContext *protocol_context, const OtbAsymCipher *peer_asym_cipher)
{
	unsigned char *server_response_packet=NULL;
	uint32_t server_response_packet_size=otb_create_ok_packet(&server_response_packet);
	unsigned char *client_packet=NULL;
	uint32_t client_packet_size=otb_protocol_client(protocol_context, server_response_packet, server_response_packet_size, &client_packet);
	g_assert(client_packet!=NULL);
	g_assert_cmpint(1, ==, client_packet_size);
	g_assert_cmpint(EXPECTED_COMMAND_FINISH, ==, client_packet[0]);
	g_free(client_packet);
	g_free(server_response_packet);
}

static void otb_assert_ok(unsigned char *packet, uint32_t packet_size)
{
	g_assert(packet!=NULL);
	g_assert_cmpint(1, ==, packet_size);
	g_assert_cmpint(EXPECTED_COMMAND_OK, ==, packet[0]);
}

static void otb_do_server_establish_protocol_version(const ProtocolParams params, OtbProtocolContext *protocol_context, const OtbAsymCipher *peer_asym_cipher)
{
	unsigned char expected_protocol_version=0;
	uint32_t client_request_packet_size=2;
	unsigned char *client_request_packet=g_malloc(client_request_packet_size);
	client_request_packet[0]=EXPECTED_COMMAND_PROTOCOL_VERSION;
	client_request_packet[1]=expected_protocol_version;
	unsigned char *server_packet=NULL;
	uint32_t server_packet_size=otb_protocol_server(protocol_context, client_request_packet, client_request_packet_size, &server_packet);
	otb_assert_ok(server_packet, server_packet_size);
	g_free(server_packet);
	g_free(client_request_packet);
}

static void otb_do_server_establish_wrong_protocol_version(const ProtocolParams params, OtbProtocolContext *protocol_context, const OtbAsymCipher *peer_asym_cipher)
{
	unsigned char expected_protocol_version=1;
	uint32_t client_request_packet_size=2;
	unsigned char *client_request_packet=g_malloc(client_request_packet_size);
	client_request_packet[0]=EXPECTED_COMMAND_PROTOCOL_VERSION;
	client_request_packet[1]=expected_protocol_version;
	unsigned char *server_packet=NULL;
	uint32_t server_packet_size=otb_protocol_server(protocol_context, client_request_packet, client_request_packet_size, &server_packet);
	g_assert(server_packet!=NULL);
	g_assert_cmpint(1, ==, server_packet_size);
	g_assert_cmpint(EXPECTED_COMMAND_ERROR, ==, server_packet[0]);
	g_free(server_packet);
	g_free(client_request_packet);
}

static void otb_do_server_establish_unknown_friend(const ProtocolParams params, OtbProtocolContext *protocol_context, const OtbAsymCipher *peer_asym_cipher)
{
	unsigned char *client_request_packet=NULL;
	uint32_t client_request_packet_size=17;
	client_request_packet=g_malloc(client_request_packet_size);
	client_request_packet[0]=EXPECTED_COMMAND_SENDING_FRIEND_ID;
	uuid_generate(client_request_packet+1);
	unsigned char *server_packet=NULL;
	uint32_t server_packet_size=otb_protocol_server(protocol_context, client_request_packet, client_request_packet_size, &server_packet);
	g_assert(server_packet!=NULL);
	g_assert_cmpint(1, ==, server_packet_size);
	g_assert_cmpint(EXPECTED_COMMAND_ERROR, ==, server_packet[0]);
	g_free(server_packet);
	g_free(client_request_packet);
}

static void otb_do_server_establish_friend(const ProtocolParams params, OtbProtocolContext *protocol_context, const OtbAsymCipher *peer_asym_cipher)
{
	unsigned char *client_request_packet=NULL;
	uint32_t client_request_packet_size=17;
	client_request_packet=g_malloc(client_request_packet_size);
	client_request_packet[0]=EXPECTED_COMMAND_SENDING_FRIEND_ID;
	GSList *friend_unique_ids=NULL;
	g_assert((friend_unique_ids=otb_bitkeeper_get_unique_ids_of_friends(TEST_PROTOCOL_CONTEXT(protocol_context)->bitkeeper))!=NULL);
	OtbUniqueId *expected_friend_unique_id=friend_unique_ids->data;
	memcpy(client_request_packet+1, otb_unique_id_get_bytes(expected_friend_unique_id), 16);
	unsigned char *server_packet=NULL;
	uint32_t server_packet_size=otb_protocol_server(protocol_context, client_request_packet, client_request_packet_size, &server_packet);
	otb_assert_ok(server_packet, server_packet_size);
	g_free(server_packet);
	g_slist_free_full(friend_unique_ids, (GDestroyNotify)otb_unique_id_unref);
	g_free(client_request_packet);
}

static void otb_do_server_receive_authentication_token_from_client_for_server_authentication(const ProtocolParams params, OtbProtocolContext *protocol_context, const OtbAsymCipher *peer_asym_cipher)
{
	unsigned char expected_authentication_token[EXPECTED_AUTHENTICATION_TOKEN_SIZE];
	otb_random_bytes(expected_authentication_token, EXPECTED_AUTHENTICATION_TOKEN_SIZE);
	unsigned char *client_request_packet=NULL;
	uint32_t client_request_packet_size=otb_create_sending_authentication_token_packet_encrypted(params, expected_authentication_token, TEST_PROTOCOL_CONTEXT(protocol_context)->local_asym_cipher, &client_request_packet);
	unsigned char *encrypted_server_packet=NULL;
	uint32_t encrypted_server_packet_size=otb_protocol_server(protocol_context, client_request_packet, client_request_packet_size, &encrypted_server_packet);
	otb_assert_sending_authentication_token(peer_asym_cipher, encrypted_server_packet, encrypted_server_packet_size, expected_authentication_token);
	g_free(encrypted_server_packet);
	g_free(client_request_packet);
}

static void otb_do_server_receive_authentication_request_from_client(const ProtocolParams params, OtbProtocolContext *protocol_context, const OtbAsymCipher *peer_asym_cipher)
{
	unsigned char *client_request_packet=NULL;
	uint32_t client_request_packet_size=1;
	client_request_packet=g_malloc(client_request_packet_size);
	client_request_packet[0]=EXPECTED_COMMAND_REQUESTING_AUTHENTICATION;
	unsigned char *encrypted_server_packet=NULL;
	uint32_t encrypted_server_packet_size=otb_protocol_server(protocol_context, client_request_packet, client_request_packet_size, &encrypted_server_packet);
	otb_assert_sending_authentication_token(peer_asym_cipher, encrypted_server_packet, encrypted_server_packet_size, TEST_PROTOCOL_CONTEXT(protocol_context)->authentication_token);
	g_free(encrypted_server_packet);
	g_free(client_request_packet);
}

static void otb_do_server_receive_authentication_token_from_client_for_client_authentication(const ProtocolParams params, OtbProtocolContext *protocol_context, const OtbAsymCipher *peer_asym_cipher)
{
	unsigned char *client_request_packet=NULL;
	uint32_t client_request_packet_size=otb_create_sending_authentication_token_packet_encrypted(params, TEST_PROTOCOL_CONTEXT(protocol_context)->authentication_token, TEST_PROTOCOL_CONTEXT(protocol_context)->local_asym_cipher, &client_request_packet);
	unsigned char *server_packet=NULL;
	uint32_t server_packet_size=otb_protocol_server(protocol_context, client_request_packet, client_request_packet_size, &server_packet);
	otb_assert_ok(server_packet, server_packet_size);
	g_free(server_packet);
	g_free(client_request_packet);
}

static void otb_do_server_receive_pad_ids_request_from_client(const ProtocolParams params, OtbProtocolContext *protocol_context, const OtbAsymCipher *peer_asym_cipher)
{
	unsigned char *client_request_packet=NULL;
	uint32_t client_request_packet_size=1;
	client_request_packet=g_malloc(client_request_packet_size);
	client_request_packet[0]=EXPECTED_COMMAND_REQUESTING_PAD_IDS;
	unsigned char *encrypted_server_packet=NULL;
	uint32_t encrypted_server_packet_size=otb_protocol_server(protocol_context, client_request_packet, client_request_packet_size, &encrypted_server_packet);
	g_assert(encrypted_server_packet!=NULL);
	g_assert_cmpint(61+RECEIVED_PAD_COUNT(params)*16, ==, encrypted_server_packet_size);
	unsigned char *plain_server_packet=NULL;
	size_t plain_server_packet_buffer_size=0;
	uint32_t plain_packet_size=otb_decrypt_packet(peer_asym_cipher, encrypted_server_packet, encrypted_server_packet_size, &plain_server_packet, &plain_server_packet_buffer_size);
	g_assert_cmpint(5+RECEIVED_PAD_COUNT(params)*16, ==, plain_packet_size);
	g_assert_cmpint(EXPECTED_COMMAND_SENDING_PAD_IDS, ==, plain_server_packet[0]);
	unsigned int actual_packet_pad_id_count=g_ntohl(*(int32_t*)(plain_server_packet+1));
	g_assert_cmpint(RECEIVED_PAD_COUNT(params), ==, actual_packet_pad_id_count);
	GSList *expected_pad_ids=otb_pad_db_get_ids_of_pads_in_status(TEST_PROTOCOL_CONTEXT(protocol_context)->pad_db, OTB_PAD_REC_STATUS_RECEIVED);
	otb_assert_pad_ids_in_packet(expected_pad_ids, plain_server_packet+5, actual_packet_pad_id_count);
	g_slist_free_full(expected_pad_ids, (GDestroyNotify)otb_unique_id_unref);
	g_free(plain_server_packet);
	g_free(encrypted_server_packet);
	g_free(client_request_packet);
}

static void otb_do_server_receive_pad_ids_from_client(const ProtocolParams params, OtbProtocolContext *protocol_context, const OtbAsymCipher *peer_asym_cipher)
{
	OtbPadDb *incoming_pad_db=NULL;
	g_object_get(TEST_PROTOCOL_CONTEXT(protocol_context)->peer_friend, OTB_FRIEND_PROP_INCOMING_PAD_DB, &incoming_pad_db, NULL);
	g_assert(incoming_pad_db!=NULL);
	GSList *expected_pad_ids=otb_pad_db_get_ids_of_pads_in_status_missing_one(incoming_pad_db, OTB_PAD_REC_STATUS_RECEIVED);
	unsigned char *client_request_packet=NULL;
	uint32_t client_request_packet_size=otb_create_pad_ids_packet_encrypted(TEST_PROTOCOL_CONTEXT(protocol_context), expected_pad_ids, &client_request_packet);
	unsigned char *server_packet=NULL;
	uint32_t server_packet_size=otb_protocol_server(protocol_context, client_request_packet, client_request_packet_size, &server_packet);
	otb_assert_ok(server_packet, server_packet_size);
	otb_assert_appropriate_pads_deleted_after_receiving_pad_ids_from_peer(params, incoming_pad_db, expected_pad_ids);
	g_free(server_packet);
	g_free(client_request_packet);
	g_slist_free_full(expected_pad_ids, (GDestroyNotify)otb_unique_id_unref);
	g_object_unref(incoming_pad_db);
}

static void otb_do_server_receive_finish_from_client(const ProtocolParams params, OtbProtocolContext *protocol_context, const OtbAsymCipher *peer_asym_cipher)
{
	const size_t CLIENT_REQUEST_PACKET_SIZE=1;
	unsigned char *client_request_packet=g_malloc(CLIENT_REQUEST_PACKET_SIZE);
	*client_request_packet=EXPECTED_COMMAND_FINISH;
	unsigned char *server_packet=NULL;
	uint32_t server_packet_size=otb_protocol_server(protocol_context, client_request_packet, 1, &server_packet);
	g_assert_cmpint(0, ==, server_packet_size);
	g_assert(server_packet==NULL);
	g_free(client_request_packet);
}

static uint32_t otb_create_sending_pad_header_packet_plain(const OtbTestProtocolContext *context, off_t pad_size, unsigned char **packet_out)
{
	OtbUniqueId *pad_unique_id=otb_unique_id_new();
	uint32_t packet_out_size=29;
	*packet_out=g_malloc(packet_out_size);
	*packet_out[0]=EXPECTED_COMMAND_SENDING_PAD_HEADER;
	memcpy(*packet_out+1, otb_unique_id_get_bytes(pad_unique_id), 16);
	*(uint32_t*)(*packet_out+17)=g_htonl(pad_size);
	*(uint64_t*)(*packet_out+21)=GINT64_TO_BE(g_get_real_time()+EXPECTED_EXPIRATION_SPAN);
	otb_unique_id_unref(pad_unique_id);
	return packet_out_size;
}

static uint32_t otb_create_sending_pad_header_packet_encrypted(const OtbTestProtocolContext *protocol_context, off_t pad_size, unsigned char **encrypted_packet_out)
{
	unsigned char *plain_packet=NULL;
	uint32_t plain_packet_size=otb_create_sending_pad_header_packet_plain(protocol_context, pad_size, &plain_packet);
	uint32_t encrypted_packet_out_size=otb_make_encrypted_packet(protocol_context->local_asym_cipher, plain_packet, plain_packet_size, encrypted_packet_out);
	g_free(plain_packet);
	return encrypted_packet_out_size;
}

static void otb_do_server_receive_pad_header_too_large_from_client(const ProtocolParams params, OtbProtocolContext *protocol_context, const OtbAsymCipher *peer_asym_cipher)
{
	const off_t PAD_SIZE_TOO_LARGE=2147483647;
	unsigned char *client_request_packet=NULL;
	uint32_t client_request_packet_size=otb_create_sending_pad_header_packet_encrypted(TEST_PROTOCOL_CONTEXT(protocol_context), PAD_SIZE_TOO_LARGE, &client_request_packet);
	unsigned char *server_packet=NULL;
	uint32_t server_packet_size=otb_protocol_server(protocol_context, client_request_packet, client_request_packet_size, &server_packet);
	g_assert(server_packet!=NULL);
	g_assert_cmpint(1, ==, server_packet_size);
	g_assert_cmpint(EXPECTED_COMMAND_UNABLE, ==, server_packet[0]);
	g_free(server_packet);
	g_free(client_request_packet);
}

static void otb_do_server_receive_pad_header_from_client(const ProtocolParams params, OtbProtocolContext *protocol_context, const OtbAsymCipher *peer_asym_cipher)
{
	unsigned char *client_request_packet=NULL;
	uint32_t client_request_packet_size=otb_create_sending_pad_header_packet_encrypted(TEST_PROTOCOL_CONTEXT(protocol_context), PAD_SIZE(params), &client_request_packet);
	unsigned char *server_packet=NULL;
	uint32_t server_packet_size=otb_protocol_server(protocol_context, client_request_packet, client_request_packet_size, &server_packet);
	otb_assert_ok(server_packet, server_packet_size);
	g_free(server_packet);
	g_free(client_request_packet);
}

static uint32_t otb_create_sending_pad_chunk_packet_plain(const OtbTestProtocolContext *protocol_context, gboolean final, unsigned char **packet_out)
{
	uint32_t final_chunk_size=EXPECTED_DEFAULT_CHUNK_SIZE/(final?2:1);
	uint32_t packet_out_size=5+final_chunk_size;
	*packet_out=g_malloc(packet_out_size);
	*packet_out[0]=(final?EXPECTED_COMMAND_SENDING_FINAL_PAD_CHUNK:EXPECTED_COMMAND_SENDING_PAD_CHUNK);
	*(uint32_t*)(*packet_out+1)=g_htonl(final_chunk_size);
	otb_random_bytes(*packet_out+5, final_chunk_size);
	otb_transmit_pad_bytes_from_packet(*packet_out, packet_out_size);
	return packet_out_size;
}

static uint32_t otb_create_sending_pad_chunk_packet_encrypted(const OtbTestProtocolContext *protocol_context, gboolean final, unsigned char **encrypted_packet_out)
{
	unsigned char *plain_packet=NULL;
	uint32_t plain_packet_size=otb_create_sending_pad_chunk_packet_plain(protocol_context, final, &plain_packet);
	uint32_t encrypted_packet_out_size=otb_make_encrypted_packet(protocol_context->local_asym_cipher, plain_packet, plain_packet_size, encrypted_packet_out);
	g_free(plain_packet);
	return encrypted_packet_out_size;
}

static void otb_do_server_receive_pad_chunk_from_client(const ProtocolParams params, OtbProtocolContext *protocol_context, const OtbAsymCipher *peer_asym_cipher, gboolean final)
{
	unsigned char *client_request_packet=NULL;
	uint32_t client_request_packet_size=otb_create_sending_pad_chunk_packet_encrypted(TEST_PROTOCOL_CONTEXT(protocol_context), final, &client_request_packet);
	unsigned char *server_packet=NULL;
	uint32_t server_packet_size=otb_protocol_server(protocol_context, client_request_packet, client_request_packet_size, &server_packet);
	otb_assert_ok(server_packet, server_packet_size);
	g_free(server_packet);
	g_free(client_request_packet);
}

static void otb_do_server_receive_nonfinal_pad_chunk_from_client(const ProtocolParams params, OtbProtocolContext *protocol_context, const OtbAsymCipher *peer_asym_cipher)
{
	otb_do_server_receive_pad_chunk_from_client(params, protocol_context, peer_asym_cipher, FALSE);
}

static void otb_do_server_receive_final_pad_chunk_from_client(const ProtocolParams params, OtbProtocolContext *protocol_context, const OtbAsymCipher *peer_asym_cipher)
{
	otb_do_server_receive_pad_chunk_from_client(params, protocol_context, peer_asym_cipher, TRUE);
	otb_assert_transmitted_pad(TEST_PROTOCOL_CONTEXT(protocol_context), TEST_PROTOCOL_CONTEXT(protocol_context)->pad_db);
}

static OtbBitkeeper *otb_create_bitkeeper_for_protocol_test()
{
	OtbBitkeeper *bitkeeper=otb_create_bitkeeper_for_test();
	OtbUser *user=NULL;
	g_object_get(bitkeeper, OTB_BITKEEPER_PROP_USER, &user, NULL);
	g_assert(user!=NULL);
	OtbAsymCipher *asym_cipher=NULL;
	g_object_get(user, OTB_USER_PROP_ASYM_CIPHER, &asym_cipher, NULL);
	g_assert(asym_cipher!=NULL);
	g_object_set(asym_cipher, OTB_ASYM_CIPHER_PROP_SYM_CIPHER_NAME, "RC2-64-CBC", NULL);
	g_object_unref(asym_cipher);
	g_object_unref(user);
	return bitkeeper;
}

static void otb_create_peer_for_protocol_test(OtbUniqueId **peer_unique_id_out, OtbAsymCipher **asym_cipher_out, char **export_out)
{
	OtbBitkeeper *bitkeeper=otb_create_bitkeeper_for_protocol_test();
	OtbUser *user=NULL;
	g_object_get(bitkeeper, OTB_BITKEEPER_PROP_USER, &user, NULL);
	g_assert(user!=NULL);
	g_assert(otb_user_set_address(user, "ajshdjashgdsjdf.onion"));
	g_object_get(user, OTB_USER_PROP_UNIQUE_ID, peer_unique_id_out, OTB_USER_PROP_ASYM_CIPHER, asym_cipher_out, NULL);
	g_assert(peer_unique_id_out!=NULL);
	g_assert(asym_cipher_out!=NULL);
	*export_out=otb_user_export(user);
	g_assert(export_out!=NULL);
	g_object_unref(user);
	g_object_unref(bitkeeper);
}

static void otb_setup_friend_pads_for_test(OtbFriend *friend, const ProtocolParams params)
{
	OtbPadDb *outgoing_pad_db=NULL;
	g_object_get(friend, OTB_FRIEND_PROP_OUTGOING_PAD_DB, &outgoing_pad_db, NULL);
	g_assert(outgoing_pad_db!=NULL);
	g_assert(otb_pad_db_set_new_pad_min_size(outgoing_pad_db, PAD_SIZE(params)));
	g_assert(otb_pad_db_set_new_pad_max_size(outgoing_pad_db, PAD_SIZE(params)));
	g_assert(otb_pad_db_set_new_pad_expiration(outgoing_pad_db, EXPECTED_EXPIRATION_SPAN));
	for(int counter=0; counter<UNSENT_PAD_COUNT(params)+SENT_PAD_COUNT(params)+CONSUMED_PAD_COUNT(params); counter++)
		g_assert(otb_pad_db_create_unsent_pad(outgoing_pad_db));
	for(int counter=0; counter<SENT_PAD_COUNT(params)+CONSUMED_PAD_COUNT(params); counter++)
	{
		OtbUniqueId *pad_unique_id=otb_pad_db_fetch_random_rec_id(outgoing_pad_db, OTB_PAD_REC_STATUS_UNSENT);
		g_assert(pad_unique_id!=NULL);
		g_assert(otb_pad_db_mark_pad_as_sent(outgoing_pad_db, pad_unique_id));
		otb_unique_id_unref(pad_unique_id);
	}
	unsigned char *encrypted_bytes=NULL;
	size_t encrypted_bytes_size=0;
	for(int counter=0; counter<CONSUMED_PAD_COUNT(params); counter++)
	{
		OtbCipherContext *cipher_context=otb_cipher_context_new(outgoing_pad_db);
		g_assert_cmpint(OTB_PAD_DB_CRYPT_RESULT_SUCCESS, ==, otb_encrypt(cipher_context, TRUE, "", 1, &encrypted_bytes, &encrypted_bytes_size));
		g_free(encrypted_bytes);
		otb_cipher_context_free(cipher_context);
	}
	OtbPadDb *incoming_pad_db=NULL;
	g_object_get(friend, OTB_FRIEND_PROP_INCOMING_PAD_DB, &incoming_pad_db, NULL);
	g_assert(incoming_pad_db!=NULL);
	for(int counter=0; counter<RECEIVED_PAD_COUNT(params); counter++)
	{
		OtbUniqueId *received_pad_unique_id=otb_unique_id_new();
		long long expiration=otb_few_months_from_now();
		OtbPadIO *received_pad_io=NULL;
		g_assert((received_pad_io=otb_pad_db_add_incoming_pad(incoming_pad_db, received_pad_unique_id, PAD_SIZE(params), expiration))!=NULL);
		unsigned char *pad_bytes=otb_create_random_bytes(PAD_SIZE(params));
		g_assert(otb_pad_write(received_pad_io, pad_bytes, PAD_SIZE(params)));
		otb_pad_db_close_pad(incoming_pad_db, received_pad_io);
		otb_pad_db_mark_pad_as_received(incoming_pad_db, received_pad_unique_id);
		g_free(pad_bytes);
		otb_unique_id_unref(received_pad_unique_id);
	}
	g_object_unref(incoming_pad_db);
	g_object_unref(outgoing_pad_db);
}

typedef void (*ProtocolTestFunc)(const ProtocolParams params, OtbProtocolContext *protocol_context, const OtbAsymCipher *peer_asym_cipher);

static void otb_setup_protocol_test(const ProtocolParams params, OtbProtocolContext **context_out, OtbAsymCipher **peer_asym_cipher_out)
{
	OtbUniqueId *peer_unique_id=NULL;
	char *peer_export=NULL;
	otb_create_peer_for_protocol_test(&peer_unique_id, peer_asym_cipher_out, &peer_export);
	OtbBitkeeper *local_bitkeeper=otb_create_bitkeeper_for_protocol_test();
	g_assert(otb_bitkeeper_import_friend(local_bitkeeper, peer_export));
	OtbFriend *peer_friend=otb_bitkeeper_get_friend(local_bitkeeper, peer_unique_id);
	g_assert(peer_friend!=NULL);
	otb_setup_friend_pads_for_test(peer_friend, params);
	if(CLIENT_SERVER(params)==CLIENT)
		*context_out=otb_protocol_context_create_client(local_bitkeeper, peer_friend);
	else
		*context_out=otb_protocol_context_create_server(local_bitkeeper);
	g_assert(*context_out!=NULL);
	g_object_unref(peer_friend);
	g_object_unref(local_bitkeeper);
	g_free(peer_export);
	otb_unique_id_unref(peer_unique_id);
}

#define EXPECTED_STATE_INITIAL	0
#define EXPECTED_STATE_FINISHED	11

static gboolean otb_run_protocol_error_injected_tests(const ProtocolParams params, va_list *tests, ProtocolTestFunc error_injection_func, int error_injection_point)
{
	OtbProtocolContext *protocol_context=NULL;
	OtbAsymCipher *peer_asym_cipher=NULL;
	otb_setup_protocol_test(params, &protocol_context, &peer_asym_cipher);
	ProtocolTestFunc current_test_func;
	int test_count;
	g_assert_cmpint(EXPECTED_STATE_INITIAL, ==, TEST_PROTOCOL_CONTEXT(protocol_context)->state);
	for(current_test_func=va_arg(*tests, ProtocolTestFunc), test_count=0; current_test_func!=NULL && test_count<error_injection_point; current_test_func=va_arg(*tests, ProtocolTestFunc), test_count++)
	{
		g_assert_cmpint(EXPECTED_STATE_FINISHED, !=, TEST_PROTOCOL_CONTEXT(protocol_context)->state);
		current_test_func(params, protocol_context, peer_asym_cipher);
	}
	error_injection_func(params, protocol_context, peer_asym_cipher);
	g_assert_cmpint(EXPECTED_STATE_FINISHED, ==, TEST_PROTOCOL_CONTEXT(protocol_context)->state);
	if(transmitted_pad_byte_array!=NULL)
	{
		g_byte_array_unref(transmitted_pad_byte_array);
		transmitted_pad_byte_array=NULL;
	}
	otb_protocol_context_free(protocol_context);
	g_object_unref(peer_asym_cipher);
	return current_test_func!=NULL;
}

static void otb_run_protocol_tests(const ProtocolParams params, ...)
{
	gboolean injecting_errors=TRUE;
	for(int error_injection_point=1; injecting_errors; error_injection_point++)
	{
		va_list tests;
		va_start(tests, params);
		injecting_errors=otb_run_protocol_error_injected_tests(params, &tests, otb_do_client_receive_unexpected_command, error_injection_point);
		va_end(tests);
		if(injecting_errors)
		{
			va_start(tests, params);
			otb_run_protocol_error_injected_tests(params, &tests, otb_do_client_receive_malformed_packet, error_injection_point);
			va_end(tests);
		}
	}
}

static void test_otb_protocol_client_0_2_2_0_1()
{
	otb_run_protocol_tests((ProtocolParams){CLIENT, 0, 2, 2, 0, 1}, otb_do_client_establish_protocol_version, otb_do_client_establish_friend, otb_do_client_send_authentication_token_to_server_for_server_authentication, otb_do_client_request_authentication_from_server, otb_do_client_send_authentication_token_to_server_for_client_authentication, otb_do_client_request_pad_ids_from_server, otb_do_client_send_pad_ids_to_server, otb_do_client_send_finish_to_server, NULL);
}

static void test_otb_protocol_client_1_2_2_0_1()
{
	otb_run_protocol_tests((ProtocolParams){CLIENT, 1, 2, 2, 0, 1}, otb_do_client_establish_protocol_version, otb_do_client_establish_friend, otb_do_client_send_authentication_token_to_server_for_server_authentication, otb_do_client_request_authentication_from_server, otb_do_client_send_authentication_token_to_server_for_client_authentication, otb_do_client_request_pad_ids_from_server, otb_do_client_send_pad_ids_to_server, otb_do_client_send_pad_header_to_server, otb_do_client_send_final_pad_chunk_to_server, otb_do_client_send_finish_to_server, NULL);
}

static void test_otb_protocol_client_1_0_2_0_1()
{
	otb_run_protocol_tests((ProtocolParams){CLIENT, 1, 0, 2, 0, 1}, otb_do_client_establish_protocol_version, otb_do_client_establish_friend, otb_do_client_send_authentication_token_to_server_for_server_authentication, otb_do_client_request_authentication_from_server, otb_do_client_send_authentication_token_to_server_for_client_authentication, otb_do_client_request_pad_ids_from_server, otb_do_client_send_pad_ids_to_server, otb_do_client_send_pad_header_to_server, otb_do_client_send_final_pad_chunk_to_server, otb_do_client_send_finish_to_server, NULL);
}

static void test_otb_protocol_client_1_3_2_0_1()
{
	otb_run_protocol_tests((ProtocolParams){CLIENT, 1, 3, 2, 0, 1}, otb_do_client_establish_protocol_version, otb_do_client_establish_friend, otb_do_client_send_authentication_token_to_server_for_server_authentication, otb_do_client_request_authentication_from_server, otb_do_client_send_authentication_token_to_server_for_client_authentication, otb_do_client_request_pad_ids_from_server, otb_do_client_send_pad_ids_to_server, otb_do_client_send_pad_header_to_server, otb_do_client_send_final_pad_chunk_to_server, otb_do_client_send_finish_to_server, NULL);
}

static void test_otb_protocol_client_2_3_2_0_1()
{
	otb_run_protocol_tests((ProtocolParams){CLIENT, 2, 3, 2, 0, 1}, otb_do_client_establish_protocol_version, otb_do_client_establish_friend, otb_do_client_send_authentication_token_to_server_for_server_authentication, otb_do_client_request_authentication_from_server, otb_do_client_send_authentication_token_to_server_for_client_authentication, otb_do_client_request_pad_ids_from_server, otb_do_client_send_pad_ids_to_server, otb_do_client_send_pad_header_to_server, otb_do_client_send_final_pad_chunk_to_server, otb_do_client_send_pad_header_to_server, otb_do_client_send_final_pad_chunk_to_server, otb_do_client_send_finish_to_server, NULL);
}

static void test_otb_protocol_client_3_3_3_0_1()
{
	otb_run_protocol_tests((ProtocolParams){CLIENT, 3, 3, 3, 0, 1}, otb_do_client_establish_protocol_version, otb_do_client_establish_friend, otb_do_client_send_authentication_token_to_server_for_server_authentication, otb_do_client_request_authentication_from_server, otb_do_client_send_authentication_token_to_server_for_client_authentication, otb_do_client_request_pad_ids_from_server, otb_do_client_send_pad_ids_to_server, otb_do_client_send_pad_header_to_server, otb_do_client_send_final_pad_chunk_to_server, otb_do_client_send_pad_header_to_server, otb_do_client_send_final_pad_chunk_to_server, otb_do_client_send_pad_header_to_server, otb_do_client_send_final_pad_chunk_to_server, otb_do_client_send_finish_to_server, NULL);
}

static void test_otb_protocol_client_1_2_2_0_2()
{
	otb_run_protocol_tests((ProtocolParams){CLIENT, 1, 2, 2, 0, 2}, otb_do_client_establish_protocol_version, otb_do_client_establish_friend, otb_do_client_send_authentication_token_to_server_for_server_authentication, otb_do_client_request_authentication_from_server, otb_do_client_send_authentication_token_to_server_for_client_authentication, otb_do_client_request_pad_ids_from_server, otb_do_client_send_pad_ids_to_server, otb_do_client_send_pad_header_to_server, otb_do_client_send_pad_chunk_to_server, otb_do_client_send_final_pad_chunk_to_server, otb_do_client_send_finish_to_server, NULL);
}

static void test_otb_protocol_client_3_3_3_0_4()
{
	otb_run_protocol_tests((ProtocolParams){CLIENT, 3, 3, 3, 0, 4}, otb_do_client_establish_protocol_version, otb_do_client_establish_friend, otb_do_client_send_authentication_token_to_server_for_server_authentication, otb_do_client_request_authentication_from_server, otb_do_client_send_authentication_token_to_server_for_client_authentication, otb_do_client_request_pad_ids_from_server, otb_do_client_send_pad_ids_to_server, otb_do_client_send_pad_header_to_server, otb_do_client_send_pad_chunk_to_server, otb_do_client_send_pad_chunk_to_server, otb_do_client_send_pad_chunk_to_server, otb_do_client_send_final_pad_chunk_to_server, otb_do_client_send_pad_header_to_server, otb_do_client_send_pad_chunk_to_server, otb_do_client_send_pad_chunk_to_server, otb_do_client_send_pad_chunk_to_server, otb_do_client_send_final_pad_chunk_to_server, otb_do_client_send_pad_header_to_server, otb_do_client_send_pad_chunk_to_server, otb_do_client_send_pad_chunk_to_server, otb_do_client_send_pad_chunk_to_server, otb_do_client_send_final_pad_chunk_to_server, otb_do_client_send_finish_to_server, NULL);
}

static void test_otb_protocol_client_1_1_1_0_1_unable()
{
	otb_run_protocol_tests((ProtocolParams){CLIENT, 1, 1, 1, 0, 1}, otb_do_client_establish_protocol_version, otb_do_client_establish_friend, otb_do_client_send_authentication_token_to_server_for_server_authentication, otb_do_client_request_authentication_from_server, otb_do_client_send_authentication_token_to_server_for_client_authentication, otb_do_client_request_pad_ids_from_server, otb_do_client_send_pad_ids_to_server, otb_do_client_send_pad_header_to_server, otb_do_client_receive_unable_command, NULL);
}

static void test_otb_protocol_server_wrong_version()
{
	otb_run_protocol_tests((ProtocolParams){SERVER, 0, 0, 0, 1, 1}, otb_do_server_establish_wrong_protocol_version, NULL);
}

static void test_otb_protocol_server_unknown_friend()
{
	otb_run_protocol_tests((ProtocolParams){SERVER, 0, 0, 0, 1, 1}, otb_do_server_establish_protocol_version, otb_do_server_establish_unknown_friend, NULL);
}

static void test_otb_protocol_server_0_0_0_1_1_no_incoming()
{
	otb_run_protocol_tests((ProtocolParams){SERVER, 0, 0, 0, 1, 1}, otb_do_server_establish_protocol_version, otb_do_server_establish_friend, otb_do_server_receive_authentication_token_from_client_for_server_authentication, otb_do_server_receive_authentication_request_from_client, otb_do_server_receive_authentication_token_from_client_for_client_authentication, otb_do_server_receive_pad_ids_request_from_client, otb_do_server_receive_pad_ids_from_client, otb_do_server_receive_finish_from_client, NULL);
}

static void test_otb_protocol_server_0_0_0_1_1_too_large()
{
	otb_run_protocol_tests((ProtocolParams){SERVER, 0, 0, 0, 1, 1}, otb_do_server_establish_protocol_version, otb_do_server_establish_friend, otb_do_server_receive_authentication_token_from_client_for_server_authentication, otb_do_server_receive_authentication_request_from_client, otb_do_server_receive_authentication_token_from_client_for_client_authentication, otb_do_server_receive_pad_ids_request_from_client, otb_do_server_receive_pad_ids_from_client, otb_do_server_receive_pad_header_too_large_from_client, NULL);
}

static void test_otb_protocol_server_0_0_0_1_1_one_incoming()
{
	otb_run_protocol_tests((ProtocolParams){SERVER, 0, 0, 0, 1, 1}, otb_do_server_establish_protocol_version, otb_do_server_establish_friend, otb_do_server_receive_authentication_token_from_client_for_server_authentication, otb_do_server_receive_authentication_request_from_client, otb_do_server_receive_authentication_token_from_client_for_client_authentication, otb_do_server_receive_pad_ids_request_from_client, otb_do_server_receive_pad_ids_from_client, otb_do_server_receive_pad_header_from_client, otb_do_server_receive_final_pad_chunk_from_client, otb_do_server_receive_finish_from_client, NULL);
}

static void test_otb_protocol_server_0_0_0_1_1_four_incoming()
{
	otb_run_protocol_tests((ProtocolParams){SERVER, 0, 0, 0, 1, 1}, otb_do_server_establish_protocol_version, otb_do_server_establish_friend, otb_do_server_receive_authentication_token_from_client_for_server_authentication, otb_do_server_receive_authentication_request_from_client, otb_do_server_receive_authentication_token_from_client_for_client_authentication, otb_do_server_receive_pad_ids_request_from_client, otb_do_server_receive_pad_ids_from_client, otb_do_server_receive_pad_header_from_client, otb_do_server_receive_final_pad_chunk_from_client, otb_do_server_receive_pad_header_from_client, otb_do_server_receive_final_pad_chunk_from_client, otb_do_server_receive_pad_header_from_client, otb_do_server_receive_final_pad_chunk_from_client, otb_do_server_receive_pad_header_from_client, otb_do_server_receive_final_pad_chunk_from_client, otb_do_server_receive_finish_from_client, NULL);
}

static void test_otb_protocol_server_0_0_0_1_2_one_incoming()
{
	otb_run_protocol_tests((ProtocolParams){SERVER, 0, 0, 0, 1, 1}, otb_do_server_establish_protocol_version, otb_do_server_establish_friend, otb_do_server_receive_authentication_token_from_client_for_server_authentication, otb_do_server_receive_authentication_request_from_client, otb_do_server_receive_authentication_token_from_client_for_client_authentication, otb_do_server_receive_pad_ids_request_from_client, otb_do_server_receive_pad_ids_from_client, otb_do_server_receive_pad_header_from_client, otb_do_server_receive_nonfinal_pad_chunk_from_client, otb_do_server_receive_final_pad_chunk_from_client, otb_do_server_receive_finish_from_client, NULL);
}

static void test_otb_protocol_server_0_0_0_2_4_four_incoming()
{
	otb_run_protocol_tests((ProtocolParams){SERVER, 0, 0, 0, 2, 4}, otb_do_server_establish_protocol_version, otb_do_server_establish_friend, otb_do_server_receive_authentication_token_from_client_for_server_authentication, otb_do_server_receive_authentication_request_from_client, otb_do_server_receive_authentication_token_from_client_for_client_authentication, otb_do_server_receive_pad_ids_request_from_client, otb_do_server_receive_pad_ids_from_client,  otb_do_server_receive_pad_header_from_client, otb_do_server_receive_nonfinal_pad_chunk_from_client, otb_do_server_receive_nonfinal_pad_chunk_from_client, otb_do_server_receive_nonfinal_pad_chunk_from_client, otb_do_server_receive_final_pad_chunk_from_client, otb_do_server_receive_pad_header_from_client, otb_do_server_receive_nonfinal_pad_chunk_from_client, otb_do_server_receive_nonfinal_pad_chunk_from_client, otb_do_server_receive_nonfinal_pad_chunk_from_client, otb_do_server_receive_final_pad_chunk_from_client, otb_do_server_receive_finish_from_client, NULL);
}

static void test_otb_protocol_server_0_0_0_2_4_four_incoming_one_too_large()
{
	otb_run_protocol_tests((ProtocolParams){SERVER, 0, 0, 0, 2, 4}, otb_do_server_establish_protocol_version, otb_do_server_establish_friend, otb_do_server_receive_authentication_token_from_client_for_server_authentication, otb_do_server_receive_authentication_request_from_client, otb_do_server_receive_authentication_token_from_client_for_client_authentication, otb_do_server_receive_pad_ids_request_from_client, otb_do_server_receive_pad_ids_from_client,  otb_do_server_receive_pad_header_from_client, otb_do_server_receive_nonfinal_pad_chunk_from_client, otb_do_server_receive_nonfinal_pad_chunk_from_client, otb_do_server_receive_nonfinal_pad_chunk_from_client, otb_do_server_receive_final_pad_chunk_from_client, otb_do_server_receive_pad_header_from_client, otb_do_server_receive_nonfinal_pad_chunk_from_client, otb_do_server_receive_nonfinal_pad_chunk_from_client, otb_do_server_receive_nonfinal_pad_chunk_from_client, otb_do_server_receive_final_pad_chunk_from_client, otb_do_server_receive_pad_header_too_large_from_client, NULL);
}

static unsigned char otb_protocol_client_server;
static GMutex otb_protocol_mutex;
static GCond otb_protocol_cond;
static GPtrArray *otb_client_data_array=NULL;
static GPtrArray *otb_server_data_array=NULL;

static void otb_create_client_data_array()
{
	static const unsigned char client_data_array0[8]={0, 0, 0, 4, 3, 1, 4, 1};
	static const unsigned char client_data_array1[7]={0, 0, 0, 3, 5, 9, 2};
	static const unsigned char client_data_array2[6]={0, 0, 0, 2, 6, 5};
	static const unsigned char client_data_array3[5]={0, 0, 0, 1, 3};
	g_assert(otb_client_data_array==NULL);
	otb_client_data_array=g_ptr_array_new_full(4, (GDestroyNotify)g_bytes_unref);
	g_ptr_array_add(otb_client_data_array, g_bytes_new_static(client_data_array0, sizeof client_data_array0));
	g_ptr_array_add(otb_client_data_array, g_bytes_new_static(client_data_array1, sizeof client_data_array1));
	g_ptr_array_add(otb_client_data_array, g_bytes_new_static(client_data_array2, sizeof client_data_array2));
	g_ptr_array_add(otb_client_data_array, g_bytes_new_static(client_data_array3, sizeof client_data_array3));
}

static void otb_create_server_data_array()
{
	static const unsigned char server_data_array0[6]={0, 0, 0, 2, 1, 1};
	static const unsigned char server_data_array1[7]={0, 0, 0, 3, 2, 3, 5};
	static const unsigned char server_data_array2[9]={0, 0, 0, 5, 8, 13, 21, 34, 95};
	g_assert(otb_server_data_array==NULL);
	otb_server_data_array=g_ptr_array_new_full(3, (GDestroyNotify)g_bytes_unref);
	g_ptr_array_add(otb_server_data_array, g_bytes_new_static(server_data_array0, sizeof server_data_array0));
	g_ptr_array_add(otb_server_data_array, g_bytes_new_static(server_data_array1, sizeof server_data_array1));
	g_ptr_array_add(otb_server_data_array, g_bytes_new_static(server_data_array2, sizeof server_data_array2));
}

static void otb_create_client_server_data_arrays()
{
	otb_create_client_data_array();
	otb_create_server_data_array();
}

static void otb_free_client_server_data_arrays()
{
	g_ptr_array_unref(otb_client_data_array);
	otb_client_data_array=NULL;
	g_ptr_array_unref(otb_server_data_array);
	otb_server_data_array=NULL;
}

static void otb_let_client_continue()
{
	otb_protocol_client_server=CLIENT;
	g_cond_signal(&otb_protocol_cond);
	while(otb_protocol_client_server!=SERVER)
		g_cond_wait(&otb_protocol_cond, &otb_protocol_mutex);
}

static void otb_let_server_continue(gboolean wait)
{
	otb_protocol_client_server=SERVER;
	g_cond_signal(&otb_protocol_cond);
	while(wait && otb_protocol_client_server!=CLIENT)
		g_cond_wait(&otb_protocol_cond, &otb_protocol_mutex);
}

static void otb_truncate_output_memory_stream(const GMemoryOutputStream *memory_output_stream)
{
	g_assert(g_seekable_seek(G_SEEKABLE(memory_output_stream), 0, G_SEEK_SET, NULL, NULL));
	g_assert(g_seekable_truncate(G_SEEKABLE(memory_output_stream), 0, NULL, NULL));
}

static void otb_dummy_protocol_assert_incoming_packet(GBytes *expected_peer_data_bytes, const unsigned char *input_packet, uint32_t input_packet_size)
{
	const unsigned char *expected_peer_data=g_bytes_get_data(expected_peer_data_bytes, NULL);
	uint32_t expected_packet_size=g_htonl(*((uint32_t*)expected_peer_data));
	g_assert_cmpint(expected_packet_size, ==, input_packet_size);
	g_assert_cmpint(0, ==, memcmp(expected_peer_data+sizeof expected_packet_size, input_packet, input_packet_size));
}

static void otb_do_dummy_protocol(const unsigned char *input_packet, uint32_t input_packet_size, GBytes *expected_peer_data_bytes)
{
	if(expected_peer_data_bytes!=NULL)
		otb_dummy_protocol_assert_incoming_packet(expected_peer_data_bytes, input_packet, input_packet_size);
}

#define FIRST_DUMMY_MIDDLE_STATE	1
#define SECOND_DUMMY_MIDDLE_STATE	5
#define THIRD_DUMMY_MIDDLE_STATE	7

static uint32_t otb_dummy_client_protocol(OtbProtocolContext *protocol_context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **output_out)
{
	otb_let_server_continue(TRUE);
	GBytes *output_bytes=NULL;
	switch(TEST_PROTOCOL_CONTEXT(protocol_context)->state)
	{
		case EXPECTED_STATE_INITIAL:
		{
			otb_do_dummy_protocol(input_packet, input_packet_size, NULL);
			output_bytes=g_ptr_array_index(otb_client_data_array, 0);
			TEST_PROTOCOL_CONTEXT(protocol_context)->state=FIRST_DUMMY_MIDDLE_STATE;
			break;
		}
		case FIRST_DUMMY_MIDDLE_STATE:
		{
			otb_do_dummy_protocol(input_packet, input_packet_size, g_ptr_array_index(otb_server_data_array, 0));
			output_bytes=g_ptr_array_index(otb_client_data_array, 1);
			TEST_PROTOCOL_CONTEXT(protocol_context)->state=SECOND_DUMMY_MIDDLE_STATE;
			break;
		}
		case SECOND_DUMMY_MIDDLE_STATE:
		{
			otb_do_dummy_protocol(input_packet, input_packet_size, g_ptr_array_index(otb_server_data_array, 1));
			output_bytes=g_ptr_array_index(otb_client_data_array, 2);
			TEST_PROTOCOL_CONTEXT(protocol_context)->state=THIRD_DUMMY_MIDDLE_STATE;
			break;
		}
		case THIRD_DUMMY_MIDDLE_STATE:
		{
			otb_do_dummy_protocol(input_packet, input_packet_size, g_ptr_array_index(otb_server_data_array, 2));
			output_bytes=g_ptr_array_index(otb_client_data_array, 3);
			TEST_PROTOCOL_CONTEXT(protocol_context)->state=EXPECTED_STATE_FINISHED;
			break;
		}
		default:
		{
			g_assert_not_reached();
		}
	}
	uint32_t output_size=g_bytes_get_size(output_bytes)-sizeof(uint32_t);
	*output_out=g_malloc(output_size);
	memcpy(*output_out, g_bytes_get_data(output_bytes, NULL)+sizeof output_size, output_size);
	return output_size;
}

static uint32_t otb_dummy_server_protocol(OtbProtocolContext *protocol_context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **output_out)
{
	otb_let_client_continue();
	GBytes *output_bytes=NULL;
	switch(TEST_PROTOCOL_CONTEXT(protocol_context)->state)
	{
		case EXPECTED_STATE_INITIAL:
		{
			otb_do_dummy_protocol(input_packet, input_packet_size, g_ptr_array_index(otb_client_data_array, 0));
			output_bytes=g_ptr_array_index(otb_server_data_array, 0);
			TEST_PROTOCOL_CONTEXT(protocol_context)->state=FIRST_DUMMY_MIDDLE_STATE;
			break;
		}
		case FIRST_DUMMY_MIDDLE_STATE:
		{
			otb_do_dummy_protocol(input_packet, input_packet_size, g_ptr_array_index(otb_client_data_array, 1));
			output_bytes=g_ptr_array_index(otb_server_data_array, 1);
			TEST_PROTOCOL_CONTEXT(protocol_context)->state=SECOND_DUMMY_MIDDLE_STATE;
			break;
		}
		case SECOND_DUMMY_MIDDLE_STATE:
		{
			otb_do_dummy_protocol(input_packet, input_packet_size, g_ptr_array_index(otb_client_data_array, 2));
			output_bytes=g_ptr_array_index(otb_server_data_array, 2);
			TEST_PROTOCOL_CONTEXT(protocol_context)->state=THIRD_DUMMY_MIDDLE_STATE;
			break;
		}
		case THIRD_DUMMY_MIDDLE_STATE:
		{
			otb_do_dummy_protocol(input_packet, input_packet_size, g_ptr_array_index(otb_client_data_array, 3));
			TEST_PROTOCOL_CONTEXT(protocol_context)->state=EXPECTED_STATE_FINISHED;
			break;
		}
		default:
		{
			g_assert_not_reached();
		}
	}
	uint32_t output_size=(output_bytes==NULL?0:g_bytes_get_size(output_bytes)-sizeof(uint32_t));
	*output_out=(output_size==0?NULL:g_malloc(output_size));
	if(output_size>0)
		memcpy(*output_out, g_bytes_get_data(output_bytes, NULL)+sizeof output_size, output_size);
	return output_size;
}

static void otb_dummy_io_thread_fill_response_buffer(GMemoryInputStream *memory_input_stream, const GPtrArray *local_data_array, off_t iteration)
{
	if(iteration<local_data_array->len)
		g_memory_input_stream_add_bytes(memory_input_stream, g_ptr_array_index(local_data_array, iteration));
}

static void otb_dummy_io_thread_prep_iteration(const GPtrArray *memory_io_streams, const GPtrArray *local_data_array, off_t iteration)
{
	otb_dummy_io_thread_fill_response_buffer(G_MEMORY_INPUT_STREAM(g_ptr_array_index(memory_io_streams, 0)), local_data_array, iteration);
	otb_truncate_output_memory_stream(G_MEMORY_OUTPUT_STREAM(g_ptr_array_index(memory_io_streams, 1)));
}

static void otb_dummy_io_thread_process_peer_incoming_data(GMemoryOutputStream *memory_output_stream, GBytes *peer_bytes)
{
	if(peer_bytes!=NULL)
	{
		unsigned int data_size=g_bytes_get_size(peer_bytes);
		g_assert_cmpint(g_memory_output_stream_get_data_size(memory_output_stream), ==, data_size);
		g_assert_cmpint(0, ==, memcmp(g_bytes_get_data(peer_bytes, NULL), g_memory_output_stream_get_data(memory_output_stream), data_size));
	}
}

static void *otb_dummy_server_io_thread(const GPtrArray *memory_io_streams)
{
	g_mutex_lock(&otb_protocol_mutex);
	for(off_t iteration=0; iteration<otb_client_data_array->len; iteration++)
	{
		otb_dummy_io_thread_prep_iteration(memory_io_streams, otb_server_data_array, iteration);
		otb_let_client_continue();
		otb_dummy_io_thread_process_peer_incoming_data(G_MEMORY_OUTPUT_STREAM(g_ptr_array_index(memory_io_streams, 1)), iteration<otb_client_data_array->len?g_ptr_array_index(otb_client_data_array, iteration):NULL);
	}
	g_mutex_unlock(&otb_protocol_mutex);
	return NULL;
}

static void *otb_dummy_client_io_thread(const GPtrArray *memory_io_streams)
{
	g_mutex_lock(&otb_protocol_mutex);
	for(off_t iteration=0; iteration<otb_client_data_array->len; iteration++)
	{
		otb_dummy_io_thread_prep_iteration(memory_io_streams, otb_client_data_array, iteration);
		otb_let_server_continue(TRUE);
		otb_dummy_io_thread_process_peer_incoming_data(G_MEMORY_OUTPUT_STREAM(g_ptr_array_index(memory_io_streams, 1)), iteration>0?g_ptr_array_index(otb_server_data_array, iteration-1):NULL);
	}
	otb_let_server_continue(FALSE);
	g_mutex_unlock(&otb_protocol_mutex);
	return NULL;
}

static GPtrArray *otb_create_memory_io_streams()
{
	GPtrArray *memory_io_streams=g_ptr_array_new_full(2, g_object_unref);
	g_ptr_array_add(memory_io_streams, g_memory_input_stream_new());
	g_ptr_array_add(memory_io_streams, g_memory_output_stream_new_resizable());
	return memory_io_streams;
}

static void otb_protocol_execution_test(unsigned char client_server, GThreadFunc dummy_io_func, ProtocolFunc protocol_func)
{
	otb_create_client_server_data_arrays();
	otb_protocol_client_server=CLIENT;
	OtbProtocolContext *protocol_context=NULL;
	OtbAsymCipher *peer_asym_cipher=NULL;
	otb_setup_protocol_test((ProtocolParams){client_server, 0, 0, 0, 0, 1}, &protocol_context, &peer_asym_cipher);
	GPtrArray *memory_io_streams=otb_create_memory_io_streams();
	g_mutex_lock(&otb_protocol_mutex);
	GThread *dummy_io_thread=g_thread_new("DummyPeerIO", dummy_io_func, memory_io_streams);
	if(client_server==SERVER)
		otb_let_client_continue();
	otb_protocol_execute(protocol_context, protocol_func, g_ptr_array_index(memory_io_streams, 0), g_ptr_array_index(memory_io_streams, 1), client_server==CLIENT);
	if(client_server==CLIENT)
		otb_let_server_continue(FALSE);
	g_mutex_unlock(&otb_protocol_mutex);
	g_thread_join(dummy_io_thread);
	g_ptr_array_unref(memory_io_streams);
	otb_protocol_context_free(protocol_context);
	g_object_unref(peer_asym_cipher);
	otb_free_client_server_data_arrays();
}

static void test_otb_protocol_client_execution()
{
	otb_protocol_execution_test(CLIENT, (GThreadFunc)otb_dummy_server_io_thread, otb_dummy_client_protocol);
}

static void test_otb_protocol_server_execution()
{
	otb_protocol_execution_test(SERVER, (GThreadFunc)otb_dummy_client_io_thread, otb_dummy_server_protocol);
}

void otb_add_protocol_tests()
{
	otb_add_test_func("/protocol/test_otb_protocol_client_0_2_2_0_1", test_otb_protocol_client_0_2_2_0_1);
	otb_add_test_func("/protocol/test_otb_protocol_client_1_2_2_0_1", test_otb_protocol_client_1_2_2_0_1);
	otb_add_test_func("/protocol/test_otb_protocol_client_1_0_2_0_1", test_otb_protocol_client_1_0_2_0_1);
	otb_add_test_func("/protocol/test_otb_protocol_client_1_3_2_0_1", test_otb_protocol_client_1_3_2_0_1);
	otb_add_test_func("/protocol/test_otb_protocol_client_2_3_2_0_1", test_otb_protocol_client_2_3_2_0_1);
	otb_add_test_func("/protocol/test_otb_protocol_client_3_3_3_0_1", test_otb_protocol_client_3_3_3_0_1);
	otb_add_test_func("/protocol/test_otb_protocol_client_1_2_2_0_2", test_otb_protocol_client_1_2_2_0_2);
	otb_add_test_func("/protocol/test_otb_protocol_client_3_3_3_0_4", test_otb_protocol_client_3_3_3_0_4);
	otb_add_test_func("/protocol/test_otb_protocol_client_1_1_1_0_1_unable", test_otb_protocol_client_1_1_1_0_1_unable);
	otb_add_test_func("/protocol/test_otb_protocol_server_wrong_version", test_otb_protocol_server_wrong_version);
	otb_add_test_func("/protocol/test_otb_protocol_server_unknown_friend", test_otb_protocol_server_unknown_friend);
	otb_add_test_func("/protocol/test_otb_protocol_server_0_0_0_1_1_no_incoming", test_otb_protocol_server_0_0_0_1_1_no_incoming);
	otb_add_test_func("/protocol/test_otb_protocol_server_0_0_0_1_1_too_large", test_otb_protocol_server_0_0_0_1_1_too_large);
	otb_add_test_func("/protocol/test_otb_protocol_server_0_0_0_1_1_one_incoming", test_otb_protocol_server_0_0_0_1_1_one_incoming);
	otb_add_test_func("/protocol/test_otb_protocol_server_0_0_0_1_1_four_incoming", test_otb_protocol_server_0_0_0_1_1_four_incoming);
	otb_add_test_func("/protocol/test_otb_protocol_server_0_0_0_1_2_one_incoming", test_otb_protocol_server_0_0_0_1_2_one_incoming);
	otb_add_test_func("/protocol/test_otb_protocol_server_0_0_0_2_4_four_incoming", test_otb_protocol_server_0_0_0_2_4_four_incoming);
	otb_add_test_func("/protocol/test_otb_protocol_server_0_0_0_2_4_four_incoming_one_too_large", test_otb_protocol_server_0_0_0_2_4_four_incoming_one_too_large);
	otb_add_test_func("/protocol/test_otb_protocol_client_execution", test_otb_protocol_client_execution);
	otb_add_test_func("/protocol/test_otb_protocol_server_execution", test_otb_protocol_server_execution);
}
