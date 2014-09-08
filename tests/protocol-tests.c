/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <string.h>

#include "asym-cipher-tests.h"
#include "bitkeeper-tests.h"
#include "main.h"
#include "pad-db-tests.h"
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
#define EXPECTED_COMMAND_SENDING_PAD_CHUNK				10	// FARE - Ha bisogno di unit test.
#define EXPECTED_COMMAND_SENDING_FINAL_PAD_CHUNK		11
#define EXPECTED_COMMAND_UNABLE							12	// FARE - Ha bisogno di unit test.
#define EXPECTED_COMMAND_FINISH							13

static uint32_t otb_decrypt_packet(const OtbAsymCipher *peer_asym_cipher, const unsigned char* encrypted_packet, uint32_t encrypted_packet_size, unsigned char **decrypted_packet_out, size_t *decrypted_packet_buffer_size_out)
{
	g_assert_cmpint(encrypted_packet[0], ==, EXPECTED_COMMAND_ENCRYPTED);
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

static void otb_do_client_receive_unexpected_command(OtbProtocolContext *context, const OtbAsymCipher *peer_asym_cipher)
{
	uint32_t server_response_packet_size=1;
	unsigned char *server_response_packet=g_malloc(server_response_packet_size);
	server_response_packet[0]=255;
	unsigned char *client_packet=NULL;
	uint32_t client_packet_size=otb_protocol_client(context, server_response_packet, server_response_packet_size, &client_packet);
	g_assert(client_packet!=NULL);
	g_assert_cmpint(1, ==, client_packet_size);
	g_assert_cmpint(client_packet[0], ==, EXPECTED_COMMAND_ERROR);
	g_free(client_packet);
	g_free(server_response_packet);
}

static void otb_do_client_receive_malformed_packet(OtbProtocolContext *context, const OtbAsymCipher *peer_asym_cipher)
{
	uint32_t server_response_packet_size=10000;
	unsigned char *server_response_packet=g_malloc(server_response_packet_size);
	server_response_packet[0]=EXPECTED_COMMAND_OK;
	unsigned char *client_packet=NULL;
	uint32_t client_packet_size=otb_protocol_client(context, server_response_packet, server_response_packet_size, &client_packet);
	g_assert(client_packet!=NULL);
	g_assert_cmpint(1, ==, client_packet_size);
	g_assert_cmpint(client_packet[0], ==, EXPECTED_COMMAND_ERROR);
	g_free(client_packet);
	g_free(server_response_packet);
}

static void otb_do_client_establish_protocol_version(OtbProtocolContext *context, const OtbAsymCipher *peer_asym_cipher)
{
	const unsigned char EXPECTED_PROTOCOL_VERSION=0;
	
	unsigned char *client_packet=NULL;
	uint32_t client_packet_size=otb_protocol_client(context, NULL, 0, &client_packet);
	g_assert(client_packet!=NULL);
	g_assert_cmpint(2, ==, client_packet_size);
	g_assert_cmpint(EXPECTED_COMMAND_PROTOCOL_VERSION, ==, client_packet[0]);
	g_assert_cmpint(EXPECTED_PROTOCOL_VERSION, ==, client_packet[1]);
	g_free(client_packet);
}

static uint32_t otb_create_ok_packet(unsigned char **server_response_packet)
{
	const uint32_t SERVER_RESPONSE_PACKET_SIZE=1;
	
	*server_response_packet=g_malloc(SERVER_RESPONSE_PACKET_SIZE);
	*server_response_packet[0]=EXPECTED_COMMAND_OK;
	return SERVER_RESPONSE_PACKET_SIZE;
}

static void otb_do_client_establish_friend(OtbProtocolContext *context, const OtbAsymCipher *peer_asym_cipher)
{
	unsigned char *server_response_packet=NULL;
	uint32_t server_response_packet_size=otb_create_ok_packet(&server_response_packet);
	unsigned char *client_packet=NULL;
	uint32_t client_packet_size=otb_protocol_client(context, server_response_packet, server_response_packet_size, &client_packet);
	g_assert(client_packet!=NULL);
	g_assert_cmpint(17, ==, client_packet_size);
	g_assert_cmpint(client_packet[0], ==, EXPECTED_COMMAND_SENDING_FRIEND_ID);
	OtbUser *local_user=NULL;
	g_object_get(context->bitkeeper, OTB_BITKEEPER_PROP_USER, &local_user, NULL);
	g_assert(local_user!=NULL);
	OtbUniqueId *expected_friend_id=NULL;
	g_object_get(local_user, OTB_USER_PROP_UNIQUE_ID, &expected_friend_id, NULL);
	g_assert_cmpint(0, ==, memcmp(expected_friend_id, client_packet+1, 16));
	g_free(expected_friend_id);
	g_object_unref(local_user);
	g_free(client_packet);
	g_free(server_response_packet);
}

#define EXPECTED_AUTHENTICATION_TOKEN_SIZE	4096

static void otb_do_client_send_authentication_token_to_server_for_server_authentication(OtbProtocolContext *context, const OtbAsymCipher *peer_asym_cipher)
{
	unsigned char *server_response_packet=NULL;
	uint32_t server_response_packet_size=otb_create_ok_packet(&server_response_packet);
	unsigned char *encrypted_client_packet=NULL;
	uint32_t encrypted_client_packet_size=otb_protocol_client(context, server_response_packet, server_response_packet_size, &encrypted_client_packet);
	g_assert_cmpint(4157, ==, encrypted_client_packet_size);
	g_assert(encrypted_client_packet!=NULL);
	unsigned char *plain_client_packet=NULL;
	size_t plain_client_packet_buffer_size=0;
	uint32_t plain_client_packet_size=otb_decrypt_packet(peer_asym_cipher, encrypted_client_packet, encrypted_client_packet_size, &plain_client_packet, &plain_client_packet_buffer_size);
	g_assert_cmpint(4112, ==, plain_client_packet_buffer_size);
	g_assert_cmpint(5+EXPECTED_AUTHENTICATION_TOKEN_SIZE, ==, plain_client_packet_size);
	g_assert(plain_client_packet!=NULL);
	g_assert_cmpint(EXPECTED_COMMAND_SENDING_AUTHENTICATION_TOKEN, ==, plain_client_packet[0]);
	g_assert_cmpint(EXPECTED_AUTHENTICATION_TOKEN_SIZE, ==, g_ntohl(*(uint32_t*)(plain_client_packet+1)));
	g_assert_cmpint(0, ==, memcmp(context->authentication_token, plain_client_packet+5, EXPECTED_AUTHENTICATION_TOKEN_SIZE));
	otb_asym_cipher_dispose_decryption_buffer(plain_client_packet, plain_client_packet_buffer_size);
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

static uint32_t otb_create_sending_authentication_token_packet_plain(const unsigned char *authentication_token, unsigned char **packet_out)
{
	uint32_t packet_out_size=5+EXPECTED_AUTHENTICATION_TOKEN_SIZE;
	*packet_out=g_malloc(packet_out_size);
	*packet_out[0]=EXPECTED_COMMAND_SENDING_AUTHENTICATION_TOKEN;
	*(uint32_t*)(*packet_out+1)=g_htonl(EXPECTED_AUTHENTICATION_TOKEN_SIZE);
	memcpy(*packet_out+5, authentication_token, EXPECTED_AUTHENTICATION_TOKEN_SIZE);
	return packet_out_size;
}

static uint32_t otb_create_sending_authentication_token_packet_encrypted(unsigned char *authentication_token, const OtbAsymCipher *asym_cipher, unsigned char **encrypted_packet_out)
{
	unsigned char *plain_packet=NULL;
	uint32_t plain_packet_size=otb_create_sending_authentication_token_packet_plain(authentication_token, &plain_packet);
	uint32_t encrypted_packet_out_size=otb_make_encrypted_packet(asym_cipher, plain_packet, plain_packet_size, encrypted_packet_out);
	g_free(plain_packet);
	return encrypted_packet_out_size;
}

static void otb_do_client_request_authentication_from_server(OtbProtocolContext *context, const OtbAsymCipher *peer_asym_cipher)
{
	unsigned char *server_response_packet=NULL;
	uint32_t server_response_packet_size=otb_create_sending_authentication_token_packet_encrypted(context->authentication_token, context->local_asym_cipher, &server_response_packet);
	unsigned char *client_packet=NULL;
	uint32_t client_packet_size=otb_protocol_client(context, server_response_packet, server_response_packet_size, &client_packet);
	g_assert_cmpint(1, ==, client_packet_size);
	g_assert(client_packet!=NULL);
	g_assert_cmpint(EXPECTED_COMMAND_REQUESTING_AUTHENTICATION, ==, client_packet[0]);
	g_free(client_packet);
	g_free(server_response_packet);
}

static void otb_do_client_send_authentication_token_to_server_for_client_authentication(OtbProtocolContext *context, const OtbAsymCipher *peer_asym_cipher)
{
	unsigned char expected_authentication_token[EXPECTED_AUTHENTICATION_TOKEN_SIZE];
	otb_random_bytes(expected_authentication_token, EXPECTED_AUTHENTICATION_TOKEN_SIZE);
	unsigned char *server_response_packet=NULL;
	uint32_t server_response_packet_size=otb_create_sending_authentication_token_packet_encrypted(expected_authentication_token, context->local_asym_cipher, &server_response_packet);
	unsigned char *encrypted_client_packet=NULL;
	uint32_t encrypted_client_packet_size=otb_protocol_client(context, server_response_packet, server_response_packet_size, &encrypted_client_packet);
	g_assert_cmpint(4157, ==, encrypted_client_packet_size);
	g_assert(encrypted_client_packet!=NULL);
	g_assert_cmpint(EXPECTED_COMMAND_ENCRYPTED, ==, encrypted_client_packet[0]);
	unsigned char *plain_client_packet=NULL;
	size_t plain_client_packet_buffer_size=0;
	uint32_t plain_client_packet_size=otb_decrypt_packet(peer_asym_cipher, encrypted_client_packet, encrypted_client_packet_size, &plain_client_packet, &plain_client_packet_buffer_size);
	g_assert_cmpint(4112, ==, plain_client_packet_buffer_size);
	g_assert_cmpint(5+EXPECTED_AUTHENTICATION_TOKEN_SIZE, ==, plain_client_packet_size);
	g_assert_cmpint(EXPECTED_COMMAND_SENDING_AUTHENTICATION_TOKEN, ==, plain_client_packet[0]);
	g_assert_cmpint(EXPECTED_AUTHENTICATION_TOKEN_SIZE, ==, g_ntohl(*(uint32_t*)(plain_client_packet+1)));
	g_assert_cmpint(0, ==, memcmp(expected_authentication_token, plain_client_packet+5, EXPECTED_AUTHENTICATION_TOKEN_SIZE));
	otb_asym_cipher_dispose_decryption_buffer(plain_client_packet, plain_client_packet_buffer_size);
	g_free(encrypted_client_packet);
	g_free(server_response_packet);
}

static void otb_do_client_request_pad_ids_from_server(OtbProtocolContext *context, const OtbAsymCipher *peer_asym_cipher)
{
	unsigned char *server_response_packet=NULL;
	uint32_t server_response_packet_size=otb_create_ok_packet(&server_response_packet);
	unsigned char *client_packet=NULL;
	uint32_t client_packet_size=otb_protocol_client(context, server_response_packet, server_response_packet_size, &client_packet);
	g_assert(client_packet!=NULL);
	g_assert_cmpint(1, ==, client_packet_size);
	g_assert_cmpint(client_packet[0], ==, EXPECTED_COMMAND_REQUESTING_PAD_IDS);
	g_free(client_packet);
	g_free(server_response_packet);
}

static uint32_t otb_create_pad_ids_packet_plain(size_t pad_ids_count, OtbUniqueId *pad_ids[], unsigned char **packet_out)
{
	uint32_t packet_size=5+16*pad_ids_count;
	*packet_out=g_malloc(packet_size);
	*packet_out[0]=EXPECTED_COMMAND_SENDING_PAD_IDS;
	*(uint32_t*)(*packet_out+1)=g_htonl(pad_ids_count);
	for(uint32_t pad_id_iter=0; pad_id_iter<pad_ids_count; pad_id_iter++)
		memcpy(*packet_out+5+16*pad_id_iter, pad_ids[pad_id_iter], 16);
	return packet_size;
}

static uint32_t otb_create_pad_ids_packet_encrypted(const OtbProtocolContext *context, size_t pad_ids_count, OtbUniqueId *pad_ids[], unsigned char **encrypted_packet_out)
{
	unsigned char *plain_packet=NULL;
	uint32_t plain_packet_size=otb_create_pad_ids_packet_plain(pad_ids_count, pad_ids, &plain_packet);
	uint32_t encrypted_packet_out_size=otb_make_encrypted_packet(context->local_asym_cipher, plain_packet, plain_packet_size, encrypted_packet_out);
	g_free(plain_packet);
	return encrypted_packet_out_size;
}

static void otb_assert_pads_appropriate_deleted_by_client_after_server_sends_pad_ids_to_client(const OtbPadDb *outgoing_pad_db, OtbUniqueId *expected_pad_ids[2])
{
	GSList *unsent_pad_ids=otb_pad_db_get_ids_of_pads_in_status(outgoing_pad_db, OTB_PAD_REC_STATUS_UNSENT);
	g_assert_cmpint(1, ==, g_slist_length(unsent_pad_ids));
	GSList *sent_pad_ids=otb_pad_db_get_ids_of_pads_in_status(outgoing_pad_db, OTB_PAD_REC_STATUS_SENT);
	g_assert_cmpint(1, ==, g_slist_length(sent_pad_ids));
	GSList *consumed_pad_ids=otb_pad_db_get_ids_of_pads_in_status(outgoing_pad_db, OTB_PAD_REC_STATUS_CONSUMED);
	g_assert_cmpint(1, ==, g_slist_length(consumed_pad_ids));
	g_assert(memcmp(expected_pad_ids[0], sent_pad_ids->data, sizeof *expected_pad_ids[0])==0 || memcmp(expected_pad_ids[0], consumed_pad_ids->data, sizeof *expected_pad_ids[0])==0);
	g_assert(memcmp(expected_pad_ids[1], sent_pad_ids->data, sizeof *expected_pad_ids[1])==0 || memcmp(expected_pad_ids[1], consumed_pad_ids->data, sizeof *expected_pad_ids[1])==0);
	g_slist_free_full(consumed_pad_ids, g_free);
	g_slist_free_full(sent_pad_ids, g_free);
	g_slist_free_full(unsent_pad_ids, g_free);
}

static void otb_do_client_send_pad_ids_to_server(OtbProtocolContext *context, const OtbAsymCipher *peer_asym_cipher)
{
	OtbPadDb *outgoing_pad_db=NULL;
	g_object_get(context->peer_friend, OTB_FRIEND_PROP_OUTGOING_PAD_DB, &outgoing_pad_db, NULL);
	g_assert(outgoing_pad_db!=NULL);
	OtbUniqueId *expected_pad_ids[2];
	g_assert((expected_pad_ids[0]=otb_pad_db_fetch_random_rec_id(outgoing_pad_db, OTB_PAD_REC_STATUS_SENT))!=NULL);
	g_assert((expected_pad_ids[1]=otb_pad_db_fetch_random_rec_id(outgoing_pad_db, OTB_PAD_REC_STATUS_CONSUMED))!=NULL);
	unsigned char *server_response_packet=NULL;
	uint32_t server_response_packet_size=otb_create_pad_ids_packet_encrypted(context, 2, expected_pad_ids, &server_response_packet);
	unsigned char *encrypted_client_packet=NULL;
	uint32_t encrypted_client_packet_size=otb_protocol_client(context, server_response_packet, server_response_packet_size, &encrypted_client_packet);
	g_assert(encrypted_client_packet!=NULL);
	g_assert_cmpint(93, ==, encrypted_client_packet_size);
	g_assert_cmpint(EXPECTED_COMMAND_ENCRYPTED, ==, encrypted_client_packet[0]);
	unsigned char *plain_client_packet=NULL;
	size_t plain_client_packet_buffer_size=0;
	uint32_t plain_client_packet_size=otb_decrypt_packet(peer_asym_cipher, encrypted_client_packet, encrypted_client_packet_size, &plain_client_packet, &plain_client_packet_buffer_size);
	g_assert_cmpint(48, ==, plain_client_packet_buffer_size);
	g_assert_cmpint(37, ==, plain_client_packet_size);
	g_assert(plain_client_packet!=NULL);
	g_assert_cmpint(EXPECTED_COMMAND_SENDING_PAD_IDS, ==, plain_client_packet[0]);
	g_assert_cmpint(2, ==, g_ntohl(*(uint32_t*)(plain_client_packet+1)));
	g_assert(outgoing_pad_db!=NULL);
	OtbUniqueId *actual_packet_pad_id1=(OtbUniqueId*)(plain_client_packet+5);
	OtbUniqueId *actual_packet_pad_id2=(OtbUniqueId*)(plain_client_packet+21);
	g_assert(memcmp(expected_pad_ids[0], actual_packet_pad_id1, sizeof *expected_pad_ids[0])==0 || memcmp(expected_pad_ids[1], actual_packet_pad_id1, sizeof *expected_pad_ids[0])==0);
	g_assert(memcmp(expected_pad_ids[0], actual_packet_pad_id2, sizeof *expected_pad_ids[0])==0 || memcmp(expected_pad_ids[1], actual_packet_pad_id2, sizeof *expected_pad_ids[0])==0);
	otb_assert_pads_appropriate_deleted_by_client_after_server_sends_pad_ids_to_client(outgoing_pad_db, expected_pad_ids);
	otb_asym_cipher_dispose_decryption_buffer(plain_client_packet, plain_client_packet_buffer_size);
	g_free(encrypted_client_packet);
	g_free(server_response_packet);
	g_free(expected_pad_ids[0]);
	g_free(expected_pad_ids[1]);
	g_object_unref(outgoing_pad_db);
}

static void otb_do_client_send_pad_header_to_server(OtbProtocolContext *context, const OtbAsymCipher *peer_asym_cipher)
{
	OtbPadDb *outgoing_pad_db=NULL;
	g_object_get(context->peer_friend, OTB_FRIEND_PROP_OUTGOING_PAD_DB, &outgoing_pad_db, NULL);
	g_assert(outgoing_pad_db!=NULL);
	OtbUniqueId *expected_pad_id;
	g_assert((expected_pad_id=otb_pad_db_fetch_random_rec_id(outgoing_pad_db, OTB_PAD_REC_STATUS_UNSENT))!=NULL);
	unsigned char *server_response_packet=NULL;
	uint32_t server_response_packet_size=otb_create_ok_packet(&server_response_packet);
	unsigned char *encrypted_client_packet=NULL;
	uint32_t encrypted_client_packet_size=otb_protocol_client(context, server_response_packet, server_response_packet_size, &encrypted_client_packet);
	g_assert(encrypted_client_packet!=NULL);
	g_assert_cmpint(77, ==, encrypted_client_packet_size);
	g_assert_cmpint(EXPECTED_COMMAND_ENCRYPTED, ==, encrypted_client_packet[0]);
	unsigned char *plain_client_packet=NULL;
	size_t plain_client_packet_buffer_size=0;
	uint32_t plain_client_packet_size=otb_decrypt_packet(peer_asym_cipher, encrypted_client_packet, encrypted_client_packet_size, &plain_client_packet, &plain_client_packet_buffer_size);
	g_assert_cmpint(32, ==, plain_client_packet_buffer_size);
	g_assert_cmpint(21, ==, plain_client_packet_size);
	g_assert(plain_client_packet!=NULL);
	g_assert_cmpint(EXPECTED_COMMAND_SENDING_PAD_HEADER, ==, plain_client_packet[0]);
	OtbUniqueId *actual_packet_pad_id=(OtbUniqueId*)(plain_client_packet+1);
	g_assert(memcmp(expected_pad_id, actual_packet_pad_id, sizeof *expected_pad_id)==0);
	g_assert_cmpint(ABSOLUTE_MIN_PAD_SIZE, ==, g_ntohl(*(int32_t*)(plain_client_packet+17)));
	otb_asym_cipher_dispose_decryption_buffer(plain_client_packet, plain_client_packet_buffer_size);
	g_free(encrypted_client_packet);
	g_free(server_response_packet);
	g_free(expected_pad_id);
	g_object_unref(outgoing_pad_db);
}

static void otb_do_client_send_final_pad_chunk_to_server(OtbProtocolContext *context, const OtbAsymCipher *peer_asym_cipher)
{
	OtbPadDb *outgoing_pad_db=NULL;
	g_object_get(context->peer_friend, OTB_FRIEND_PROP_OUTGOING_PAD_DB, &outgoing_pad_db, NULL);
	g_assert(outgoing_pad_db!=NULL);
	OtbUniqueId *expected_pad_id;
	g_assert((expected_pad_id=otb_pad_db_fetch_random_rec_id(outgoing_pad_db, OTB_PAD_REC_STATUS_UNSENT))!=NULL);
	unsigned char *server_response_packet=NULL;
	uint32_t server_response_packet_size=otb_create_ok_packet(&server_response_packet);
	unsigned char *encrypted_client_packet=NULL;
	uint32_t encrypted_client_packet_size=otb_protocol_client(context, server_response_packet, server_response_packet_size, &encrypted_client_packet);
	g_assert(encrypted_client_packet!=NULL);
	g_assert_cmpint(1085, ==, encrypted_client_packet_size);
	g_assert_cmpint(EXPECTED_COMMAND_ENCRYPTED, ==, encrypted_client_packet[0]);
	unsigned char *plain_client_packet=NULL;
	size_t plain_client_packet_buffer_size=0;
	uint32_t plain_client_packet_size=otb_decrypt_packet(peer_asym_cipher, encrypted_client_packet, encrypted_client_packet_size, &plain_client_packet, &plain_client_packet_buffer_size);
	g_assert_cmpint(1040, ==, plain_client_packet_buffer_size);
	g_assert_cmpint(1029, ==, plain_client_packet_size);
	g_assert(plain_client_packet!=NULL);
	g_assert_cmpint(EXPECTED_COMMAND_SENDING_FINAL_PAD_CHUNK, ==, plain_client_packet[0]);
	g_assert_cmpint(ABSOLUTE_MIN_PAD_SIZE, ==, g_ntohl(*(int32_t*)(plain_client_packet+1)));
	OtbPadIO *pad_io=otb_pad_db_open_pad_for_read(outgoing_pad_db, expected_pad_id);
	unsigned char *current_plain_client_packet_byte;
	for(current_plain_client_packet_byte=plain_client_packet+5; current_plain_client_packet_byte<plain_client_packet+plain_client_packet_size && otb_pad_has_more_bytes(pad_io); current_plain_client_packet_byte++)
	{
		unsigned char expected_byte;
		g_assert(otb_pad_read_byte(pad_io, &expected_byte));
		g_assert_cmpint(expected_byte, ==, *current_plain_client_packet_byte);
	}
	g_assert(otb_pad_db_close_pad(outgoing_pad_db, pad_io));
	g_assert(plain_client_packet+plain_client_packet_size==current_plain_client_packet_byte);
	otb_asym_cipher_dispose_decryption_buffer(plain_client_packet, plain_client_packet_buffer_size);
	g_free(encrypted_client_packet);
	g_free(server_response_packet);
	g_free(expected_pad_id);
	g_object_unref(outgoing_pad_db);
}

static void otb_do_client_send_finish_to_server(OtbProtocolContext *context, const OtbAsymCipher *peer_asym_cipher)
{
	unsigned char *server_response_packet=NULL;
	uint32_t server_response_packet_size=otb_create_ok_packet(&server_response_packet);
	unsigned char *client_packet=NULL;
	uint32_t client_packet_size=otb_protocol_client(context, server_response_packet, server_response_packet_size, &client_packet);
	g_assert(client_packet!=NULL);
	g_assert_cmpint(1, ==, client_packet_size);
	g_assert_cmpint(EXPECTED_COMMAND_FINISH, ==, client_packet[0]);
	g_free(client_packet);
	g_free(server_response_packet);
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

static void otb_create_peer_for_protocol_test(OtbUniqueId **peer_id_out, OtbAsymCipher **asym_cipher_out, char **export_out)
{
	OtbBitkeeper *bitkeeper=otb_create_bitkeeper_for_protocol_test();
	OtbUser *user=NULL;
	g_object_get(bitkeeper, OTB_BITKEEPER_PROP_USER, &user, NULL);
	g_assert(user!=NULL);
	g_assert(otb_user_set_onion_base_domain(user, "ajshdjashgdsjdf"));
	g_object_get(user, OTB_USER_PROP_UNIQUE_ID, peer_id_out, OTB_USER_PROP_ASYM_CIPHER, asym_cipher_out, NULL);
	g_assert(peer_id_out!=NULL);
	g_assert(asym_cipher_out!=NULL);
	*export_out=otb_user_export(user);
	g_assert(export_out!=NULL);
	g_object_unref(user);
	g_object_unref(bitkeeper);
}

static void otb_setup_friend_pads_for_test(OtbFriend *friend, int number_of_unsent_pads, int number_of_sent_pads, int number_of_consumed_pads)
{
	OtbPadDb *outgoing_pad_db=NULL;
	g_object_get(friend, OTB_FRIEND_PROP_OUTGOING_PAD_DB, &outgoing_pad_db, NULL);
	g_assert(outgoing_pad_db!=NULL);
	g_assert(otb_pad_db_set_new_pad_min_size(outgoing_pad_db, ABSOLUTE_MIN_PAD_SIZE));
	g_assert(otb_pad_db_set_new_pad_max_size(outgoing_pad_db, ABSOLUTE_MIN_PAD_SIZE));
	for(int counter=0; counter<number_of_unsent_pads+number_of_sent_pads+number_of_consumed_pads; counter++)
		g_assert(otb_pad_db_create_unsent_pad(outgoing_pad_db));
	for(int counter=0; counter<number_of_sent_pads+number_of_consumed_pads; counter++)
	{
		OtbUniqueId *pad_id=otb_pad_db_fetch_random_rec_id(outgoing_pad_db, OTB_PAD_REC_STATUS_UNSENT);
		g_assert(pad_id!=NULL);
		g_assert(otb_pad_db_mark_pad_as_sent(outgoing_pad_db, pad_id));
		g_free(pad_id);
	}
	unsigned char *encrypted_bytes=NULL;
	size_t encrypted_bytes_size=0;
	for(int counter=0; counter<number_of_consumed_pads; counter++)
	{
		g_assert_cmpint(0, ==, otb_pad_db_encrypt(outgoing_pad_db, "", 1, &encrypted_bytes, &encrypted_bytes_size));
		g_free(encrypted_bytes);
	}
	g_object_unref(outgoing_pad_db);
}

typedef void (*protocol_test)(OtbProtocolContext *context, const OtbAsymCipher *peer_asym_cipher);

static void otb_setup_protocol_test(int number_of_unsent_pads, int number_of_sent_pads, int number_of_consumed_pads, OtbProtocolContext **context_out, OtbAsymCipher **peer_asym_cipher_out)
{
	OtbUniqueId *peer_id=NULL;
	char *peer_export=NULL;
	otb_create_peer_for_protocol_test(&peer_id, peer_asym_cipher_out, &peer_export);
	OtbBitkeeper *local_bitkeeper=otb_create_bitkeeper_for_protocol_test();
	g_assert(otb_bitkeeper_import_friend(local_bitkeeper, peer_export));
	OtbFriend *peer_friend=otb_bitkeeper_get_friend(local_bitkeeper, peer_id);
	g_assert(peer_friend!=NULL);
	otb_setup_friend_pads_for_test(peer_friend, number_of_unsent_pads, number_of_sent_pads, number_of_consumed_pads);
	*context_out=otb_protocol_context_create_client(local_bitkeeper, peer_friend);
	g_assert(*context_out!=NULL);
	g_object_unref(peer_friend);
	g_object_unref(local_bitkeeper);
	g_free(peer_export);
	g_free(peer_id);
}

static gboolean otb_run_protocol_error_injected_tests(int number_of_unsent_pads, int number_of_sent_pads, int number_of_consumed_pads, va_list *tests, protocol_test error_injection, int error_injection_point)
{
	OtbProtocolContext *context=NULL;
	OtbAsymCipher *peer_asym_cipher=NULL;
	otb_setup_protocol_test(number_of_unsent_pads, number_of_sent_pads, number_of_consumed_pads, &context, &peer_asym_cipher);
	protocol_test current_test;
	int test_count;
	for(current_test=va_arg(*tests, protocol_test), test_count=0;
	current_test!=NULL && test_count<error_injection_point;
	current_test=va_arg(*tests, protocol_test), test_count++)
		current_test(context, peer_asym_cipher);
	error_injection(context, peer_asym_cipher);
	otb_protocol_context_free(context);
	g_object_unref(peer_asym_cipher);
	return current_test!=NULL;
}

static void otb_run_protocol_tests(int number_of_unsent_pads, int number_of_sent_pads, int number_of_consumed_pads, ...)
{
	gboolean injecting_errors=TRUE;
	for(int error_injection_point=1; injecting_errors; error_injection_point++)
	{
		va_list tests;
		va_start(tests, number_of_consumed_pads);
		injecting_errors=otb_run_protocol_error_injected_tests(number_of_unsent_pads, number_of_sent_pads, number_of_consumed_pads, &tests, otb_do_client_receive_unexpected_command, error_injection_point);
		va_end(tests);
		if(injecting_errors)
		{
			va_start(tests, number_of_consumed_pads);
			otb_run_protocol_error_injected_tests(number_of_unsent_pads, number_of_sent_pads, number_of_consumed_pads, &tests, otb_do_client_receive_malformed_packet, error_injection_point);
			va_end(tests);
		}
	}
}

static void test_otb_protocol_client_no_pads()
{
	otb_run_protocol_tests(0, 2, 2, otb_do_client_establish_protocol_version, otb_do_client_establish_friend, otb_do_client_send_authentication_token_to_server_for_server_authentication, otb_do_client_request_authentication_from_server, otb_do_client_send_authentication_token_to_server_for_client_authentication, otb_do_client_request_pad_ids_from_server, otb_do_client_send_pad_ids_to_server, otb_do_client_send_finish_to_server, NULL);
}

static void test_otb_protocol_client_one_pad_one_chunk_test()
{
	otb_run_protocol_tests(1, 2, 2, otb_do_client_establish_protocol_version, otb_do_client_establish_friend, otb_do_client_send_authentication_token_to_server_for_server_authentication, otb_do_client_request_authentication_from_server, otb_do_client_send_authentication_token_to_server_for_client_authentication, otb_do_client_request_pad_ids_from_server, otb_do_client_send_pad_ids_to_server, otb_do_client_send_pad_header_to_server, otb_do_client_send_final_pad_chunk_to_server, otb_do_client_send_finish_to_server, NULL);
}

void otb_add_protocol_tests()
{
	otb_add_test_func("/protocol/test_otb_protocol_client_no_pads", test_otb_protocol_client_one_pad_one_chunk_test);
	otb_add_test_func("/protocol/test_otb_protocol_client_one_pad_one_chunk_test", test_otb_protocol_client_one_pad_one_chunk_test);
}
