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
#include "../src/protocol.h"

#define EXPECTED_COMMAND_PROTOCOL_VERSION				0
#define EXPECTED_COMMAND_ERROR							1
#define EXPECTED_COMMAND_OK								2
#define EXPECTED_COMMAND_ENCRYPTED						3
#define EXPECTED_COMMAND_SENDING_FRIEND_ID				4
#define EXPECTED_COMMAND_REQUESTING_AUTHENTICATION		5
#define EXPECTED_COMMAND_SENDING_AUTHENTICATION_TOKEN	6
#define EXPECTED_COMMAND_REQUESTING_PAD_IDS				7
#define EXPECTED_COMMAND_SENDING_PAD_IDS				8

static unsigned char otb_random_non_error_command(unsigned char except_command)
{
	unsigned char random_command=rand()%9;
	while(random_command==except_command || random_command==EXPECTED_COMMAND_ERROR)
		random_command=(random_command+1)%9;
	return random_command;
}

static uint32_t otb_decrypt_packet(const OtbAsymCipher *peer_asym_cipher, const unsigned char* encrypted_packet, uint32_t encrypted_packet_size, unsigned char **decrypted_packet_out)
{
	g_assert_cmpint(encrypted_packet[0], ==, EXPECTED_COMMAND_ENCRYPTED);
	uint32_t encrypted_key_size=g_ntohl(*(uint32_t*)(encrypted_packet+1));
	uint32_t iv_size=g_ntohl(*(uint32_t*)(encrypted_packet+5));
	uint32_t encrypted_data_size=g_ntohl(*(uint32_t*)(encrypted_packet+9));
	g_assert_cmpint(encrypted_packet_size, ==, 13+encrypted_key_size+iv_size+encrypted_data_size);
	GBytes *encrypted_key=g_bytes_new_static(encrypted_packet+13, encrypted_key_size);
	GBytes *iv=g_bytes_new_static(encrypted_packet+13+encrypted_key_size, iv_size);
	uint32_t decrypted_packet_size=otb_asym_cipher_decrypt(peer_asym_cipher, encrypted_packet+13+encrypted_key_size+iv_size, encrypted_data_size, encrypted_key, iv, (void**)decrypted_packet_out);
	g_assert_cmpint(0, <, decrypted_packet_size);
	g_assert(*decrypted_packet_out!=NULL);
	g_bytes_unref(iv);
	g_bytes_unref(encrypted_key);
	return decrypted_packet_size;
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

static void otb_do_client_establish_protocol_version(OtbProtocolContext *context, const OtbBitkeeper *local_bitkeeper, const OtbAsymCipher *peer_asym_cipher)
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

static gboolean otb_do_client_establish_friend(OtbProtocolContext *context, OtbBitkeeper *local_bitkeeper, const OtbAsymCipher *peer_asym_cipher)
{
	unsigned char *server_response_packet=NULL;
	uint32_t server_response_packet_size=otb_create_ok_packet(&server_response_packet);
	unsigned char *client_packet=NULL;
	uint32_t client_packet_size=otb_protocol_client(context, server_response_packet, server_response_packet_size, &client_packet);
	g_assert(client_packet!=NULL);
	g_assert_cmpint(17, ==, client_packet_size);
	g_assert_cmpint(client_packet[0], ==, EXPECTED_COMMAND_SENDING_FRIEND_ID);
	OtbUser *local_user=NULL;
	g_object_get(local_bitkeeper, OTB_BITKEEPER_PROP_USER, &local_user, NULL);
	g_assert(local_user!=NULL);
	OtbUniqueId *expected_friend_id=NULL;
	g_object_get(local_user, OTB_USER_PROP_UNIQUE_ID, &expected_friend_id, NULL);
	g_assert_cmpint(0, ==, memcmp(expected_friend_id, client_packet+1, sizeof *expected_friend_id));
	g_free(expected_friend_id);
	g_object_unref(local_user);
	g_free(client_packet);
	g_free(server_response_packet);
}

static gboolean otb_do_client_send_authentication_token_to_server(OtbProtocolContext *context, const OtbBitkeeper *local_bitkeeper, const OtbAsymCipher *peer_asym_cipher)
{
	unsigned char *server_response_packet=NULL;
	uint32_t server_response_packet_size=otb_create_ok_packet(&server_response_packet);
	unsigned char *encrypted_client_packet=NULL;
	uint32_t encrypted_client_packet_size=otb_protocol_client(context, server_response_packet, server_response_packet_size, &encrypted_client_packet);
	g_assert_cmpint(4157, ==, encrypted_client_packet_size);
	g_assert(encrypted_client_packet!=NULL);
	unsigned char *plain_client_packet=NULL;
	uint32_t plain_client_packet_size=otb_decrypt_packet(peer_asym_cipher, encrypted_client_packet, encrypted_client_packet_size, &plain_client_packet);
	g_assert_cmpint(4101, ==, plain_client_packet_size);
	g_assert(plain_client_packet!=NULL);
	g_assert_cmpint(EXPECTED_COMMAND_SENDING_AUTHENTICATION_TOKEN, ==, plain_client_packet[0]);
	g_assert_cmpint(4096, ==, g_ntohl(*(uint32_t*)(plain_client_packet+1)));
	g_assert_cmpint(0, ==, memcmp(context->authentication_token, plain_client_packet+5, 4096));
	g_free(plain_client_packet);
	g_free(encrypted_client_packet);
	g_free(server_response_packet);
}

static uint32_t otb_make_encrypted_packet(const OtbProtocolContext *context, const unsigned char *plain_packet, uint32_t plain_packet_size, unsigned char **encrypted_packet_out)
{
	GBytes *encrypted_key=NULL;
	GBytes *iv=NULL;
	unsigned char *encrypted_data=NULL;
	uint32_t encrypted_data_size=otb_asym_cipher_encrypt(context->local_asym_cipher, plain_packet, 4101, &encrypted_key, &iv, &encrypted_data);
	uint32_t encrypted_packet_size=13+g_bytes_get_size(encrypted_key)+g_bytes_get_size(iv)+encrypted_data_size;
	*encrypted_packet_out=g_malloc(encrypted_packet_size);
	*encrypted_packet_out[0]=EXPECTED_COMMAND_ENCRYPTED;
	*(uint32_t*)(*encrypted_packet_out+1)=g_htonl(g_bytes_get_size(encrypted_key));
	*(uint32_t*)(*encrypted_packet_out+5)=g_htonl(g_bytes_get_size(iv));
	*(uint32_t*)(*encrypted_packet_out+9)=g_htonl(encrypted_data_size);
	memcpy(*encrypted_packet_out+13, g_bytes_get_data(encrypted_key, NULL), g_bytes_get_size(encrypted_key));
	memcpy(*encrypted_packet_out+13+g_bytes_get_size(encrypted_key), g_bytes_get_data(iv, NULL), g_bytes_get_size(iv));
	memcpy(*encrypted_packet_out+13+g_bytes_get_size(encrypted_key)+g_bytes_get_size(iv), encrypted_data, encrypted_data_size);
	g_free(encrypted_data);
	return encrypted_packet_size;
}

static gboolean otb_do_client_request_authentication_from_server(OtbProtocolContext *context, const OtbBitkeeper *local_bitkeeper, const OtbAsymCipher *peer_asym_cipher)
{
	unsigned char *server_response_plain_packet=g_malloc(4101);
	server_response_plain_packet[0]=EXPECTED_COMMAND_SENDING_AUTHENTICATION_TOKEN;
	*(uint32_t*)(server_response_plain_packet+1)=g_htonl(4096);
	memcpy(server_response_plain_packet+5, context->authentication_token, 4096);
	unsigned char *server_response_encrypted_packet=NULL;
	uint32_t server_response_encrypted_packet_size=otb_make_encrypted_packet(context, server_response_plain_packet, 4101, &server_response_encrypted_packet);
	unsigned char *client_packet=NULL;
	uint32_t client_packet_size=otb_protocol_client(context, server_response_encrypted_packet, server_response_encrypted_packet_size, &client_packet);
	g_assert_cmpint(1, ==, client_packet_size);
	g_assert(client_packet!=NULL);
	g_assert_cmpint(EXPECTED_COMMAND_REQUESTING_AUTHENTICATION, ==, client_packet[0]);
	g_free(client_packet);
	g_free(server_response_encrypted_packet);
	g_free(server_response_plain_packet);
}

static void test_otb_protocol_client()
{
	OtbUniqueId *peer_id=NULL;
	OtbAsymCipher *peer_asym_cipher=NULL;
	char *peer_export=NULL;
	otb_create_peer_for_protocol_test(&peer_id, &peer_asym_cipher, &peer_export);
	OtbBitkeeper *local_bitkeeper=otb_create_bitkeeper_for_protocol_test();
	g_assert(otb_bitkeeper_import_friend(local_bitkeeper, peer_export));
	g_free(peer_export);
	OtbFriend *peer_friend=otb_bitkeeper_get_friend(local_bitkeeper, peer_id);
	g_assert(peer_friend!=NULL);
	OtbProtocolContext *context=otb_protocol_context_create_client(local_bitkeeper, peer_friend);
	
	otb_do_client_establish_protocol_version(context, local_bitkeeper, peer_asym_cipher);
	otb_do_client_establish_friend(context, local_bitkeeper, peer_asym_cipher);
	otb_do_client_send_authentication_token_to_server(context, local_bitkeeper, peer_asym_cipher);
	otb_do_client_request_authentication_from_server(context, local_bitkeeper, peer_asym_cipher);
	
	otb_protocol_context_free(context);
	g_object_unref(peer_friend);
	g_object_unref(local_bitkeeper);
	g_object_unref(peer_asym_cipher);
}

void otb_add_protocol_tests()
{
	otb_add_test_func("/protocol/test_otb_protocol_client", test_otb_protocol_client);
}
