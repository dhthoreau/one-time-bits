/**
 * Copyright © 2015 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_PROTOCOL_H
#define OTB_PROTOCOL_H

#include <gio/gio.h>
#include <stdint.h>

#include "asym-cipher.h"
#include "friend.h"
#include "loopable-thread.h"
#include "unique-id.h"

typedef struct _OtbProtocolContext OtbProtocolContext;
typedef uint32_t (*ProtocolFunc)(OtbProtocolContext *context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **output_out);

/// Using uint32_t here instead of size_t for array sizes because these are values that could be sent across the network, and we must be assured of 32-bit sized uints for cross compatibility. A size_t could be 64-bit on some CPUs, which would not work when talking to a 32-bit peer.
OtbProtocolContext *otb_protocol_context_create_client(OtbFriend *peer_friend, OtbLoopableThread *loopable_thread);
#define otb_protocol_context_create_server(loopable_thread)	(otb_protocol_context_create_client(NULL, (loopable_thread)))
uint32_t otb_protocol_client(OtbProtocolContext *protocol_context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **output_out);
uint32_t otb_protocol_server(OtbProtocolContext *protocol_context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **output_out);
void otb_protocol_execute(OtbProtocolContext *protocol_context, ProtocolFunc protocol_func, GInputStream *input_stream, GOutputStream *output_stream, gboolean initiate_communication);
void otb_protocol_context_free(OtbProtocolContext *protocol_context);

#endif
