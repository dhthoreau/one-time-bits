/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_PROTOCOL_H
#define OTB_PROTOCOL_H

#include <stdint.h>

#include "asym-cipher.h"
#include "bitkeeper.h"
#include "unique-id.h"

typedef unsigned char OtbProtocolState;
typedef struct _OtbProtocolContext OtbProtocolContext;

/// Using uint32_t here instead of size_t for array lengths because these are values that could be sent across the network, and we must be assured of 32-bit sized uints for cross compatibility. A size_t could be 64-bit on some CPUs, which would not work when talking to a 32-bit peer.
OtbProtocolContext *otb_protocol_context_create_client(OtbBitkeeper *bitkeeper, OtbFriend *peer_friend);
#define otb_protocol_context_create_server(bitkeeper)	(otb_protocol_context_create_client((bitkeeper), NULL)
uint32_t otb_protocol_client(OtbProtocolContext *context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **output_out);
uint32_t otb_protocol_server(OtbProtocolContext *context, const unsigned char *input_packet, uint32_t input_packet_size, unsigned char **output_out);
void otb_protocol_context_free(OtbProtocolContext *context);

#endif
