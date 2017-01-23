/**
 * Copyright © 2015 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_BITKEEPER_H
#define OTB_BITKEEPER_H

#include <glib-object.h>

#include "friend.h"
#include "user.h"

#define OTB_BITKEEPER_DEFAULT_PROXY_PORT					9050
#define OTB_BITKEEPER_DEFAULT_PAD_SYNCHRONIZATION_INTERVAL	10000000ll
#define OTB_BITKEEPER_DEFAULT_USER_KEY_SIZE					4096
#define OTB_BITKEEPER_DEFAULT_USER_PORT						9876	// FARE - Scegliere una porta giusta.

#define OTB_BITKEEPER_PROP_USER							"user"
#define OTB_BITKEEPER_PROP_PROXY_PORT					"proxy-port"
#define OTB_BITKEEPER_PROP_PAD_SYNCHRONIZATION_INTERVAL	"pad-synchronization-interval"

#define OTB_TYPE_BITKEEPER				(otb_bitkeeper_get_type())
#define OTB_BITKEEPER(obj)				(G_TYPE_CHECK_INSTANCE_CAST((obj), OTB_TYPE_BITKEEPER, OtbBitkeeper))
#define OTB_IS_BITKEEPER(obj)			(G_TYPE_CHECK_INSTANCE_TYPE((obj), OTB_TYPE_BITKEEPER))
#define OTB_BITKEEPER_CLASS(klass)		(G_TYPE_CHECK_CLASS_CAST((klass), OTB_TYPE_BITKEEPER, OtbBitkeeperClass))
#define OTB_IS_BITKEEPER_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE((klass), OTB_TYPE_BITKEEPER))
#define OTB_BITKEEPER_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS((obj), OTB_TYPE_BITKEEPER, OtbBitkeeperClass))

typedef struct _OtbBitkeeper OtbBitkeeper;
typedef struct _OtbBitkeeperClass OtbBitkeeperClass;
typedef struct _OtbBitkeeperPrivate OtbBitkeeperPrivate;

struct _OtbBitkeeper
{
	GObject parent_instance;
	OtbBitkeeperPrivate *priv;
};

struct _OtbBitkeeperClass
{
	GObjectClass parent_class;
};

GType otb_bitkeeper_get_type();

gboolean otb_bitkeeper_exists();
OtbBitkeeper *otb_bitkeeper_create(unsigned int proxy_port, long long pad_synchronization_interval, const unsigned char *user_address, unsigned short user_port, unsigned int user_key_size);	// FARE - Non cancellare dati sul disc. Invece, abbi un otb_bitkeeper_delete().
																																																// FARE - Non utilizzare short.
																																																// FARE - Permettere un sottotipo (come name di OtbDemoUser).
OtbBitkeeper *otb_bitkeeper_create_with_defaults(const unsigned char *user_address);
OtbBitkeeper *otb_bitkeeper_load();
gboolean otb_bitkeeper_save(const OtbBitkeeper *bitkeeper);
GSList *otb_bitkeeper_get_unique_ids_of_friends(const OtbBitkeeper *bitkeeper);
OtbFriend *otb_bitkeeper_get_friend(const OtbBitkeeper *bitkeeper, const OtbUniqueId *friend_unique_id);
OtbFriend *otb_bitkeeper_get_friend_who_sent_pad(const OtbBitkeeper *bitkeeper, const OtbUniqueId *pad_unique_id);
gboolean otb_bitkeeper_import_friend(OtbBitkeeper *bitkeeper, const char *import_string);
gboolean otb_bitkeeper_remove_friend(OtbBitkeeper *bitkeeper, const OtbUniqueId *unique_id);
void otb_bitkeeper_launch_tasks(OtbBitkeeper *bitkeeper);
void otb_bitkeeper_shutdown_tasks(OtbBitkeeper *bitkeeper);

#endif
