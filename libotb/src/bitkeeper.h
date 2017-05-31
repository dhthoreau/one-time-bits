/**
 * Copyright © 2017 the OTB team
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

GType otb_bitkeeper_get_type(void);

gboolean otb_bitkeeper_exists(void);
gboolean otb_bitkeeper_set(OtbBitkeeper *bitkeeper);
gboolean otb_bitkeeper_load(void);
gboolean otb_bitkeeper_save(void);
void otb_bitkeeper_unload(void);
GSList *otb_bitkeeper_get_unique_ids_of_friends(void);
OtbFriend *otb_bitkeeper_get_friend(const OtbUniqueId *friend_unique_id);
OtbFriend *otb_bitkeeper_get_friend_who_sent_pad(const OtbUniqueId *pad_unique_id);
gboolean otb_bitkeeper_import_friend(const char *import_string);
gboolean otb_bitkeeper_remove_friend(const OtbUniqueId *unique_id);
void otb_bitkeeper_launch_tasks(void);
void otb_bitkeeper_shutdown_tasks(void);
OtbBitkeeper *otb_bitkeeper_get_with_ref(void);

#endif
