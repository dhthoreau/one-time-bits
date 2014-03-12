/**
 * Copyright © 2014 the OTB team
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

OtbBitkeeper *otb_bitkeeper_load();	// FARE - Ha bisogno di unit test.
OtbUser *otb_bitkeeper_get_user(const OtbBitkeeper *bitkeeper);	// FARE - Ha bisogno di unit test.
OtbFriend *otb_bitkeeper_get_friend(const OtbBitkeeper *bitkeeper, const uuid_t *unique_id);	// FARE - Ha bisogno di unit test.
OtbFriend *otb_bitkeeper_import_friend(OtbBitkeeper *bitkeeper, const char *import_string);	// FARE - Ha bisogno di unit test.
gboolean otb_bitkeeper_remove_friend(OtbBitkeeper *bitkeeper, const uuid_t *unique_id);	// FARE - Ha bisogno di unit test.
GSList *otb_bitkeeper_get_ids_of_friends(const OtbBitkeeper *bitkeeper);	// FARE - Ha bisogno di unit test.

#endif
