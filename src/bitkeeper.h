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

#include "pad-db.h"

#define OTB_BITKEEPER_PROP_BASE_PATH		"base_path"
#define OTB_BITKEEPER_PROP_RSA_PUBLIC_KEY	"rsa_public_key"

#define OTB_TYPE_BITKEEPER				(otb_bitkeeper_get_type())
#define OTB_BITKEEPER(obj)				(G_TYPE_CHECK_INSTANCE_CAST((obj), OTB_TYPE_BITKEEPER, OtbBitkeeper))
#define OTB_IS_BITKEEPER(obj)			(G_TYPE_CHECK_INSTANCE_TYPE((obj), OTB_TYPE_BITKEEPER))
#define OTB_BITKEEPER_CLASS(klass)		(G_TYPE_CHECK_CLASS_CAST((klass), OTB_TYPE_BITKEEPER, OtbBitkeeperClass))
#define OTB_IS_BITKEEPER_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE((klass), OTB_TYPE_BITKEEPER))
#define OTB_BITKEEPER_GET_CLASS(obj)	(G_TYPE_CHECK_CLASS_TYPE((obj), OTB_TYPE_BITKEEPER, OtbBitkeeperClass))

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

OtbBitkeeper *otb_bitkeeper_load();

#endif
