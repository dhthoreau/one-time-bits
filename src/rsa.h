/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_RSA_H
#define OTB_RSA_H

#include <glib-object.h>
#include <openssl/evp.h>

#define OTB_RSA_PROP_KEY_LENGTH	"key-length"

#define OTB_TYPE_RSA			(otb_rsa_get_type())
#define OTB_RSA(obj)			(G_TYPE_CHECK_INSTANCE_CAST((obj), OTB_TYPE_RSA, OtbRSA))
#define OTB_IS_RSA(obj)			(G_TYPE_CHECK_INSTANCE_TYPE((obj), OTB_TYPE_RSA))
#define OTB_RSA_CLASS(klass)	(G_TYPE_CHECK_CLASS_CAST((klass), OTB_TYPE_RSA, OtbRSAClass))
#define OTB_IS_RSA_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE((klass), OTB_TYPE_RSA))
#define OTB_RSA_GET_CLASS(obj)	(G_TYPE_CHECK_CLASS_TYPE((obj), OTB_TYPE_RSA, OtbRSAClass))

typedef struct _OtbRSA OtbRSA;
typedef struct _OtbRSAClass OtbRSAClass;
typedef struct _OtbRSAPrivate OtbRSAPrivate;

struct _OtbRSA
{
	GObject parent_instance;
	OtbRSAPrivate *priv;
};

struct _OtbRSAClass
{
	GObjectClass parent_class;
};

GType otb_rsa_get_type();

gboolean otb_rsa_generate_keys(OtbRSA *rsa, size_t key_size);

#endif
