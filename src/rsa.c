/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <openssl/rsa.h>

#include "export.h"
#include "rsa.h"

#define MINIMUM_KEY_SIZE	2048
#define DEFAULT_KEY_SIZE	4096

struct _OtbRSAPrivate
{
	RSA *rsa_impl;
};

enum
{
	PROP_0,
	PROP_KEY_SIZE
};

static void otb_rsa_finalize(GObject *object);

G_DEFINE_TYPE(OtbRSA, otb_rsa, G_TYPE_OBJECT);

static void otb_rsa_class_init(OtbRSAClass *klass)
{
	OpenSSL_add_all_algorithms();
	GObjectClass *object_class=G_OBJECT_CLASS(klass);
	object_class->finalize=otb_rsa_finalize;
	g_type_class_add_private(klass, sizeof(OtbRSAPrivate));
}

static void otb_rsa_init(OtbRSA *rsa)
{
	rsa->priv=G_TYPE_INSTANCE_GET_PRIVATE(rsa, OTB_TYPE_RSA, OtbRSAPrivate);
	rsa->priv->rsa_impl=NULL;
}

static void otb_rsa_finalize(GObject *object)
{
	g_return_if_fail(object!=NULL);
	g_return_if_fail(OTB_IS_RSA(object));
	OtbRSA *rsa=OTB_RSA(object);
	if(rsa->priv->rsa_impl!=NULL)
		RSA_free(rsa->priv->rsa_impl);
	G_OBJECT_CLASS(otb_rsa_parent_class)->finalize(object);
}

gboolean otb_rsa_generate_keys(OtbRSA *rsa, size_t key_size)
{
	gboolean success=FALSE;
	BIGNUM *big_number=BN_new();
	BN_set_word(big_number, RSA_F4);
	RSA *rsa_impl=RSA_new();
	if(_RSA_generate_key_ex(rsa_impl, (int)key_size, big_number, NULL))
		success=TRUE;
	BN_free(big_number);
	if(success)
	{
		if(rsa->priv->rsa_impl!=NULL)
			RSA_free(rsa->priv->rsa_impl);
		rsa->priv->rsa_impl=rsa_impl;
	}
	else
		RSA_free(rsa_impl);
	return success;
}
