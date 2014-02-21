/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <glib/gi18n.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "export.h"
#include "openssl-util.h"
#include "random.h"
#include "rsa.h"

#define MINIMUM_NEW_KEY_SIZE	512
#define DEFAULT_NEW_KEY_SIZE	4096
#define DEFAULT_CIPHER			"AES-256-CBC"

struct _OtbRSAPrivate
{
	size_t new_key_size;
	EVP_PKEY *public_key_impl;
	EVP_PKEY *private_key_impl;
	const EVP_CIPHER *cipher_impl;
};

enum
{
	PROP_0,
	PROP_NEW_KEY_SIZE,
	PROP_CIPHER
};

static void otb_rsa_finalize(GObject *object);
static void otb_rsa_set_property(GObject *object, unsigned int prop_id, const GValue *value, GParamSpec *pspec);
static void otb_rsa_get_property(GObject *object, unsigned int prop_id, GValue *value, GParamSpec *pspec);

G_DEFINE_TYPE(OtbRSA, otb_rsa, G_TYPE_OBJECT);

static void otb_rsa_class_init(OtbRSAClass *klass)
{
	OpenSSL_add_all_algorithms();
	GObjectClass *object_class=G_OBJECT_CLASS(klass);
	object_class->finalize=otb_rsa_finalize;
	object_class->set_property=otb_rsa_set_property;
	object_class->get_property=otb_rsa_get_property;
	g_object_class_install_property(object_class, PROP_NEW_KEY_SIZE, g_param_spec_uint(OTB_RSA_PROP_NEW_KEY_LENGTH, _("New key length"), _("The bit length of new keys"), MINIMUM_NEW_KEY_SIZE, G_MAXUINT, DEFAULT_NEW_KEY_SIZE, G_PARAM_READWRITE | G_PARAM_CONSTRUCT));
	g_object_class_install_property(object_class, PROP_CIPHER, g_param_spec_string(OTB_RSA_PROP_CIPHER, _("Cipher"), _("Name of the cipher to use"), DEFAULT_CIPHER, G_PARAM_READWRITE | G_PARAM_CONSTRUCT));
	g_type_class_add_private(klass, sizeof(OtbRSAPrivate));
}

static void otb_rsa_init(OtbRSA *rsa)
{
	rsa->priv=G_TYPE_INSTANCE_GET_PRIVATE(rsa, OTB_TYPE_RSA, OtbRSAPrivate);
	rsa->priv->new_key_size=0;
	rsa->priv->public_key_impl=NULL;
	rsa->priv->private_key_impl=NULL;
	rsa->priv->cipher_impl=NULL;
}

static void otb_rsa_finalize(GObject *object)
{
	g_return_if_fail(object!=NULL);
	g_return_if_fail(OTB_IS_RSA(object));
	OtbRSA *rsa=OTB_RSA(object);
	if(rsa->priv->public_key_impl!=NULL)
		EVP_PKEY_free(rsa->priv->public_key_impl);
	if(rsa->priv->private_key_impl!=NULL)
		EVP_PKEY_free(rsa->priv->private_key_impl);
	G_OBJECT_CLASS(otb_rsa_parent_class)->finalize(object);
}

static void otb_rsa_set_private_key_impl(OtbRSA *rsa, EVP_PKEY *private_key_impl)
{
	if(rsa->priv->private_key_impl!=NULL)
		EVP_PKEY_free(rsa->priv->private_key_impl);
	rsa->priv->private_key_impl=private_key_impl;
}

static void otb_rsa_set_public_key_impl(OtbRSA *rsa, EVP_PKEY *public_key_impl)
{
	if(rsa->priv->public_key_impl!=NULL)
		EVP_PKEY_free(rsa->priv->public_key_impl);
	rsa->priv->public_key_impl=public_key_impl;
}

static void otb_rsa_set_property(GObject *object, unsigned int prop_id, const GValue *value, GParamSpec *pspec)
{
	OtbRSA *rsa=OTB_RSA(object);
	const char *string_value;
	switch(prop_id)
	{
		case PROP_NEW_KEY_SIZE:
			rsa->priv->new_key_size=g_value_get_uint(value);
			break;
		case PROP_CIPHER:
			string_value=g_value_get_string(value);
			rsa->priv->cipher_impl=_EVP_get_cipherbyname(string_value);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
	}
}

static void otb_rsa_get_property(GObject *object, unsigned int prop_id, GValue *value, GParamSpec *pspec)
{
	OtbRSA *rsa=OTB_RSA(object);
	switch(prop_id)
	{
		case PROP_NEW_KEY_SIZE:
			g_value_set_uint(value, rsa->priv->new_key_size);
			break;
		case PROP_CIPHER:
			g_value_set_string(value, EVP_CIPHER_name(rsa->priv->cipher_impl));
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
	}
}

gboolean otb_rsa_set_public_key(OtbRSA *rsa, GBytes *key)
{
	gboolean ret_val=FALSE;
	BIO *buff_io=BIO_new_mem_buf((void *)g_bytes_get_data(key, NULL), g_bytes_get_size(key));
	EVP_PKEY *public_key_impl=PEM_read_bio_PUBKEY(buff_io, NULL, NULL, NULL);
	BIO_free(buff_io);
	if(public_key_impl!=NULL)
	{
		otb_rsa_set_private_key_impl(rsa, public_key_impl);
		ret_val=TRUE;
	}
}

GBytes *otb_rsa_get_public_key(OtbRSA *rsa)
{
	GBytes *ret_val=NULL;
	BIO *buff_io=BIO_new(BIO_s_mem());
	if(PEM_write_bio_PUBKEY(buff_io, rsa->priv->public_key_impl))
	{
		char *key=NULL;
		long key_size=BIO_get_mem_data(buff_io, &key);
		ret_val=g_bytes_new_take(key, key_size);
	}
	BIO_free(buff_io);
	return ret_val;
}

static EVP_PKEY *otb_rsa_get_private_key_impl_from_joint_key(EVP_PKEY *key_impl)
{
	BIO *private_buff_io=BIO_new(BIO_s_mem());
	PEM_write_bio_PrivateKey(private_buff_io, key_impl, NULL, NULL, 0, NULL, NULL);
	EVP_PKEY *private_key_impl=PEM_read_bio_PrivateKey(private_buff_io, NULL, NULL, NULL);
	BIO_free_all(private_buff_io);
	return private_key_impl;
}

static EVP_PKEY *otb_rsa_get_public_key_impl_from_joint_key(EVP_PKEY *key_impl)
{
	BIO *public_buff_io=BIO_new(BIO_s_mem());
	PEM_write_bio_PUBKEY(public_buff_io, key_impl);
	EVP_PKEY *public_key_impl=PEM_read_bio_PUBKEY(public_buff_io, NULL, NULL, NULL);
	BIO_free_all(public_buff_io);
	return public_key_impl;
}

static gboolean otb_rsa_set_both_keys(OtbRSA *rsa, EVP_PKEY *key_impl)
{
	gboolean ret_val=FALSE;
	EVP_PKEY *private_key_impl=otb_rsa_get_private_key_impl_from_joint_key(key_impl);
	EVP_PKEY *public_key_impl=otb_rsa_get_public_key_impl_from_joint_key(key_impl);
	if(private_key_impl!=NULL && public_key_impl!=NULL)
	{
		otb_rsa_set_private_key_impl(rsa, private_key_impl);
		otb_rsa_set_public_key_impl(rsa, public_key_impl);
		ret_val=TRUE;
	}
	else
	{
		if(private_key_impl!=NULL)
			EVP_PKEY_free(private_key_impl);
		if(public_key_impl!=NULL)
			EVP_PKEY_free(public_key_impl);
	}
	return ret_val;
}

gboolean otb_rsa_generate_keys(OtbRSA *rsa, size_t key_size)
{
	gboolean ret_val=TRUE;
	EVP_PKEY_CTX *context=EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	EVP_PKEY *key_impl;
	if(EVP_PKEY_keygen_init(context)<=0)
		ret_val=FALSE;
	else if(_EVP_PKEY_CTX_set_rsa_keygen_bits(context, rsa->priv->new_key_size)<=0)
		ret_val=FALSE;
	else if(EVP_PKEY_keygen(context, &key_impl)<=0)
		ret_val=FALSE;
	EVP_PKEY_CTX_free(context);
	if(ret_val)
	{
		ret_val=otb_rsa_set_both_keys(rsa, key_impl);
		EVP_PKEY_free(key_impl);
	}
	return ret_val;
}

OtbRSAContext *otb_rsa_init_encryption(const OtbRSA *rsa, GBytes **iv_out, GBytes **encrypted_key_out)
{
	OtbRSAContext *rsa_context=NULL;
	rsa_context=g_malloc(sizeof(OtbRSAContext));
	unsigned char *iv_bytes=g_malloc(EVP_CIPHER_iv_length(rsa->priv->cipher_impl));
	unsigned char *encrypted_key_bytes;
	size_t encrypted_key_size;
	*encrypted_key_out=g_malloc(EVP_PKEY_size(rsa->priv->public_key_impl));
	EVP_CIPHER_CTX_init(rsa_context);
	if(EVP_SealInit(rsa_context, rsa->priv->cipher_impl, &encrypted_key_bytes, &encrypted_key_size, iv_bytes, &rsa->priv->public_key_impl, 1))
	{
		*iv_out=g_bytes_new_take(iv_bytes, EVP_CIPHER_iv_length(rsa->priv->cipher_impl));
		*encrypted_key_out=g_bytes_new_take(encrypted_key_bytes, encrypted_key_size);
	}
	else
	{
		otb_rsa_context_free(rsa_context);
		g_free(iv_bytes);
		g_free(*encrypted_key_out);
		g_warning(_("%s: Failed to initialize encryption."), "otb_rsa_init_encryption");
	}
	return rsa_context;
}

OtbRSAContext *otb_rsa_init_decryption(const OtbRSA *rsa, GBytes *iv, GBytes *encrypted_key)
{
	OtbRSAContext *rsa_context=g_malloc(sizeof(OtbRSAContext));
	EVP_CIPHER_CTX_init(rsa_context);
	if(!EVP_OpenInit(rsa_context, rsa->priv->cipher_impl, g_bytes_get_data(encrypted_key, NULL), 1, g_bytes_get_data(iv, NULL), rsa->priv->private_key_impl))
	{
		otb_rsa_context_free(rsa_context);
		g_warning(_("%s: Failed to initialize decryption."), "otb_rsa_init_decryption");
	}
	return rsa_context;
}

size_t otb_rsa_encrypt(OtbRSAContext *rsa_context, const char *plain_bytes, size_t plain_bytes_size, char *encrypted_bytes_out)
{
	int encrypted_bytes_size;
	if(!EVP_SealUpdate(rsa_context, encrypted_bytes_out, &encrypted_bytes_size, plain_bytes, plain_bytes_size))
	{
		char *error=otb_openssl_errors_as_string();
		g_warning(_("%s: Failed to encrypt data. Error == %s"), "otb_rsa_encrypt", error);
		g_free(error);
		encrypted_bytes_size=0;
	}
	return (size_t)encrypted_bytes_size;
}

size_t otb_rsa_decrypt(OtbRSAContext *rsa_context, const char *encrypted_bytes, size_t encrypted_bytes_size, char *plain_bytes_out)
{
	int plain_bytes_size;
	if(!EVP_OpenUpdate(rsa_context, plain_bytes_out, &plain_bytes_size, encrypted_bytes, encrypted_bytes_size))
	{
		char *error=otb_openssl_errors_as_string();
		g_warning(_("%s: Failed to decrypt data. Error == %s"), "otb_rsa_decrypt", error);
		g_free(error);
		plain_bytes_size=0;
	}
	return (size_t)plain_bytes_size;
}

size_t otb_rsa_finish_encrypt(OtbRSAContext *rsa_context, char *encrypted_bytes_out)
{
	int encrypted_bytes_size;
	if(!EVP_SealFinal(rsa_context, encrypted_bytes_out, &encrypted_bytes_size))
	{
		char *error=otb_openssl_errors_as_string();
		g_warning(_("%s: Failed to encrypt final data. Error == %s"), "otb_rsa_finish_encrypt", error);
		g_free(error);
		encrypted_bytes_size=0;
	}
	otb_rsa_context_free(rsa_context);
	return (size_t)encrypted_bytes_size;
}

size_t otb_rsa_finish_decrypt(OtbRSAContext *rsa_context, char *plain_bytes_out)
{
	int plain_bytes_size;
	if(!EVP_OpenFinal(rsa_context, plain_bytes_out, &plain_bytes_size))
	{
		char *error=otb_openssl_errors_as_string();
		g_warning(_("%s: Failed to decrypt final data. Error == %s"), "otb_rsa_finish_decrypt", error);
		g_free(error);
		plain_bytes_size=0;
	}
	
	otb_rsa_context_free(rsa_context);
	return (size_t)plain_bytes_size;
}
