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
#include "asym-cipher.h"
#include "smem.h"

#define DEFAULT_CIPHER			"AES-256-CBC"

struct _OtbAsymCipherPrivate
{
	const EVP_CIPHER *cipher_impl;
	char *public_key;
	EVP_PKEY *public_key_impl;
	EVP_PKEY *private_key_impl;
};

enum
{
	PROP_0,
	PROP_SYM_CIPHER
};

static void otb_asym_cipher_finalize(GObject *object);
static void otb_asym_cipher_set_property(GObject *object, unsigned int prop_id, const GValue *value, GParamSpec *pspec);
static void otb_asym_cipher_get_property(GObject *object, unsigned int prop_id, GValue *value, GParamSpec *pspec);

G_DEFINE_TYPE(OtbAsymCipher, otb_asym_cipher, G_TYPE_OBJECT);

static void otb_asym_cipher_class_init(OtbAsymCipherClass *klass)
{
	OpenSSL_add_all_algorithms();
	GObjectClass *object_class=G_OBJECT_CLASS(klass);
	object_class->finalize=otb_asym_cipher_finalize;
	object_class->set_property=otb_asym_cipher_set_property;
	object_class->get_property=otb_asym_cipher_get_property;
	g_object_class_install_property(object_class, PROP_SYM_CIPHER, g_param_spec_string(OTB_ASYM_CIPHER_PROP_SYM_CIPHER, _("Symmetric cipher"), _("Name of the symmetric cipher to use"), DEFAULT_CIPHER, G_PARAM_READWRITE | G_PARAM_CONSTRUCT));
	g_type_class_add_private(klass, sizeof(OtbAsymCipherPrivate));
}

static void otb_asym_cipher_init(OtbAsymCipher *asym_cipher)
{
	asym_cipher->priv=G_TYPE_INSTANCE_GET_PRIVATE(asym_cipher, OTB_TYPE_ASYM_CIPHER, OtbAsymCipherPrivate);
	asym_cipher->priv->cipher_impl=NULL;
	asym_cipher->priv->public_key=NULL;
	asym_cipher->priv->public_key_impl=NULL;
	asym_cipher->priv->private_key_impl=NULL;
}

static void otb_asym_cipher_set_private_key_impl(const OtbAsymCipher *asym_cipher, EVP_PKEY *private_key_impl)
{
	if(asym_cipher->priv->private_key_impl!=NULL)
		EVP_PKEY_free(asym_cipher->priv->private_key_impl);
	_otb_set_EVP_PKEY(&asym_cipher->priv->private_key_impl, &private_key_impl);
}

static void otb_asym_cipher_set_public_key_impl(const OtbAsymCipher *asym_cipher, const char *public_key, EVP_PKEY *public_key_impl)
{
	g_free(asym_cipher->priv->public_key);
	asym_cipher->priv->public_key=g_strdup(public_key);
	if(asym_cipher->priv->public_key_impl!=NULL)
		EVP_PKEY_free(asym_cipher->priv->public_key_impl);
	_otb_set_EVP_PKEY(&asym_cipher->priv->public_key_impl, &public_key_impl);
}

static void otb_asym_cipher_finalize(GObject *object)
{
	g_return_if_fail(object!=NULL);
	g_return_if_fail(OTB_IS_ASYM_CIPHER(object));
	OtbAsymCipher *asym_cipher=OTB_ASYM_CIPHER(object);
	otb_asym_cipher_set_public_key_impl(asym_cipher, NULL, NULL);
	if(asym_cipher->priv->private_key_impl!=NULL)
		EVP_PKEY_free(asym_cipher->priv->private_key_impl);
	G_OBJECT_CLASS(otb_asym_cipher_parent_class)->finalize(object);
}

static void otb_asym_cipher_set_property(GObject *object, unsigned int prop_id, const GValue *value, GParamSpec *pspec)
{
	OtbAsymCipher *asym_cipher=OTB_ASYM_CIPHER(object);
	const char *string_value;
	switch(prop_id)
	{
		case PROP_SYM_CIPHER:
			string_value=g_value_get_string(value);
			asym_cipher->priv->cipher_impl=_EVP_get_cipherbyname(string_value);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
	}
}

static void otb_asym_cipher_get_property(GObject *object, unsigned int prop_id, GValue *value, GParamSpec *pspec)
{
	OtbAsymCipher *asym_cipher=OTB_ASYM_CIPHER(object);
	switch(prop_id)
	{
		case PROP_SYM_CIPHER:
			g_value_set_string(value, EVP_CIPHER_name(asym_cipher->priv->cipher_impl));
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
	}
}

gboolean otb_asym_cipher_set_public_key(const OtbAsymCipher *asym_cipher, const char *public_key)
{
	gboolean ret_val=FALSE;
	BIO *buff_io=BIO_new_mem_buf(g_strdup(public_key), strlen(public_key));
	EVP_PKEY *public_key_impl=PEM_read_bio_PUBKEY(buff_io, NULL, NULL, NULL);
	BIO_free(buff_io);
	if(public_key_impl!=NULL)
	{
		otb_asym_cipher_set_public_key_impl(asym_cipher, public_key, public_key_impl);
		ret_val=TRUE;
	}
	return ret_val;
}

const char *otb_asym_cipher_get_public_key(const OtbAsymCipher *asym_cipher)
{
	return asym_cipher->priv->public_key;
}

static unsigned char *otb_asym_cipher_decrypt_private_key(const OtbCipher *cipher, GBytes *iv, GBytes *encrypted_private_key, size_t *private_key_size_out)
{
	unsigned char *private_key=otb_cipher_create_decryption_buffer(cipher, g_bytes_get_size(encrypted_private_key), NULL);
	OtbCipherContext *cipher_context=otb_cipher_init_decryption(cipher, iv);
	*private_key_size_out=otb_cipher_decrypt(cipher_context, g_bytes_get_data(encrypted_private_key, NULL), g_bytes_get_size(encrypted_private_key), private_key);
	*private_key_size_out+=otb_cipher_finish_decrypt(cipher_context, private_key+*private_key_size_out);
	return private_key;
}

gboolean otb_asym_cipher_set_private_key(const OtbAsymCipher *asym_cipher, GBytes *encrypted_private_key, const OtbCipher *cipher, GBytes *iv)
{
	gboolean ret_val=FALSE;
	size_t private_key_size;
	void *private_key=otb_asym_cipher_decrypt_private_key(cipher, iv, encrypted_private_key, &private_key_size);
	BIO *buff_io=BIO_new_mem_buf(private_key, private_key_size);
	EVP_PKEY *private_key_impl=PEM_read_bio_PrivateKey(buff_io, NULL, NULL, NULL);
	BIO_free(buff_io);
	smemset(private_key, 0, private_key_size);
	g_free(private_key);
	if(private_key_impl!=NULL)
	{
		otb_asym_cipher_set_private_key_impl(asym_cipher, private_key_impl);
		ret_val=TRUE;
	}
	return ret_val;
}

static unsigned char *otb_asym_cipher_encrypt_private_key(const OtbCipher *cipher, unsigned char *private_key, size_t private_key_size, size_t *encrypted_private_key_size_out, GBytes **iv_out)
{
	unsigned char *encrypted_private_key=otb_cipher_create_encryption_buffer(cipher, private_key_size, NULL);
	OtbCipherContext *cipher_context=otb_cipher_init_encryption(cipher, iv_out);
	*encrypted_private_key_size_out=otb_cipher_encrypt(cipher_context, private_key, private_key_size, encrypted_private_key);
	*encrypted_private_key_size_out+=otb_cipher_finish_encrypt(cipher_context, encrypted_private_key+*encrypted_private_key_size_out);
	return encrypted_private_key;
}

GBytes *otb_asym_cipher_get_private_key(const OtbAsymCipher *asym_cipher, const OtbCipher *cipher, GBytes **iv_out)
{
	GBytes *ret_val=NULL;
	BIO *buff_io=BIO_new(BIO_s_mem());
	if(PEM_write_bio_PrivateKey(buff_io, asym_cipher->priv->private_key_impl, NULL, NULL, 0, NULL, NULL))
	{
		char *private_key=NULL;
		long private_key_size=BIO_get_mem_data(buff_io, &private_key);
		size_t encrypted_private_key_size;
		unsigned char *encrypted_private_key=otb_asym_cipher_encrypt_private_key(cipher, private_key, private_key_size, &encrypted_private_key_size, iv_out);
		ret_val=g_bytes_new_take(encrypted_private_key, encrypted_private_key_size);
	}
	BIO_free(buff_io);
	return ret_val;
}

static EVP_PKEY *otb_asym_cipher_get_private_key_impl_from_joint_key(EVP_PKEY *key_impl)
{
	BIO *private_buff_io=BIO_new(BIO_s_mem());
	PEM_write_bio_PrivateKey(private_buff_io, key_impl, NULL, NULL, 0, NULL, NULL);
	EVP_PKEY *private_key_impl=PEM_read_bio_PrivateKey(private_buff_io, NULL, NULL, NULL);
	BIO_free_all(private_buff_io);
	return private_key_impl;
}

static EVP_PKEY *otb_asym_cipher_get_public_key_impl_from_joint_key(EVP_PKEY *key_impl)
{
	BIO *public_buff_io=BIO_new(BIO_s_mem());
	PEM_write_bio_PUBKEY(public_buff_io, key_impl);
	EVP_PKEY *public_key_impl=PEM_read_bio_PUBKEY(public_buff_io, NULL, NULL, NULL);
	BIO_free_all(public_buff_io);
	return public_key_impl;
}

static char *otb_asym_cipher_public_key_impl_to_public_key(EVP_PKEY *public_key_impl)
{
	char *ret_val=NULL;
	BIO *buff_io=BIO_new(BIO_s_mem());
	if(PEM_write_bio_PUBKEY(buff_io, public_key_impl))
	{
		char *public_key=NULL;
		long public_key_size=BIO_get_mem_data(buff_io, &public_key);
		ret_val=g_strdup(public_key);
	}
	BIO_free(buff_io);
	return ret_val;
}

static gboolean otb_asym_cipher_set_both_keys(OtbAsymCipher *asym_cipher, EVP_PKEY *key_impl)
{
	gboolean ret_val=FALSE;
	EVP_PKEY *private_key_impl=otb_asym_cipher_get_private_key_impl_from_joint_key(key_impl);
	EVP_PKEY *public_key_impl=otb_asym_cipher_get_public_key_impl_from_joint_key(key_impl);
	if(private_key_impl!=NULL && public_key_impl!=NULL)
	{
		otb_asym_cipher_set_private_key_impl(asym_cipher, private_key_impl);
		char *public_key=otb_asym_cipher_public_key_impl_to_public_key(public_key_impl);
		otb_asym_cipher_set_public_key_impl(asym_cipher, public_key, public_key_impl);
		g_free(public_key);
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

gboolean otb_asym_cipher_generate_random_keys(OtbAsymCipher *asym_cipher, size_t key_size)
{
	gboolean ret_val=TRUE;
	// FARE - Potrebbe essere bene se c'erano più di EVP_PKEY_RSA. Fai EVP_PKEY_RSA come un input?
	EVP_PKEY_CTX *context=EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	EVP_PKEY *key_impl=NULL;
	if(EVP_PKEY_keygen_init(context)<=0)
		ret_val=FALSE;
	else if(_EVP_PKEY_CTX_set_rsa_keygen_bits(context, key_size)<=0)
		ret_val=FALSE;
	else if(EVP_PKEY_keygen(context, &key_impl)<=0)
		ret_val=FALSE;
	EVP_PKEY_CTX_free(context);
	if(ret_val)
	{
		ret_val=otb_asym_cipher_set_both_keys(asym_cipher, key_impl);
		EVP_PKEY_free(key_impl);
	}
	return ret_val;
}

unsigned char *otb_asym_cipher_create_encryption_buffer(const OtbAsymCipher *asym_cipher, size_t plain_bytes_buffer_size, size_t *encryption_buffer_size_out)
{
	return otb_openssl_create_encryption_buffer(asym_cipher->priv->cipher_impl, plain_bytes_buffer_size, encryption_buffer_size_out);
}

unsigned char *otb_asym_cipher_create_decryption_buffer(const OtbAsymCipher *asym_cipher, size_t encrypted_bytes_buffer_size, size_t *decryption_buffer_size_out)
{
	return otb_openssl_create_decryption_buffer(asym_cipher->priv->cipher_impl, encrypted_bytes_buffer_size, decryption_buffer_size_out);
}

OtbAsymCipherContext *otb_asym_cipher_init_encryption(const OtbAsymCipher *asym_cipher, GBytes **iv_out, GBytes **encrypted_key_out)
{
	OtbAsymCipherContext *asym_cipher_context=NULL;
	asym_cipher_context=g_malloc(sizeof(OtbAsymCipherContext));
	unsigned char *iv_bytes=g_malloc(EVP_CIPHER_iv_length(asym_cipher->priv->cipher_impl));
	unsigned char *encrypted_key_bytes=g_malloc(EVP_PKEY_size(asym_cipher->priv->public_key_impl));
	size_t encrypted_key_size;
	EVP_CIPHER_CTX_init(asym_cipher_context);
	if(EVP_SealInit(asym_cipher_context, asym_cipher->priv->cipher_impl, &encrypted_key_bytes, &encrypted_key_size, iv_bytes, &asym_cipher->priv->public_key_impl, 1))
	{
		*iv_out=g_bytes_new_take(iv_bytes, EVP_CIPHER_iv_length(asym_cipher->priv->cipher_impl));
		*encrypted_key_out=g_bytes_new_take(encrypted_key_bytes, encrypted_key_size);
	}
	else
	{
		otb_asym_cipher_context_free(asym_cipher_context);
		g_free(iv_bytes);
		g_free(encrypted_key_bytes);
		char *error=otb_openssl_errors_as_string();
		g_warning(_("%s: Failed to initialize encryption. Error == %s"), "otb_asym_cipher_init_encryption", error);
		g_free(error);
	}
	return asym_cipher_context;
}

OtbAsymCipherContext *otb_asym_cipher_init_decryption(const OtbAsymCipher *asym_cipher, GBytes *iv, GBytes *encrypted_key)
{
	OtbAsymCipherContext *asym_cipher_context=g_malloc(sizeof(OtbAsymCipherContext));
	EVP_CIPHER_CTX_init(asym_cipher_context);
	if(!EVP_OpenInit(asym_cipher_context, asym_cipher->priv->cipher_impl, g_bytes_get_data(encrypted_key, NULL), g_bytes_get_size(encrypted_key), g_bytes_get_data(iv, NULL), asym_cipher->priv->private_key_impl))
	{
		otb_asym_cipher_context_free(asym_cipher_context);
		char *error=otb_openssl_errors_as_string();
		g_warning(_("%s: Failed to initialize decryption. Error == %s"), "otb_asym_cipher_init_decryption", error);
		g_free(error);
	}
	return asym_cipher_context;
}

size_t otb_asym_cipher_encrypt(OtbAsymCipherContext *asym_cipher_context, const unsigned char *plain_bytes, size_t plain_bytes_size, unsigned char *encrypted_bytes_out)
{
	int encrypted_bytes_size;
	if(!EVP_SealUpdate(asym_cipher_context, encrypted_bytes_out, &encrypted_bytes_size, plain_bytes, plain_bytes_size))
	{
		char *error=otb_openssl_errors_as_string();
		g_warning(_("%s: Failed to encrypt data. Error == %s"), "otb_asym_cipher_encrypt", error);
		g_free(error);
		encrypted_bytes_size=0;
	}
	return (size_t)encrypted_bytes_size;
}

size_t otb_asym_cipher_decrypt(OtbAsymCipherContext *asym_cipher_context, const unsigned char *encrypted_bytes, size_t encrypted_bytes_size, unsigned char *plain_bytes_out)
{
	int plain_bytes_size;
	if(!EVP_OpenUpdate(asym_cipher_context, plain_bytes_out, &plain_bytes_size, encrypted_bytes, encrypted_bytes_size))
	{
		char *error=otb_openssl_errors_as_string();
		g_warning(_("%s: Failed to decrypt data. Error == %s"), "otb_asym_cipher_decrypt", error);
		g_free(error);
		plain_bytes_size=0;
	}
	return (size_t)plain_bytes_size;
}

size_t otb_asym_cipher_finish_encrypt(OtbAsymCipherContext *asym_cipher_context, unsigned char *encrypted_bytes_out)
{
	int encrypted_bytes_size;
	if(!EVP_SealFinal(asym_cipher_context, encrypted_bytes_out, &encrypted_bytes_size))
	{
		char *error=otb_openssl_errors_as_string();
		g_warning(_("%s: Failed to encrypt final data. Error == %s"), "otb_asym_cipher_finish_encrypt", error);
		g_free(error);
		encrypted_bytes_size=0;
	}
	otb_asym_cipher_context_free(asym_cipher_context);
	return (size_t)encrypted_bytes_size;
}

size_t otb_asym_cipher_finish_decrypt(OtbAsymCipherContext *asym_cipher_context, unsigned char *plain_bytes_out)
{
	int plain_bytes_size;
	if(!EVP_OpenFinal(asym_cipher_context, plain_bytes_out, &plain_bytes_size))
	{
		char *error=otb_openssl_errors_as_string();
		g_warning(_("%s: Failed to decrypt final data. Error == %s"), "otb_asym_cipher_finish_decrypt", error);
		g_free(error);
		plain_bytes_size=0;
	}
	
	otb_asym_cipher_context_free(asym_cipher_context);
	return (size_t)plain_bytes_size;
}
