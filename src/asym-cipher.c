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
	GBytes *encrypted_private_key;
	OtbSymCipher *private_key_sym_cipher;
	GBytes *private_key_iv;
	char *public_key;
};

enum
{
	PROP_0,
	PROP_SYM_CIPHER,
	PROP_PUBLIC_KEY
};

static void otb_asym_cipher_dispose(GObject *object);
static void otb_asym_cipher_finalize(GObject *object);
static void otb_asym_cipher_set_property(GObject *object, unsigned int prop_id, const GValue *value, GParamSpec *pspec);
static void otb_asym_cipher_get_property(GObject *object, unsigned int prop_id, GValue *value, GParamSpec *pspec);

G_DEFINE_TYPE(OtbAsymCipher, otb_asym_cipher, G_TYPE_OBJECT);

static void otb_asym_cipher_class_init(OtbAsymCipherClass *klass)
{
	OpenSSL_add_all_algorithms();
	GObjectClass *object_class=G_OBJECT_CLASS(klass);
	object_class->dispose=otb_asym_cipher_dispose;
	object_class->finalize=otb_asym_cipher_finalize;
	object_class->set_property=otb_asym_cipher_set_property;
	object_class->get_property=otb_asym_cipher_get_property;
	g_object_class_install_property(object_class, PROP_SYM_CIPHER, g_param_spec_string(OTB_ASYM_CIPHER_PROP_SYM_CIPHER, _("Symmetric cipher"), _("Name of the symmetric cipher to use"), DEFAULT_CIPHER, G_PARAM_READWRITE | G_PARAM_CONSTRUCT));
	g_object_class_install_property(object_class, PROP_PUBLIC_KEY, g_param_spec_string(OTB_ASYM_CIPHER_PROP_PUBLIC_KEY, _("Public key"), _("The public key used for encryption"), NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT));
	g_type_class_add_private(klass, sizeof(OtbAsymCipherPrivate));
}

static void otb_asym_cipher_init(OtbAsymCipher *asym_cipher)
{
	asym_cipher->priv=G_TYPE_INSTANCE_GET_PRIVATE(asym_cipher, OTB_TYPE_ASYM_CIPHER, OtbAsymCipherPrivate);
	asym_cipher->priv->cipher_impl=NULL;
	asym_cipher->priv->encrypted_private_key=NULL;
	asym_cipher->priv->private_key_sym_cipher=NULL;
	asym_cipher->priv->private_key_iv=NULL;
	asym_cipher->priv->public_key=NULL;
}

static void otb_asym_cipher_dispose(GObject *object)
{
	g_return_if_fail(object!=NULL);
	g_return_if_fail(OTB_IS_ASYM_CIPHER(object));
	OtbAsymCipher *asym_cipher=OTB_ASYM_CIPHER(object);
	otb_asym_cipher_set_encrypted_private_key(asym_cipher, NULL, NULL, NULL);
	G_OBJECT_CLASS(otb_asym_cipher_parent_class)->dispose(object);
}

static void otb_asym_cipher_finalize(GObject *object)
{
	g_return_if_fail(object!=NULL);
	g_return_if_fail(OTB_IS_ASYM_CIPHER(object));
	OtbAsymCipher *asym_cipher=OTB_ASYM_CIPHER(object);
	g_free(asym_cipher->priv->public_key);
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
		case PROP_PUBLIC_KEY:
			g_free(asym_cipher->priv->public_key);
			asym_cipher->priv->public_key=g_value_dup_string(value);
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
		case PROP_PUBLIC_KEY:
			g_value_set_string(value, asym_cipher->priv->public_key);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
	}
}

gboolean otb_asym_cipher_set_encrypted_private_key(const OtbAsymCipher *asym_cipher, GBytes *encrypted_private_key, OtbSymCipher *private_key_sym_cipher, GBytes *private_key_iv)
{
	if(encrypted_private_key!=NULL)
		g_bytes_ref(encrypted_private_key);
	g_bytes_unref(asym_cipher->priv->encrypted_private_key);
	asym_cipher->priv->encrypted_private_key=encrypted_private_key;
	if(private_key_sym_cipher!=NULL)
		g_object_ref(private_key_sym_cipher);
	if(asym_cipher->priv->private_key_sym_cipher!=NULL)
		g_object_unref(asym_cipher->priv->private_key_sym_cipher);
	asym_cipher->priv->private_key_sym_cipher=private_key_sym_cipher;
	if(private_key_iv!=NULL)
		g_bytes_ref(private_key_iv);
	g_bytes_unref(asym_cipher->priv->private_key_iv);
	asym_cipher->priv->private_key_iv=private_key_iv;
}

GBytes *otb_asym_cipher_get_encrypted_private_key(const OtbAsymCipher *asym_cipher, GBytes **private_key_iv_out)
{
	*private_key_iv_out=asym_cipher->priv->private_key_iv;
	return asym_cipher->priv->encrypted_private_key;
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

static GBytes *otb_asym_cipher_private_key_impl_to_encrypted_private_key(EVP_PKEY *private_key_impl, const OtbSymCipher *private_key_sym_cipher, GBytes **private_key_iv_out)
{
	GBytes *encrypted_private_key=NULL;
	BIO *buff_io=BIO_new(BIO_s_mem());
	if(PEM_write_bio_PrivateKey(buff_io, private_key_impl, NULL, NULL, 0, NULL, NULL))
	{
		char *private_key=NULL;
		long private_key_size=BIO_get_mem_data(buff_io, &private_key);
		void *encrypted_private_key_bytes=NULL;
		size_t encrypted_private_key_size=otb_sym_cipher_encrypt(private_key_sym_cipher, private_key, private_key_size, private_key_iv_out, &encrypted_private_key_bytes);
		encrypted_private_key=g_bytes_new_take(encrypted_private_key_bytes, encrypted_private_key_size);
	}
	BIO_free(buff_io);
	return encrypted_private_key;
}

static gboolean otb_asym_cipher_set_both_keys(OtbAsymCipher *asym_cipher, EVP_PKEY *key_impl, OtbSymCipher *private_key_sym_cipher)
{
	gboolean ret_val=FALSE;
	EVP_PKEY *private_key_impl=otb_asym_cipher_get_private_key_impl_from_joint_key(key_impl);
	EVP_PKEY *public_key_impl=otb_asym_cipher_get_public_key_impl_from_joint_key(key_impl);
	if(private_key_impl!=NULL && public_key_impl!=NULL)
	{
		GBytes *private_key_iv=NULL;
		GBytes *encrypted_private_key=otb_asym_cipher_private_key_impl_to_encrypted_private_key(private_key_impl, private_key_sym_cipher, &private_key_iv);
		otb_asym_cipher_set_encrypted_private_key(asym_cipher, encrypted_private_key, private_key_sym_cipher, private_key_iv);
		g_bytes_unref(private_key_iv);
		g_bytes_unref(encrypted_private_key);
		char *public_key=otb_asym_cipher_public_key_impl_to_public_key(public_key_impl);
		g_object_set(asym_cipher, OTB_ASYM_CIPHER_PROP_PUBLIC_KEY, public_key, NULL);
		g_free(public_key);
		if(encrypted_private_key!=NULL && public_key!=NULL)
			ret_val=TRUE;
	}
	if(public_key_impl!=NULL)
		EVP_PKEY_free(public_key_impl);
	if(private_key_impl!=NULL)
		EVP_PKEY_free(private_key_impl);
	return ret_val;
}

gboolean otb_asym_cipher_generate_random_keys(OtbAsymCipher *asym_cipher, size_t key_size, OtbSymCipher *private_key_sym_cipher)
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
		ret_val=otb_asym_cipher_set_both_keys(asym_cipher, key_impl, private_key_sym_cipher);
	if(key_impl!=NULL)
		EVP_PKEY_free(key_impl);
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

static EVP_PKEY *otb_asym_cipher_public_key_to_public_key_impl(const char *public_key)
{
	BIO *buff_io=BIO_new_mem_buf((void*)public_key, -1);
	EVP_PKEY *public_key_impl=NULL;
	_otb_set_EVP_PKEY(&public_key_impl, PEM_read_bio_PUBKEY(buff_io, NULL, NULL, NULL));
	BIO_free(buff_io);
	return public_key_impl;
}

OtbAsymCipherContext *otb_asym_cipher_init_encryption(const OtbAsymCipher *asym_cipher, GBytes **encrypted_key_out, GBytes **iv_out)
{
	OtbAsymCipherContext *asym_cipher_context=NULL;
	asym_cipher_context=g_malloc(sizeof(OtbAsymCipherContext));
	EVP_CIPHER_CTX_init(asym_cipher_context);
	EVP_PKEY *public_key_impl=otb_asym_cipher_public_key_to_public_key_impl(asym_cipher->priv->public_key);
	unsigned char *encrypted_key_bytes=g_malloc(EVP_PKEY_size(public_key_impl));
	size_t encrypted_key_size;
	unsigned char *iv_bytes=g_malloc(EVP_CIPHER_iv_length(asym_cipher->priv->cipher_impl));
	if(EVP_SealInit(asym_cipher_context, asym_cipher->priv->cipher_impl, &encrypted_key_bytes, &encrypted_key_size, iv_bytes, &public_key_impl, 1))
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
	EVP_PKEY_free(public_key_impl);
	return asym_cipher_context;
}

static EVP_PKEY *otb_asym_cipher_encrypted_private_key_to_private_key_impl(const OtbAsymCipher *asym_cipher)
{
	void *private_key=NULL;
	size_t private_key_size=otb_sym_cipher_decrypt(asym_cipher->priv->private_key_sym_cipher, g_bytes_get_data(asym_cipher->priv->encrypted_private_key, NULL), g_bytes_get_size(asym_cipher->priv->encrypted_private_key), asym_cipher->priv->private_key_iv, &private_key);
	BIO *buff_io=BIO_new_mem_buf(private_key, private_key_size);
	EVP_PKEY *private_key_impl=NULL;
	_otb_set_EVP_PKEY(&private_key_impl, PEM_read_bio_PrivateKey(buff_io, NULL, NULL, NULL));
	BIO_free(buff_io);
	smemset(private_key, 0, private_key_size);
	g_free(private_key);
	return private_key_impl;
}

OtbAsymCipherContext *otb_asym_cipher_init_decryption(const OtbAsymCipher *asym_cipher, GBytes *encrypted_key, GBytes *iv)
{
	OtbAsymCipherContext *asym_cipher_context=g_malloc(sizeof(OtbAsymCipherContext));
	EVP_CIPHER_CTX_init(asym_cipher_context);
	EVP_PKEY *private_key_impl=otb_asym_cipher_encrypted_private_key_to_private_key_impl(asym_cipher);
	if(!EVP_OpenInit(asym_cipher_context, asym_cipher->priv->cipher_impl, g_bytes_get_data(encrypted_key, NULL), g_bytes_get_size(encrypted_key), g_bytes_get_data(iv, NULL), private_key_impl))
	{
		otb_asym_cipher_context_free(asym_cipher_context);
		char *error=otb_openssl_errors_as_string();
		g_warning(_("%s: Failed to initialize decryption. Error == %s"), "otb_asym_cipher_init_decryption", error);
		g_free(error);
	}
	EVP_PKEY_free(private_key_impl);
	return asym_cipher_context;
}

size_t otb_asym_cipher_encrypt(OtbAsymCipherContext *asym_cipher_context, const void *plain_bytes, size_t plain_bytes_size, void *encrypted_bytes_out)
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

size_t otb_asym_cipher_decrypt(OtbAsymCipherContext *asym_cipher_context, const void *encrypted_bytes, size_t encrypted_bytes_size, void *plain_bytes_out)
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

size_t otb_asym_cipher_finish_encrypt(OtbAsymCipherContext *asym_cipher_context, void *encrypted_bytes_out)
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

size_t otb_asym_cipher_finish_decrypt(OtbAsymCipherContext *asym_cipher_context, void *plain_bytes_out)
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
