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
	GRWLock lock;
	const EVP_CIPHER *cipher_impl;
	EVP_PKEY *key_impl;
};

enum
{
	PROP_0,
	PROP_SYM_CIPHER,
	PROP_PUBLIC_KEY
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
	g_object_class_install_property(object_class, PROP_PUBLIC_KEY, g_param_spec_string(OTB_ASYM_CIPHER_PROP_PUBLIC_KEY, _("Public key"), _("The public key to use for encryption"), NULL, G_PARAM_READWRITE));
	g_type_class_add_private(klass, sizeof(OtbAsymCipherPrivate));
}

static void otb_asym_cipher_init(OtbAsymCipher *asym_cipher)
{
	asym_cipher->priv=G_TYPE_INSTANCE_GET_PRIVATE(asym_cipher, OTB_TYPE_ASYM_CIPHER, OtbAsymCipherPrivate);
	g_rw_lock_init(&asym_cipher->priv->lock);
	asym_cipher->priv->cipher_impl=NULL;
	asym_cipher->priv->key_impl=NULL;
}

static void otb_asym_cipher_finalize(GObject *object)
{
	g_return_if_fail(object!=NULL);
	g_return_if_fail(OTB_IS_ASYM_CIPHER(object));
	OtbAsymCipher *asym_cipher=OTB_ASYM_CIPHER(object);
	g_rw_lock_clear(&asym_cipher->priv->lock);
	EVP_PKEY_free(asym_cipher->priv->key_impl);
	G_OBJECT_CLASS(otb_asym_cipher_parent_class)->finalize(object);
}

static void otb_asym_cipher_set_key_impl(const OtbAsymCipher *asym_cipher, EVP_PKEY *key_impl)
{
	if(asym_cipher->priv->key_impl!=NULL)
		EVP_PKEY_free(asym_cipher->priv->key_impl);
	_otb_set_EVP_PKEY(&asym_cipher->priv->key_impl, key_impl);
}

#define otb_asym_cipher_lock_read(asym_cipher)	(g_rw_lock_reader_lock(&asym_cipher->priv->lock))
#define otb_asym_cipher_unlock_read(asym_cipher)	(g_rw_lock_reader_unlock(&asym_cipher->priv->lock))
#define otb_asym_cipher_lock_write(asym_cipher)	(g_rw_lock_writer_lock(&asym_cipher->priv->lock))
#define otb_asym_cipher_unlock_write(asym_cipher)	(g_rw_lock_writer_unlock(&asym_cipher->priv->lock))

static void otb_asym_cipher_set_property(GObject *object, unsigned int prop_id, const GValue *value, GParamSpec *pspec)
{
	OtbAsymCipher *asym_cipher=OTB_ASYM_CIPHER(object);
	switch(prop_id)
	{
		case PROP_SYM_CIPHER:
		{
			otb_asym_cipher_lock_write(asym_cipher);
			asym_cipher->priv->cipher_impl=_EVP_get_cipherbyname(g_value_get_string(value));
			otb_asym_cipher_unlock_write(asym_cipher);
			break;
		}
		case PROP_PUBLIC_KEY:
		{
			char *string_value=g_value_dup_string(value);
			BIO *buff_io=BIO_new_mem_buf(string_value, strlen(string_value));
			otb_asym_cipher_lock_write(asym_cipher);
			otb_asym_cipher_set_key_impl(asym_cipher, PEM_read_bio_PUBKEY(buff_io, NULL, NULL, NULL));
			otb_asym_cipher_unlock_write(asym_cipher);
			BIO_free_all(buff_io);
			g_free(string_value);
			break;
		}
		default:
		{
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
		}
	}
}

static void otb_asym_cipher_get_property(GObject *object, unsigned int prop_id, GValue *value, GParamSpec *pspec)
{
	OtbAsymCipher *asym_cipher=OTB_ASYM_CIPHER(object);
	switch(prop_id)
	{
		case PROP_SYM_CIPHER:
		{
			otb_asym_cipher_lock_read(asym_cipher);
			g_value_set_string(value, EVP_CIPHER_name(asym_cipher->priv->cipher_impl));
			otb_asym_cipher_unlock_read(asym_cipher);
			break;
		}
		case PROP_PUBLIC_KEY:
		{
			BIO *buff_io=BIO_new(BIO_s_mem());
			otb_asym_cipher_lock_read(asym_cipher);
			if(PEM_write_bio_PUBKEY(buff_io, asym_cipher->priv->key_impl))
			{
				char *public_key_in_buff=NULL;
				long public_key_size=BIO_get_mem_data(buff_io, &public_key_in_buff);
				char *public_key=g_malloc(public_key_size);
				memcpy(public_key, public_key_in_buff, public_key_size);
				public_key[public_key_size]='\0';	/// Data in a BIO isn't always null terminated, though sometimes it is by random dumb luck. It's a PEM, not a string. This unusual code is meant to work around that, turn the PEM into a real C string.
				g_value_take_string(value, public_key);
			}
			otb_asym_cipher_unlock_read(asym_cipher);
			BIO_free(buff_io);
			break;
		}
		default:
		{
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
		}
	}
}

void otb_asym_cipher_set_encrypted_private_key(const OtbAsymCipher *asym_cipher, GBytes *encrypted_private_key, OtbSymCipher *private_key_sym_cipher, GBytes *private_key_iv)
{
	void *private_key=NULL;
	size_t private_key_size=otb_sym_cipher_decrypt(private_key_sym_cipher, g_bytes_get_data(encrypted_private_key, NULL), g_bytes_get_size(encrypted_private_key), private_key_iv, &private_key);
	BIO *buff_io=BIO_new_mem_buf(private_key, private_key_size);
	otb_asym_cipher_lock_write(asym_cipher);
	otb_asym_cipher_set_key_impl(asym_cipher, PEM_read_bio_PrivateKey(buff_io, NULL, NULL, NULL));
	otb_asym_cipher_unlock_write(asym_cipher);
	BIO_free(buff_io);
	smemset(private_key, 0, private_key_size);
	g_free(private_key);
}

GBytes *otb_asym_cipher_get_encrypted_private_key(const OtbAsymCipher *asym_cipher, OtbSymCipher *private_key_sym_cipher, GBytes **private_key_iv_out)
{
	GBytes *encrypted_private_key=NULL;
	BIO *buff_io=BIO_new(BIO_s_mem());
	otb_asym_cipher_lock_read(asym_cipher);
	if(PEM_write_bio_PrivateKey(buff_io, asym_cipher->priv->key_impl, NULL, NULL, 0, NULL, NULL))
	{
		char *private_key=NULL;
		long private_key_size=BIO_get_mem_data(buff_io, &private_key);
		unsigned char *encrypted_private_key_bytes=NULL;
		size_t encrypted_private_key_size=otb_sym_cipher_encrypt(private_key_sym_cipher, private_key, private_key_size, private_key_iv_out, &encrypted_private_key_bytes);
		encrypted_private_key=g_bytes_new_take(encrypted_private_key_bytes, encrypted_private_key_size);
	}
	otb_asym_cipher_unlock_read(asym_cipher);
	BIO_free(buff_io);
	return encrypted_private_key;
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
	otb_asym_cipher_lock_write(asym_cipher);
	if(ret_val)
		asym_cipher->priv->key_impl=key_impl;
	else if(key_impl!=NULL)
		EVP_PKEY_free(key_impl);
	otb_asym_cipher_unlock_write(asym_cipher);
	return ret_val;
}

unsigned char *otb_asym_cipher_create_encryption_buffer(const OtbAsymCipher *asym_cipher, size_t plain_bytes_buffer_size, size_t *encryption_buffer_size_out)
{
	otb_asym_cipher_lock_read(asym_cipher);
	const EVP_CIPHER *cipher_impl=asym_cipher->priv->cipher_impl;
	otb_asym_cipher_unlock_read(asym_cipher);
	return otb_openssl_create_encryption_buffer(cipher_impl, plain_bytes_buffer_size, encryption_buffer_size_out);
}

void *otb_asym_cipher_create_decryption_buffer(const OtbAsymCipher *asym_cipher, size_t encrypted_bytes_buffer_size, size_t *decryption_buffer_size_out)
{
	otb_asym_cipher_lock_read(asym_cipher);
	const EVP_CIPHER *cipher_impl=asym_cipher->priv->cipher_impl;
	otb_asym_cipher_unlock_read(asym_cipher);
	return otb_openssl_create_decryption_buffer(cipher_impl, encrypted_bytes_buffer_size, decryption_buffer_size_out);
}

OtbAsymCipherContext *otb_asym_cipher_init_encryption(const OtbAsymCipher *asym_cipher, GBytes **encrypted_key_out, GBytes **iv_out)
{
	OtbAsymCipherContext *asym_cipher_context=NULL;
	asym_cipher_context=g_malloc(sizeof(OtbAsymCipherContext));
	EVP_CIPHER_CTX_init(asym_cipher_context);
	otb_asym_cipher_lock_read(asym_cipher);
	unsigned char *encrypted_key_bytes=g_malloc(EVP_PKEY_size(asym_cipher->priv->key_impl));
	int encrypted_key_size;
	unsigned char *iv_bytes=g_malloc(EVP_CIPHER_iv_length(asym_cipher->priv->cipher_impl));
	if(EVP_SealInit(asym_cipher_context, asym_cipher->priv->cipher_impl, &encrypted_key_bytes, &encrypted_key_size, iv_bytes, &asym_cipher->priv->key_impl, 1))
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
		g_warning(_("Failed to initialize encryption. Error == %s"), error);
		g_free(error);
	}
	otb_asym_cipher_unlock_read(asym_cipher);
	return asym_cipher_context;
}

OtbAsymCipherContext *otb_asym_cipher_init_decryption(const OtbAsymCipher *asym_cipher, GBytes *encrypted_key, GBytes *iv)
{
	OtbAsymCipherContext *asym_cipher_context=g_malloc(sizeof(OtbAsymCipherContext));
	EVP_CIPHER_CTX_init(asym_cipher_context);
	otb_asym_cipher_lock_read(asym_cipher);
	if(!EVP_OpenInit(asym_cipher_context, asym_cipher->priv->cipher_impl, g_bytes_get_data(encrypted_key, NULL), g_bytes_get_size(encrypted_key), g_bytes_get_data(iv, NULL), asym_cipher->priv->key_impl))
	{
		otb_asym_cipher_context_free(asym_cipher_context);
		char *error=otb_openssl_errors_as_string();
		g_warning(_("Failed to initialize decryption. Error == %s"), error);
		g_free(error);
	}
	otb_asym_cipher_unlock_read(asym_cipher);
	return asym_cipher_context;
}

size_t otb_asym_cipher_encrypt_next(OtbAsymCipherContext *asym_cipher_context, const void *plain_bytes, size_t plain_bytes_size, unsigned char *encrypted_bytes_out)
{
	int encrypted_bytes_size;
	if(!EVP_SealUpdate(asym_cipher_context, encrypted_bytes_out, &encrypted_bytes_size, plain_bytes, plain_bytes_size))
	{
		char *error=otb_openssl_errors_as_string();
		g_warning(_("Failed to encrypt data. Error == %s"), error);
		g_free(error);
		encrypted_bytes_size=0;
	}
	return (size_t)encrypted_bytes_size;
}

size_t otb_asym_cipher_decrypt_next(OtbAsymCipherContext *asym_cipher_context, const unsigned char *encrypted_bytes, size_t encrypted_bytes_size, void *plain_bytes_out)
{
	int plain_bytes_size;
	if(!EVP_OpenUpdate(asym_cipher_context, plain_bytes_out, &plain_bytes_size, encrypted_bytes, encrypted_bytes_size))
	{
		char *error=otb_openssl_errors_as_string();
		g_warning(_("Failed to decrypt data. Error == %s"), error);
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
		g_warning(_("Failed to encrypt final data. Error == %s"), error);
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
		g_warning(_("Failed to decrypt final data. Error == %s"), error);
		g_free(error);
		plain_bytes_size=0;
	}
	otb_asym_cipher_context_free(asym_cipher_context);
	return (size_t)plain_bytes_size;
}

size_t otb_asym_cipher_encrypt(const OtbAsymCipher *asym_cipher, const void *plain_bytes, size_t plain_bytes_size, GBytes **encrypted_key_out, GBytes **iv_out, unsigned char **encrypted_bytes_out)
{
	*encrypted_bytes_out=otb_asym_cipher_create_encryption_buffer(asym_cipher, plain_bytes_size, NULL);
	OtbAsymCipherContext *asym_cipher_context=otb_asym_cipher_init_encryption(asym_cipher, encrypted_key_out, iv_out);
	size_t ret_val=otb_asym_cipher_encrypt_next(asym_cipher_context, plain_bytes, plain_bytes_size, *encrypted_bytes_out);
	ret_val+=otb_asym_cipher_finish_encrypt(asym_cipher_context, *encrypted_bytes_out+ret_val);
	return ret_val;
}

size_t otb_asym_cipher_decrypt(const OtbAsymCipher *asym_cipher, const unsigned char *encrypted_bytes, size_t encrypted_bytes_size, GBytes *encrypted_key, GBytes *iv, void **plain_bytes_out)
{
	*plain_bytes_out=otb_asym_cipher_create_decryption_buffer(asym_cipher, encrypted_bytes_size, NULL);
	OtbSymCipherContext *asym_cipher_context=otb_asym_cipher_init_decryption(asym_cipher, encrypted_key, iv);
	size_t ret_val=otb_asym_cipher_decrypt_next(asym_cipher_context, encrypted_bytes, encrypted_bytes_size, *plain_bytes_out);
	ret_val+=otb_asym_cipher_finish_decrypt(asym_cipher_context, *(unsigned char**)plain_bytes_out+ret_val);
	return ret_val;
}
