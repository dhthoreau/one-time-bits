/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <glib/gi18n.h>

#include "sym-cipher.h"
#include "export.h"
#include "io.h"
#include "memory.h"
#include "openssl-util.h"
#include "random.h"
#include "smem.h"

#define DEFAULT_CIPHER			"AES-256-CBC"
#define DEFAULT_MESSAGE_DIGEST	"SHA512"
#define DEFAULT_HASH_ITERATIONS	20480

struct _OtbSymCipherPrivate
{
	unsigned char *key;
	size_t key_size;
	const EVP_CIPHER *sym_cipher_impl;
	// FARE - message_digest_impl ed hash_iterations dovrebbero essere input a otb_cipher_hash_passphrase(), etc. invece di membri di OtbSymCipherPrivate.
	const EVP_MD *message_digest_impl;
	unsigned int hash_iterations;
};

enum
{
	PROP_0,
	PROP_CIPHER,
	PROP_MESSAGE_DIGEST,
	PROP_HASH_ITERATIONS
};

static void otb_sym_cipher_finalize(GObject *object);
static void otb_sym_cipher_set_property(GObject *object, unsigned int prop_id, const GValue *value, GParamSpec *pspec);
static void otb_sym_cipher_get_property(GObject *object, unsigned int prop_id, GValue *value, GParamSpec *pspec);

G_DEFINE_TYPE(OtbSymCipher, otb_sym_cipher, G_TYPE_OBJECT);

static void otb_sym_cipher_class_init(OtbSymCipherClass *klass)
{
	OpenSSL_add_all_algorithms();
	GObjectClass *object_class=G_OBJECT_CLASS(klass);
	object_class->finalize=otb_sym_cipher_finalize;
	object_class->set_property=otb_sym_cipher_set_property;
	object_class->get_property=otb_sym_cipher_get_property;
	g_object_class_install_property(object_class, PROP_CIPHER, g_param_spec_string(OTB_SYM_CIPHER_PROP_CIPHER, _("Cipher"), _("Name of the cipher to use"), DEFAULT_CIPHER, G_PARAM_READWRITE | G_PARAM_CONSTRUCT));
	g_object_class_install_property(object_class, PROP_MESSAGE_DIGEST, g_param_spec_string(OTB_SYM_CIPHER_PROP_MESSAGE_DIGEST, _("Message digest"), _("Message digest to use for hashes"), DEFAULT_MESSAGE_DIGEST, G_PARAM_READWRITE | G_PARAM_CONSTRUCT));
	g_object_class_install_property(object_class, PROP_HASH_ITERATIONS, g_param_spec_uint(OTB_SYM_CIPHER_PROP_HASH_ITERATIONS, _("Hash iterations"), _("Number of iterations to go through when hashing"), 1, G_MAXUINT, DEFAULT_HASH_ITERATIONS, G_PARAM_READWRITE | G_PARAM_CONSTRUCT));
	g_type_class_add_private(klass, sizeof(OtbSymCipherPrivate));
}

static void otb_sym_cipher_init(OtbSymCipher *sym_cipher)
{
	sym_cipher->priv=G_TYPE_INSTANCE_GET_PRIVATE(sym_cipher, OTB_TYPE_SYM_CIPHER, OtbSymCipherPrivate);
	sym_cipher->priv->key=NULL;
	sym_cipher->priv->key_size=0;
	sym_cipher->priv->sym_cipher_impl=NULL;
	sym_cipher->priv->message_digest_impl=NULL;
	sym_cipher->priv->hash_iterations=0;
}

static void otb_sym_cipher_set_key(OtbSymCipher *sym_cipher, unsigned char *key, size_t key_size)
{
	if(sym_cipher->priv->key!=NULL)
	{
		smemset(sym_cipher->priv->key, 0, sym_cipher->priv->key_size);
		g_free(sym_cipher->priv->key);
	}
	sym_cipher->priv->key=key;
	sym_cipher->priv->key_size=key_size;
}

static void otb_sym_cipher_finalize(GObject *object)
{
	g_return_if_fail(object!=NULL);
	g_return_if_fail(OTB_IS_SYM_CIPHER(object));
	OtbSymCipher *sym_cipher=OTB_SYM_CIPHER(object);
	otb_sym_cipher_set_key(sym_cipher, NULL, 0);
	sym_cipher->priv->key=NULL;
	G_OBJECT_CLASS(otb_sym_cipher_parent_class)->finalize(object);
}

static void otb_sym_cipher_set_property(GObject *object, unsigned int prop_id, const GValue *value, GParamSpec *pspec)
{
	OtbSymCipher *sym_cipher=OTB_SYM_CIPHER(object);
	const char *string_value;
	switch(prop_id)
	{
		case PROP_CIPHER:
			string_value=g_value_get_string(value);
			sym_cipher->priv->sym_cipher_impl=_EVP_get_cipherbyname(string_value);
			break;
		case PROP_MESSAGE_DIGEST:
			string_value=g_value_get_string(value);
			sym_cipher->priv->message_digest_impl=EVP_get_digestbyname(string_value);
			break;
		case PROP_HASH_ITERATIONS:
			sym_cipher->priv->hash_iterations=g_value_get_uint(value);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
	}
}

static void otb_sym_cipher_get_property(GObject *object, unsigned int prop_id, GValue *value, GParamSpec *pspec)
{
	OtbSymCipher *sym_cipher=OTB_SYM_CIPHER(object);
	switch(prop_id)
	{
		case PROP_CIPHER:
			g_value_set_string(value, EVP_CIPHER_name(sym_cipher->priv->sym_cipher_impl));
			break;
		case PROP_MESSAGE_DIGEST:
			g_value_set_string(value, EVP_MD_name(sym_cipher->priv->message_digest_impl));
			break;
		case PROP_HASH_ITERATIONS:
			g_value_set_uint(value, sym_cipher->priv->hash_iterations);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
	}
}

GBytes *otb_sym_cipher_hash_passphrase(const OtbSymCipher *sym_cipher, const char *passphrase, OtbSymCipherSalt salt_out)
{
	GBytes *hash=NULL;
	size_t hash_size=EVP_MD_size(sym_cipher->priv->message_digest_impl);
	unsigned char *hash_bytes=g_malloc(hash_size);
	if(otb_random_bytes(salt_out, sizeof salt_out) && PKCS5_PBKDF2_HMAC(passphrase, strlen(passphrase), salt_out, sizeof salt_out, sym_cipher->priv->hash_iterations, sym_cipher->priv->message_digest_impl, hash_size, hash_bytes))
		hash=g_bytes_new_take(hash_bytes, hash_size);
	else
		g_free(hash_bytes);
	return hash;
}

gboolean otb_sym_cipher_validate_passphrase(const OtbSymCipher *sym_cipher, const char *passphrase, GBytes *passphrase_hash, OtbSymCipherSalt salt)
{
	gboolean ret_val=FALSE;
	size_t hash_size;
	const unsigned char *passphrase_hash_bytes=g_bytes_get_data(passphrase_hash, &hash_size);
	unsigned char *hash_bytes=g_malloc(hash_size);
	if(PKCS5_PBKDF2_HMAC(passphrase, strlen(passphrase), salt, sizeof salt, sym_cipher->priv->hash_iterations, sym_cipher->priv->message_digest_impl, hash_size, hash_bytes) && smemcmp(passphrase_hash_bytes, hash_bytes, hash_size)==0)
		ret_val=TRUE;
	g_free(hash_bytes);
	return ret_val;
}

static OtbSymCipherContext *otb_sym_cipher_init_encryption_openssl(const EVP_CIPHER *sym_cipher_impl, const unsigned char *key, const unsigned char *iv)
{
	OtbSymCipherContext *sym_cipher_context=g_malloc(sizeof(OtbSymCipherContext));
	EVP_CIPHER_CTX_init(sym_cipher_context);
	if(!EVP_EncryptInit_ex(sym_cipher_context, sym_cipher_impl, NULL, key, iv))
	{
		otb_sym_cipher_context_free(sym_cipher_context);
		char *error=otb_openssl_errors_as_string();
		g_warning(_("%s: Failed to initialize encryption. Error == %s"), "otb_sym_cipher_init_encryption_openssl", error);
		g_free(error);
	}
	return sym_cipher_context;
}

static OtbSymCipherContext *otb_sym_cipher_init_decryption_openssl(const EVP_CIPHER *sym_cipher, const unsigned char *key, const unsigned char *iv)
{
	OtbSymCipherContext *sym_cipher_context=g_malloc(sizeof(OtbSymCipherContext));
	EVP_CIPHER_CTX_init(sym_cipher_context);
	if(!EVP_DecryptInit_ex(sym_cipher_context, sym_cipher, NULL, key, iv))
	{
		otb_sym_cipher_context_free(sym_cipher_context);
		char *error=otb_openssl_errors_as_string();
		g_warning(_("%s: Failed to initialize decryption. Error == %s"), "otb_sym_cipher_init_decryption_openssl", error);
		g_free(error);
	}
	return sym_cipher_context;
}

#define key_and_iv_size(sym_cipher)	(EVP_CIPHER_key_length((sym_cipher)->priv->sym_cipher_impl)+EVP_CIPHER_iv_length((sym_cipher)->priv->sym_cipher_impl))

gboolean otb_sym_cipher_unwrap_key(OtbSymCipher *sym_cipher, GBytes *wrapped_key, const char *passphrase, OtbSymCipherSalt salt)
{
	gboolean ret_val=FALSE;
	unsigned char *wrapping_key_and_iv=g_malloc(key_and_iv_size(sym_cipher));
	if(PKCS5_PBKDF2_HMAC(passphrase, strlen(passphrase), salt, sizeof salt, sym_cipher->priv->hash_iterations, sym_cipher->priv->message_digest_impl, key_and_iv_size(sym_cipher), wrapping_key_and_iv))
	{
		unsigned char *key_bytes=otb_sym_cipher_create_decryption_buffer(sym_cipher, g_bytes_get_size(wrapped_key), NULL);
		OtbSymCipherContext *sym_cipher_context=otb_sym_cipher_init_decryption_openssl(sym_cipher->priv->sym_cipher_impl, wrapping_key_and_iv, wrapping_key_and_iv+EVP_CIPHER_key_length(sym_cipher->priv->sym_cipher_impl));
		size_t key_size=otb_sym_cipher_decrypt(sym_cipher_context, g_bytes_get_data(wrapped_key, NULL), g_bytes_get_size(wrapped_key), key_bytes);
		size_t final_bytes_size=otb_sym_cipher_finish_decrypt(sym_cipher_context, key_bytes+key_size);
		if(key_size==-1)
			g_free(key_bytes);
		else
		{
			otb_sym_cipher_set_key(sym_cipher, key_bytes, key_size);
			ret_val=TRUE;
		}
	}
	return ret_val;
}

GBytes *otb_sym_cipher_wrap_key(const OtbSymCipher *sym_cipher, const char *passphrase, OtbSymCipherSalt salt_out)
{
	GBytes *wrapped_key=NULL;
	if(otb_random_bytes(salt_out, sizeof salt_out))
	{
		unsigned char *wrapping_key_and_iv=g_malloc(key_and_iv_size(sym_cipher));
		if(PKCS5_PBKDF2_HMAC(passphrase, strlen(passphrase), salt_out, sizeof salt_out, sym_cipher->priv->hash_iterations, sym_cipher->priv->message_digest_impl, key_and_iv_size(sym_cipher), wrapping_key_and_iv))
		{
			unsigned char *wrapped_key_bytes=otb_sym_cipher_create_encryption_buffer(sym_cipher, sym_cipher->priv->key_size, NULL);
			OtbSymCipherContext *sym_cipher_context=otb_sym_cipher_init_encryption_openssl(sym_cipher->priv->sym_cipher_impl, wrapping_key_and_iv, wrapping_key_and_iv+EVP_CIPHER_key_length(sym_cipher->priv->sym_cipher_impl));
			size_t wrapped_key_size=otb_sym_cipher_encrypt(sym_cipher_context, sym_cipher->priv->key, sym_cipher->priv->key_size, wrapped_key_bytes);
			size_t final_bytes_size=otb_sym_cipher_finish_encrypt(sym_cipher_context, wrapped_key_bytes+wrapped_key_size);
			if(wrapped_key_size==-1)
				g_free(wrapped_key_bytes);
			else
				wrapped_key=g_bytes_new_take(wrapped_key_bytes, wrapped_key_size+final_bytes_size);
		}
		g_free(wrapping_key_and_iv);
	}
	return wrapped_key;
}

gboolean otb_sym_cipher_generate_random_key(OtbSymCipher *sym_cipher)
{
	gboolean ret_val=TRUE;
	unsigned char *key=otb_create_random_bytes(EVP_CIPHER_key_length(sym_cipher->priv->sym_cipher_impl));
	if(key==NULL)
		ret_val=FALSE;
	else
		otb_sym_cipher_set_key(sym_cipher, key, EVP_CIPHER_key_length(sym_cipher->priv->sym_cipher_impl));
	return ret_val;
}

unsigned char *otb_sym_cipher_create_encryption_buffer(const OtbSymCipher *sym_cipher, size_t plain_bytes_buffer_size, size_t *encryption_buffer_size_out)
{
	return otb_openssl_create_encryption_buffer(sym_cipher->priv->sym_cipher_impl, plain_bytes_buffer_size, encryption_buffer_size_out);
}

unsigned char *otb_sym_cipher_create_decryption_buffer(const OtbSymCipher *sym_cipher, size_t encrypted_bytes_buffer_size, size_t *decryption_buffer_size_out)
{
	return otb_openssl_create_decryption_buffer(sym_cipher->priv->sym_cipher_impl, encrypted_bytes_buffer_size, decryption_buffer_size_out);
}

OtbSymCipherContext *otb_sym_cipher_init_encryption(const OtbSymCipher *sym_cipher, GBytes **iv_out)
{
	*iv_out=otb_openssl_generate_random_iv(sym_cipher->priv->sym_cipher_impl);
	size_t iv_size;
	OtbSymCipherContext *ret_val=otb_sym_cipher_init_encryption_openssl(sym_cipher->priv->sym_cipher_impl, sym_cipher->priv->key, g_bytes_get_data(*iv_out, NULL));
	if(ret_val==NULL)
	{
		g_bytes_unref(*iv_out);
		*iv_out=NULL;
	}
	return ret_val;
}

OtbSymCipherContext *otb_sym_cipher_init_decryption(const OtbSymCipher *sym_cipher, GBytes *iv)
{
	return otb_sym_cipher_init_decryption_openssl(sym_cipher->priv->sym_cipher_impl, sym_cipher->priv->key, g_bytes_get_data(iv, NULL));
}

size_t otb_sym_cipher_encrypt(OtbSymCipherContext *sym_cipher_context, const unsigned char *plain_bytes, size_t plain_bytes_size, unsigned char *encrypted_bytes_out)
{
	int encrypted_bytes_size;
	if(!EVP_EncryptUpdate(sym_cipher_context, encrypted_bytes_out, &encrypted_bytes_size, plain_bytes, plain_bytes_size))
	{
		char *error=otb_openssl_errors_as_string();
		g_warning(_("%s: Failed to encrypt data. Error == %s"), "otb_sym_cipher_encrypt", error);
		g_free(error);
		encrypted_bytes_size=0;
	}
	return (size_t)encrypted_bytes_size;
}

size_t otb_sym_cipher_decrypt(OtbSymCipherContext *sym_cipher_context, const unsigned char *encrypted_bytes, size_t encrypted_bytes_size, unsigned char *plain_bytes_out)
{
	int plain_bytes_size;
	if(!EVP_DecryptUpdate(sym_cipher_context, plain_bytes_out, &plain_bytes_size, encrypted_bytes, encrypted_bytes_size))
	{
		char *error=otb_openssl_errors_as_string();
		g_warning(_("%s: Failed to decrypt data. Error == %s"), "otb_sym_cipher_decrypt", error);
		g_free(error);
		plain_bytes_size=0;
	}
	return (size_t)plain_bytes_size;
}

size_t otb_sym_cipher_finish_encrypt(OtbSymCipherContext *sym_cipher_context, unsigned char *encrypted_bytes_out)
{
	int encrypted_bytes_size;
	if(!EVP_EncryptFinal_ex(sym_cipher_context, encrypted_bytes_out, &encrypted_bytes_size))
	{
		char *error=otb_openssl_errors_as_string();
		g_warning(_("%s: Failed to encrypt final data. Error == %s"), "otb_sym_cipher_finish_encrypt", error);
		g_free(error);
		encrypted_bytes_size=0;
	}
	otb_sym_cipher_context_free(sym_cipher_context);
	return (size_t)encrypted_bytes_size;
}

size_t otb_sym_cipher_finish_decrypt(OtbSymCipherContext *sym_cipher_context, unsigned char *plain_bytes_out)
{
	int plain_bytes_size;
	if(!EVP_DecryptFinal_ex(sym_cipher_context, plain_bytes_out, &plain_bytes_size))
	{
		char *error=otb_openssl_errors_as_string();
		g_warning(_("%s: Failed to decrypt final data. Error == %s"), "otb_sym_cipher_finish_decrypt", error);
		g_free(error);
		plain_bytes_size=0;
	}
	
	otb_sym_cipher_context_free(sym_cipher_context);
	return (size_t)plain_bytes_size;
}
