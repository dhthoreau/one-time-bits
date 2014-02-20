/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <glib/gi18n.h>

#include "cipher.h"
#include "export.h"
#include "io.h"
#include "memory.h"
#include "openssl-util.h"
#include "random.h"
#include "smem.h"

#define DEFAULT_CIPHER			"AES-256-CBC"
#define DEFAULT_MESSAGE_DIGEST	"SHA512"
#define DEFAULT_HASH_ITERATIONS	20480

#define CIPHER_CONTEXT_ONE_KEY_INDEX	0
#define CIPHER_CONTEXT_TWO_KEY_INDEX	1

struct _OtbCipherPrivate
{
	char *key;
	size_t key_size;
	const EVP_CIPHER *cipher_impl;
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

static void otb_cipher_finalize(GObject *object);
static void otb_cipher_set_property(GObject *object, unsigned int prop_id, const GValue *value, GParamSpec *pspec);
static void otb_cipher_get_property(GObject *object, unsigned int prop_id, GValue *value, GParamSpec *pspec);

G_DEFINE_TYPE(OtbCipher, otb_cipher, G_TYPE_OBJECT);

static void otb_cipher_class_init(OtbCipherClass *klass)
{
	OpenSSL_add_all_algorithms();
	GObjectClass *object_class=G_OBJECT_CLASS(klass);
	object_class->finalize=otb_cipher_finalize;
	object_class->set_property=otb_cipher_set_property;
	object_class->get_property=otb_cipher_get_property;
	g_object_class_install_property(object_class, PROP_CIPHER, g_param_spec_string(OTB_CIPHER_PROP_CIPHER, _("Cipher"), _("Name of the cipher to use"), DEFAULT_CIPHER, G_PARAM_READWRITE | G_PARAM_CONSTRUCT));
	g_object_class_install_property(object_class, PROP_MESSAGE_DIGEST, g_param_spec_string(OTB_CIPHER_PROP_MESSAGE_DIGEST, _("Message digest"), _("Message digest to use for hashes"), DEFAULT_MESSAGE_DIGEST, G_PARAM_READWRITE | G_PARAM_CONSTRUCT));
	g_object_class_install_property(object_class, PROP_HASH_ITERATIONS, g_param_spec_uint(OTB_CIPHER_PROP_HASH_ITERATIONS, _("Hash iterations"), _("Number of iterations to go through when hashing"), 1, G_MAXUINT, DEFAULT_HASH_ITERATIONS, G_PARAM_READWRITE | G_PARAM_CONSTRUCT));
	g_type_class_add_private(klass, sizeof(OtbCipherPrivate));
}

static void otb_cipher_init(OtbCipher *cipher)
{
	cipher->priv=G_TYPE_INSTANCE_GET_PRIVATE(cipher, OTB_TYPE_CIPHER, OtbCipherPrivate);
	cipher->priv->key=NULL;
	cipher->priv->key_size=0;
	cipher->priv->cipher_impl=NULL;
	cipher->priv->message_digest_impl=NULL;
	cipher->priv->hash_iterations=0;
}

static void otb_cipher_set_key(OtbCipher *cipher, char *key, size_t key_size)
{
	if(cipher->priv->key!=NULL)
	{
		smemset(cipher->priv->key, 0, cipher->priv->key_size);
		g_free(cipher->priv->key);
	}
	cipher->priv->key=key;
	cipher->priv->key_size=key_size;
}

static void otb_cipher_finalize(GObject *object)
{
	g_return_if_fail(object!=NULL);
	g_return_if_fail(OTB_IS_CIPHER(object));
	OtbCipher *cipher=OTB_CIPHER(object);
	otb_cipher_set_key(cipher, NULL, 0);
	cipher->priv->key=NULL;
	G_OBJECT_CLASS(otb_cipher_parent_class)->finalize(object);
}

static void otb_cipher_set_property(GObject *object, unsigned int prop_id, const GValue *value, GParamSpec *pspec)
{
	OtbCipher *cipher=OTB_CIPHER(object);
	const char *string_value;
	switch(prop_id)
	{
		case PROP_CIPHER:
			string_value=g_value_get_string(value);
			cipher->priv->cipher_impl=_EVP_get_cipherbyname(string_value);
			break;
		case PROP_MESSAGE_DIGEST:
			string_value=g_value_get_string(value);
			cipher->priv->message_digest_impl=EVP_get_digestbyname(string_value);
			break;
		case PROP_HASH_ITERATIONS:
			cipher->priv->hash_iterations=g_value_get_uint(value);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
	}
}

static void otb_cipher_get_property(GObject *object, unsigned int prop_id, GValue *value, GParamSpec *pspec)
{
	OtbCipher *cipher=OTB_CIPHER(object);
	switch(prop_id)
	{
		case PROP_CIPHER:
			g_value_set_string(value, EVP_CIPHER_name(cipher->priv->cipher_impl));
			break;
		case PROP_MESSAGE_DIGEST:
			g_value_set_string(value, EVP_MD_name(cipher->priv->message_digest_impl));
			break;
		case PROP_HASH_ITERATIONS:
			g_value_set_uint(value, cipher->priv->hash_iterations);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
			break;
	}
}

GBytes *otb_cipher_hash_passphrase(const OtbCipher *cipher, const unsigned char *passphrase, OtbCipherSalt salt_out)
{
	GBytes *hash=NULL;
	size_t hash_size=EVP_MD_size(cipher->priv->message_digest_impl);
	char *hash_bytes=g_malloc(hash_size);
	if(otb_random_bytes(salt_out, sizeof salt_out) && PKCS5_PBKDF2_HMAC(passphrase, strlen(passphrase), salt_out, sizeof salt_out, cipher->priv->hash_iterations, cipher->priv->message_digest_impl, hash_size, hash_bytes))
		hash=g_bytes_new_take(hash_bytes, hash_size);
	else
		g_free(hash_bytes);
	return hash;
}

gboolean otb_cipher_validate_passphrase(const OtbCipher *cipher, const unsigned char *passphrase, GBytes *passphrase_hash, OtbCipherSalt salt)
{
	gboolean ret_val=FALSE;
	size_t hash_size;
	const char *passphrase_hash_bytes=g_bytes_get_data(passphrase_hash, &hash_size);
	char *hash_bytes=g_malloc(hash_size);
	if(PKCS5_PBKDF2_HMAC(passphrase, strlen(passphrase), salt, sizeof salt, cipher->priv->hash_iterations, cipher->priv->message_digest_impl, hash_size, hash_bytes) && smemcmp(passphrase_hash_bytes, hash_bytes, hash_size)==0)
		ret_val=TRUE;
	g_free(hash_bytes);
	return ret_val;
}

static OtbCipherContext *otb_cipher_init_encryption_openssl(const EVP_CIPHER *cipher, const char *key, const char *iv)
{
	OtbCipherContext *cipher_context=g_malloc(sizeof(OtbCipherContext));
	EVP_CIPHER_CTX_init(cipher_context[CIPHER_CONTEXT_ONE_KEY_INDEX]);
	if(!EVP_EncryptInit_ex(cipher_context[CIPHER_CONTEXT_ONE_KEY_INDEX], cipher, NULL, key, iv))
	{
		g_free(cipher_context);
		g_warning(_("%s: Failed to initialize encryption."), "otb_cipher_init_encryption_openssl");
	}
	return cipher_context;
}

static OtbCipherContext *otb_cipher_init_decryption_openssl(const EVP_CIPHER *cipher, const char *key, const char *iv)
{
	OtbCipherContext *cipher_context=g_malloc(sizeof(OtbCipherContext));
	EVP_CIPHER_CTX_init(cipher_context[CIPHER_CONTEXT_ONE_KEY_INDEX]);
	if(!EVP_DecryptInit_ex(cipher_context[CIPHER_CONTEXT_ONE_KEY_INDEX], cipher, NULL, key, iv))
	{
		g_free(cipher_context);
		g_warning(_("%s: Failed to initialize decryption."), "otb_cipher_init_decryption");
	}
	return cipher_context;
}

#define key_and_iv_size(cipher)	(EVP_CIPHER_key_length((cipher)->priv->cipher_impl)+EVP_CIPHER_iv_length((cipher)->priv->cipher_impl))

GBytes *otb_cipher_wrap_key(const OtbCipher *cipher, const unsigned char *passphrase, OtbCipherSalt salt_out)
{
	GBytes *wrapped_key=NULL;
	if(otb_random_bytes(salt_out, sizeof salt_out))
	{
		char *wrapping_key_and_iv=g_malloc(key_and_iv_size(cipher));
		if(PKCS5_PBKDF2_HMAC(passphrase, strlen(passphrase), salt_out, sizeof salt_out, cipher->priv->hash_iterations, cipher->priv->message_digest_impl, key_and_iv_size(cipher), wrapping_key_and_iv))
		{
			char *wrapped_key_bytes=otb_cipher_create_encryption_buffer(cipher, cipher->priv->key_size, NULL);
			OtbCipherContext *cipher_context=otb_cipher_init_encryption_openssl(cipher->priv->cipher_impl, wrapping_key_and_iv, wrapping_key_and_iv+EVP_CIPHER_key_length(cipher->priv->cipher_impl));
			size_t wrapped_key_size=otb_cipher_encrypt(cipher_context, cipher->priv->key, cipher->priv->key_size, wrapped_key_bytes);
			size_t final_bytes_size=otb_cipher_finish_encrypt(cipher_context, wrapped_key_bytes+wrapped_key_size);
			if(wrapped_key_size==-1)
				g_free(wrapped_key_bytes);
			else
				wrapped_key=g_bytes_new_take(wrapped_key_bytes, wrapped_key_size+final_bytes_size);
		}
		g_free(wrapping_key_and_iv);
	}
	return wrapped_key;
}

gboolean otb_cipher_unwrap_key(OtbCipher *cipher, GBytes *wrapped_key, const unsigned char *passphrase, OtbCipherSalt salt)
{
	gboolean ret_val=FALSE;
	char *wrapping_key_and_iv=g_malloc(key_and_iv_size(cipher));
	if(PKCS5_PBKDF2_HMAC(passphrase, strlen(passphrase), salt, sizeof salt, cipher->priv->hash_iterations, cipher->priv->message_digest_impl, key_and_iv_size(cipher), wrapping_key_and_iv))
	{
		char *key_bytes=otb_cipher_create_decryption_buffer(cipher, g_bytes_get_size(wrapped_key), NULL);
		OtbCipherContext *cipher_context=otb_cipher_init_decryption_openssl(cipher->priv->cipher_impl, wrapping_key_and_iv, wrapping_key_and_iv+EVP_CIPHER_key_length(cipher->priv->cipher_impl));
		size_t key_size=otb_cipher_decrypt(cipher_context, g_bytes_get_data(wrapped_key, NULL), g_bytes_get_size(wrapped_key), key_bytes);
		size_t final_bytes_size=otb_cipher_finish_decrypt(cipher_context, key_bytes+key_size);
		if(key_size==-1)
			g_free(key_bytes);
		else
		{
			otb_cipher_set_key(cipher, key_bytes, key_size);
			ret_val=TRUE;
		}
	}
	return ret_val;
}

gboolean otb_cipher_generate_random_key(OtbCipher *cipher)
{
	gboolean ret_val=TRUE;
	char *key=otb_create_random_bytes(EVP_CIPHER_key_length(cipher->priv->cipher_impl));
	if(key==NULL)
		ret_val=FALSE;
	else
		otb_cipher_set_key(cipher, key, EVP_CIPHER_key_length(cipher->priv->cipher_impl));
	return ret_val;
}

GBytes *otb_cipher_generate_random_iv(const OtbCipher *cipher)
{
	GBytes *iv=NULL;
	char *iv_bytes=otb_create_random_bytes(EVP_CIPHER_iv_length(cipher->priv->cipher_impl));
	if(iv_bytes!=NULL)
		iv=g_bytes_new_take(iv_bytes, EVP_CIPHER_iv_length(cipher->priv->cipher_impl));
	return iv;
}

char *otb_cipher_create_encryption_buffer(const OtbCipher *cipher, size_t plain_bytes_buffer_size, size_t *encryption_buffer_size_out)
{
	size_t size=plain_bytes_buffer_size+EVP_CIPHER_block_size(cipher->priv->cipher_impl)-1;
	if(encryption_buffer_size_out!=NULL)
		*encryption_buffer_size_out=size;
	return g_malloc(size);
}

char *otb_cipher_create_decryption_buffer(const OtbCipher *cipher, size_t encrypted_bytes_buffer_size, size_t *decryption_buffer_size_out)
{
	size_t size=encrypted_bytes_buffer_size+EVP_CIPHER_block_size(cipher->priv->cipher_impl);
	if(decryption_buffer_size_out!=NULL)
		*decryption_buffer_size_out=size;
	return g_malloc(size);
}

OtbCipherContext *otb_cipher_init_encryption(const OtbCipher *cipher, GBytes *iv)
{
	return otb_cipher_init_encryption_openssl(cipher->priv->cipher_impl, cipher->priv->key, g_bytes_get_data(iv, NULL));
}

OtbCipherContext *otb_cipher_init_decryption(const OtbCipher *cipher, GBytes *iv)
{
	return otb_cipher_init_decryption_openssl(cipher->priv->cipher_impl, cipher->priv->key, g_bytes_get_data(iv, NULL));
}

size_t otb_cipher_encrypt(OtbCipherContext *cipher_context, const char *plain_bytes, size_t plain_bytes_size, char *encrypted_bytes_out)
{
	int encrypted_bytes_size;
	if(!EVP_EncryptUpdate(cipher_context[CIPHER_CONTEXT_ONE_KEY_INDEX], encrypted_bytes_out, &encrypted_bytes_size, plain_bytes, plain_bytes_size))
	{
		char *error=otb_openssl_errors_as_string();
		g_warning(_("%s: Failed to encrypt data. Error == %s"), "otb_cipher_encrypt", error);
		g_free(error);
		encrypted_bytes_size=0;
	}
	return (size_t)encrypted_bytes_size;
}

size_t otb_cipher_decrypt(OtbCipherContext *cipher_context, const char *encrypted_bytes, size_t encrypted_bytes_size, char *plain_bytes_out)
{
	int plain_bytes_size;
	if(!EVP_DecryptUpdate(cipher_context[CIPHER_CONTEXT_ONE_KEY_INDEX], plain_bytes_out, &plain_bytes_size, encrypted_bytes, encrypted_bytes_size))
	{
		char *error=otb_openssl_errors_as_string();
		g_warning(_("%s: Failed to decrypt data. Error == %s"), "otb_cipher_decrypt", error);
		g_free(error);
		plain_bytes_size=0;
	}
	return (size_t)plain_bytes_size;
}

size_t otb_cipher_finish_encrypt(OtbCipherContext *cipher_context, char *encrypted_bytes_out)
{
	int encrypted_bytes_size;
	if(!EVP_EncryptFinal_ex(cipher_context[CIPHER_CONTEXT_ONE_KEY_INDEX], encrypted_bytes_out, &encrypted_bytes_size))
	{
		char *error=otb_openssl_errors_as_string();
		g_warning(_("%s: Failed to encrypt final data. Error == %s"), "otb_cipher_finish_encrypt", error);
		g_free(error);
		encrypted_bytes_size=0;
	}
	EVP_CIPHER_CTX_free(cipher_context[CIPHER_CONTEXT_ONE_KEY_INDEX]);
	return (size_t)encrypted_bytes_size;
}

size_t otb_cipher_finish_decrypt(OtbCipherContext *cipher_context, char *plain_bytes_out)
{
	int plain_bytes_size;
	if(!EVP_DecryptFinal_ex(cipher_context[CIPHER_CONTEXT_ONE_KEY_INDEX], plain_bytes_out, &plain_bytes_size))
	{
		char *error=otb_openssl_errors_as_string();
		g_warning(_("%s: Failed to decrypt final data. Error == %s"), "otb_cipher_finish_decrypt", error);
		g_free(error);
		plain_bytes_size=0;
	}
	EVP_CIPHER_CTX_free(cipher_context[CIPHER_CONTEXT_ONE_KEY_INDEX]);
	return (size_t)plain_bytes_size;
}
