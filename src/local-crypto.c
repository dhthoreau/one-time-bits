/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <glib.h>

#include "cipher.h"
#include "io.h"
#include "settings.h"

#define CONFIG_GROUP			"local-crypto"
#define CONFIG_CIPHER			"cipher"
#define CONFIG_MESSAGE_DIGEST	"message-digest"
#define CONFIG_HASH_ITERATIONS	"hash-iterations"
#define CONFIG_KEY				"key"
#define CONFIG_KEY_SALT			"key-salt"
#define CONFIG_PASSPHRASE_HASH	"passphrase-hash"
#define CONFIG_PASSPHRASE_SALT	"passphrase-salt"

static GMutex mutex;
static OtbCipher *local_cipher=NULL;

static void otb_local_crypto_lock()
{
	g_mutex_lock(&mutex);
}

static void otb_local_crypto_unlock()
{
	g_mutex_unlock(&mutex);
}

static void otb_local_crypto_new_initialize_string_property(OtbCipher *cipher, const char *config_key, const char *cipher_property)
{
	char *value=otb_settings_get_config_string(CONFIG_GROUP, config_key, "otb_local_crypto_new_initialize_string_property");
	if(value==NULL)
	{
		char *defaulted_value;
		g_object_get(cipher, cipher_property, &defaulted_value, NULL);
		otb_settings_set_config_string(CONFIG_GROUP, config_key, defaulted_value);
		g_free(defaulted_value);
	}
	else
		g_object_set(cipher, cipher_property, value, NULL);
	g_free(value);
}

static void otb_local_crypto_new_initialize_int_property(OtbCipher *cipher, const char *config_key, int error_value, const char *cipher_property)
{
	int value=otb_settings_get_config_int(CONFIG_GROUP, config_key, error_value);
	if(value==error_value)
	{
		int defaulted_value;
		g_object_get(cipher, cipher_property, &defaulted_value, NULL);
		otb_settings_set_config_int(CONFIG_GROUP, config_key, defaulted_value);
	}
	else
		g_object_set(cipher, cipher_property, value, NULL);
}

static OtbCipher *otb_local_crypto_new()
{
	OtbCipher *cipher=g_object_new(OTB_TYPE_CIPHER, NULL);
	otb_local_crypto_new_initialize_string_property(cipher, CONFIG_CIPHER, OTB_CIPHER_PROP_CIPHER);
	otb_local_crypto_new_initialize_string_property(cipher, CONFIG_MESSAGE_DIGEST, OTB_CIPHER_PROP_MESSAGE_DIGEST);
	otb_local_crypto_new_initialize_int_property(cipher, CONFIG_HASH_ITERATIONS, 0, OTB_CIPHER_PROP_HASH_ITERATIONS);
	return cipher;
}

static gboolean otb_local_crypto_set_passphrase(OtbCipher *cipher, const char *passphrase)
{
	gboolean ret_val=TRUE;
	OtbCipherSalt passphrase_salt;
	OtbCipherSalt wrapped_key_salt;
	GBytes *passphrase_hash=NULL;
	GBytes *wrapped_key=NULL;
	if((passphrase_hash=otb_cipher_hash_passphrase(cipher, passphrase, passphrase_salt))==NULL)
		ret_val=FALSE;
	else if((wrapped_key=otb_cipher_wrap_key(cipher, passphrase, wrapped_key_salt))==NULL)
		ret_val=FALSE;
	else if(!otb_settings_set_config_bytes(CONFIG_GROUP, CONFIG_PASSPHRASE_SALT, passphrase_salt, sizeof passphrase_salt))
		ret_val=FALSE;
	else if(!otb_settings_set_config_gbytes(CONFIG_GROUP, CONFIG_PASSPHRASE_HASH, passphrase_hash))
		ret_val=FALSE;
	else if(!otb_settings_set_config_bytes(CONFIG_GROUP, CONFIG_KEY_SALT, wrapped_key_salt, sizeof wrapped_key_salt))
		ret_val=FALSE;
	else if(!otb_settings_set_config_gbytes(CONFIG_GROUP, CONFIG_KEY, wrapped_key))
		ret_val=FALSE;
	g_bytes_unref(passphrase_hash);
	g_bytes_unref(wrapped_key);
}

static void otb_local_crypto_set_local_cipher(OtbCipher *cipher)
{
	otb_local_crypto_lock();
	OtbCipher *old_cipher=local_cipher;
	local_cipher=cipher;
	otb_local_crypto_unlock();
	if(old_cipher!=NULL)
		g_object_unref(old_cipher);
}

gboolean otb_local_crypto_create_cipher(const char *passphrase)
{
	gboolean creation_successful=TRUE;
	OtbCipher *cipher=otb_local_crypto_new();
	if(!otb_cipher_generate_random_key(cipher))
		creation_successful=FALSE;
	else if(!otb_local_crypto_set_passphrase(cipher, passphrase))
		creation_successful=FALSE;
	if(!creation_successful)
		g_object_unref(cipher);
	else
		otb_local_crypto_set_local_cipher(cipher);
	return creation_successful;
}

static gboolean otb_local_crypto_validate_passphrase(OtbCipher *cipher, const char *passphrase)
{
	gboolean validate_successful=TRUE;
	OtbCipherSalt *passphrase_salt=NULL;
	GBytes *passphrase_hash=NULL;
	if((passphrase_salt=(OtbCipherSalt*)otb_settings_get_config_bytes(CONFIG_GROUP, CONFIG_PASSPHRASE_SALT, NULL))==NULL)
		validate_successful=FALSE;
	else if((passphrase_hash=otb_settings_get_config_gbytes(CONFIG_GROUP, CONFIG_PASSPHRASE_HASH))==NULL)
		validate_successful=FALSE;
	else if(!otb_cipher_validate_passphrase(cipher, passphrase, passphrase_hash, *passphrase_salt))
		validate_successful=FALSE;
	g_bytes_unref(passphrase_hash);
	g_free(passphrase_salt);
	return validate_successful;
}

gboolean otb_local_crypto_unlock_cipher(const char *passphrase)
{
	gboolean unlock_successful=TRUE;
	OtbCipher *cipher=otb_local_crypto_new();
	OtbCipherSalt *wrapped_key_salt=NULL;
	GBytes *wrapped_key=NULL;
	if(!otb_local_crypto_validate_passphrase(cipher, passphrase))
		unlock_successful=FALSE;
	else if((wrapped_key_salt=(OtbCipherSalt*)otb_settings_get_config_bytes(CONFIG_GROUP, CONFIG_KEY_SALT, NULL))==NULL)
		unlock_successful=FALSE;
	else if((wrapped_key=otb_settings_get_config_gbytes(CONFIG_GROUP, CONFIG_KEY))==NULL)
		unlock_successful=FALSE;
	else if(!otb_cipher_unwrap_key(cipher, wrapped_key, passphrase, *wrapped_key_salt))
		unlock_successful=FALSE;
	g_free(wrapped_key_salt);
	g_bytes_unref(wrapped_key);
	if(!unlock_successful)
		g_object_unref(cipher);
	else
		otb_local_crypto_set_local_cipher(cipher);
	return unlock_successful;
}

gboolean otb_local_crypto_change_passphrase(const char *old_passphrase, const char *new_passphrase)
{
	gboolean ret_val=TRUE;
	otb_local_crypto_lock();
	if(local_cipher==NULL)
		ret_val=FALSE;
	else if(!otb_local_crypto_validate_passphrase(local_cipher, old_passphrase))
		ret_val=FALSE;
	else if(!otb_local_crypto_set_passphrase(local_cipher, new_passphrase))
		ret_val=FALSE;
	otb_local_crypto_unlock();
	return ret_val;
}

const OtbCipher *otb_local_crypto_get_cipher()
{
	otb_local_crypto_lock();
	OtbCipher *crypto=local_cipher;
	otb_local_crypto_unlock();
	return crypto;
}
