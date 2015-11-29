/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <glib.h>

#include "sym-cipher.h"
#include "io.h"
#include "settings.h"

#define CONFIG_GROUP			"local-crypto"
#define CONFIG_SYM_CIPHER		"sym-cipher"
#define CONFIG_MESSAGE_DIGEST	"message-digest"
#define CONFIG_HASH_ITERATIONS	"hash-iterations"
#define CONFIG_KEY				"key"
#define CONFIG_KEY_SALT			"key-salt"
#define CONFIG_PASSPHRASE_HASH	"passphrase-hash"
#define CONFIG_PASSPHRASE_SALT	"passphrase-salt"

static GRWLock otb_local_crypto_lock;
static OtbSymCipher *otb_local_crypto_sym_cipher=NULL;

#define otb_local_crypto_lock_read()	(g_rw_lock_reader_lock(&otb_local_crypto_lock))
#define otb_local_crypto_unlock_read()	(g_rw_lock_reader_unlock(&otb_local_crypto_lock))
#define otb_local_crypto_lock_write()	(g_rw_lock_writer_lock(&otb_local_crypto_lock))
#define otb_local_crypto_unlock_write()	(g_rw_lock_writer_unlock(&otb_local_crypto_lock))

gboolean otb_local_crypto_can_be_unlocked()
{
	GBytes *passphrase_hash=NULL;
	passphrase_hash=otb_settings_get_config_gbytes(CONFIG_GROUP, CONFIG_PASSPHRASE_HASH);
	gboolean local_crypto_can_be_unlocked=(passphrase_hash!=NULL);
	g_bytes_unref(passphrase_hash);
	return local_crypto_can_be_unlocked;
}

static void otb_local_crypto_new_sym_cipher_initialize_string_property(OtbSymCipher *sym_cipher, const char *config_key, const char *sym_cipher_property)
{
	char *value=otb_settings_get_config_string(CONFIG_GROUP, config_key);
	if(G_UNLIKELY(value==NULL))
	{
		char *defaulted_value;
		g_object_get(sym_cipher, sym_cipher_property, &defaulted_value, NULL);
		otb_settings_set_config_string(CONFIG_GROUP, config_key, defaulted_value);
		g_free(defaulted_value);
	}
	else
		g_object_set(sym_cipher, sym_cipher_property, value, NULL);
	g_free(value);
}

static void otb_local_crypto_new_sym_cipher_initialize_int_property(OtbSymCipher *sym_cipher, const char *config_key, int error_value, const char *sym_cipher_property)
{
	int value=otb_settings_get_config_int(CONFIG_GROUP, config_key, error_value);
	if(G_UNLIKELY(value==error_value))
	{
		int defaulted_value;
		g_object_get(sym_cipher, sym_cipher_property, &defaulted_value, NULL);
		otb_settings_set_config_int(CONFIG_GROUP, config_key, defaulted_value);
	}
	else
		g_object_set(sym_cipher, sym_cipher_property, value, NULL);
}

static OtbSymCipher *otb_local_crypto_new_sym_cipher()
{
	OtbSymCipher *sym_cipher=g_object_new(OTB_TYPE_SYM_CIPHER, NULL);
	otb_local_crypto_new_sym_cipher_initialize_string_property(sym_cipher, CONFIG_SYM_CIPHER, OTB_SYM_CIPHER_PROP_CIPHER);
	otb_local_crypto_new_sym_cipher_initialize_string_property(sym_cipher, CONFIG_MESSAGE_DIGEST, OTB_SYM_CIPHER_PROP_MESSAGE_DIGEST);
	otb_local_crypto_new_sym_cipher_initialize_int_property(sym_cipher, CONFIG_HASH_ITERATIONS, 0, OTB_SYM_CIPHER_PROP_HASH_ITERATIONS);
	return sym_cipher;
}

static gboolean otb_local_crypto_set_passphrase(OtbSymCipher *sym_cipher, const char *passphrase)
{
	gboolean ret_val=TRUE;
	OtbSymCipherSalt *passphrase_salt=NULL;
	OtbSymCipherSalt *wrapped_key_salt=NULL;
	GBytes *passphrase_hash=NULL;
	GBytes *wrapped_key=NULL;
	if(G_UNLIKELY((passphrase_hash=otb_sym_cipher_hash_passphrase(sym_cipher, passphrase, &passphrase_salt))==NULL))
		ret_val=FALSE;
	else if(G_UNLIKELY((wrapped_key=otb_sym_cipher_wrap_key(sym_cipher, passphrase, &wrapped_key_salt))==NULL))
		ret_val=FALSE;
	else if(G_UNLIKELY(!otb_settings_set_config_bytes(CONFIG_GROUP, CONFIG_PASSPHRASE_SALT, otb_sym_cipher_salt_get_bytes(passphrase_salt), OTB_SYM_CIPHER_SALT_BYTES_LENGTH)))
		ret_val=FALSE;
	else if(G_UNLIKELY(!otb_settings_set_config_gbytes(CONFIG_GROUP, CONFIG_PASSPHRASE_HASH, passphrase_hash)))
		ret_val=FALSE;
	else if(G_UNLIKELY(!otb_settings_set_config_bytes(CONFIG_GROUP, CONFIG_KEY_SALT, otb_sym_cipher_salt_get_bytes(wrapped_key_salt), OTB_SYM_CIPHER_SALT_BYTES_LENGTH)))
		ret_val=FALSE;
	else if(G_UNLIKELY(!otb_settings_set_config_gbytes(CONFIG_GROUP, CONFIG_KEY, wrapped_key)))
		ret_val=FALSE;
	g_bytes_unref(wrapped_key);
	g_bytes_unref(passphrase_hash);
	otb_sym_cipher_salt_free(wrapped_key_salt);
	otb_sym_cipher_salt_free(passphrase_salt);
	return ret_val;
}

static void otb_local_crypto_set_local_sym_cipher(OtbSymCipher *sym_cipher)
{
	otb_local_crypto_lock_write();
	OtbSymCipher *old_sym_cipher=otb_local_crypto_sym_cipher;
	otb_local_crypto_sym_cipher=sym_cipher;
	otb_local_crypto_unlock_write();
	if(old_sym_cipher!=NULL)
		g_object_unref(old_sym_cipher);
}

gboolean otb_local_crypto_create_sym_cipher(const char *passphrase)
{
	gboolean creation_successful=TRUE;
	OtbSymCipher *sym_cipher=otb_local_crypto_new_sym_cipher();
	if(G_UNLIKELY(!otb_sym_cipher_generate_random_key(sym_cipher)))
		creation_successful=FALSE;
	else if(G_UNLIKELY(!otb_local_crypto_set_passphrase(sym_cipher, passphrase)))
		creation_successful=FALSE;
	if(G_LIKELY(creation_successful))
		otb_local_crypto_set_local_sym_cipher(sym_cipher);
	else
		g_object_unref(sym_cipher);
	return creation_successful;
}

static gboolean otb_local_crypto_validate_passphrase(OtbSymCipher *sym_cipher, const char *passphrase)
{
	gboolean validate_successful=TRUE;
	unsigned char *passphrase_salt_bytes=NULL;
	GBytes *passphrase_hash=NULL;
	if(G_UNLIKELY((passphrase_salt_bytes=otb_settings_get_config_bytes(CONFIG_GROUP, CONFIG_PASSPHRASE_SALT, NULL))==NULL))
		validate_successful=FALSE;
	else if(G_UNLIKELY((passphrase_hash=otb_settings_get_config_gbytes(CONFIG_GROUP, CONFIG_PASSPHRASE_HASH))==NULL))
		validate_successful=FALSE;
	else
	{
		OtbSymCipherSalt *passphrase_salt=otb_sym_cipher_salt_from_bytes(passphrase_salt_bytes);
		if(!otb_sym_cipher_validate_passphrase(sym_cipher, passphrase, passphrase_hash, passphrase_salt))
			validate_successful=FALSE;
		otb_sym_cipher_salt_free(passphrase_salt);
	}
	g_bytes_unref(passphrase_hash);
	g_free(passphrase_salt_bytes);
	return validate_successful;
}

gboolean otb_local_crypto_unlock_sym_cipher(const char *passphrase)
{
	gboolean unlock_successful=TRUE;
	OtbSymCipher *sym_cipher=otb_local_crypto_new_sym_cipher();
	unsigned char *wrapped_key_salt_bytes=NULL;
	GBytes *wrapped_key=NULL;
	if(!otb_local_crypto_validate_passphrase(sym_cipher, passphrase))
		unlock_successful=FALSE;
	else if(G_UNLIKELY((wrapped_key_salt_bytes=otb_settings_get_config_bytes(CONFIG_GROUP, CONFIG_KEY_SALT, NULL))==NULL))
		unlock_successful=FALSE;
	else if(G_UNLIKELY((wrapped_key=otb_settings_get_config_gbytes(CONFIG_GROUP, CONFIG_KEY))==NULL))
		unlock_successful=FALSE;
	else
	{
		OtbSymCipherSalt *wrapped_key_salt=otb_sym_cipher_salt_from_bytes(wrapped_key_salt_bytes);
		if(!otb_sym_cipher_unwrap_key(sym_cipher, wrapped_key, passphrase, wrapped_key_salt))
			unlock_successful=FALSE;
		otb_sym_cipher_salt_free(wrapped_key_salt);
	}
	g_bytes_unref(wrapped_key);
	g_free(wrapped_key_salt_bytes);
	if(unlock_successful)
		otb_local_crypto_set_local_sym_cipher(sym_cipher);
	else
		g_object_unref(sym_cipher);
	return unlock_successful;
}

void otb_local_crypto_lock_sym_cipher()
{
	otb_local_crypto_set_local_sym_cipher(NULL);
}

gboolean otb_local_crypto_change_passphrase(const char *old_passphrase, const char *new_passphrase)
{
	gboolean ret_val=TRUE;
	otb_local_crypto_lock_read();
	if(G_UNLIKELY(otb_local_crypto_sym_cipher==NULL))
		ret_val=FALSE;
	else if(!otb_local_crypto_validate_passphrase(otb_local_crypto_sym_cipher, old_passphrase))
		ret_val=FALSE;
	else if(!otb_local_crypto_set_passphrase(otb_local_crypto_sym_cipher, new_passphrase))
		ret_val=FALSE;
	otb_local_crypto_unlock_read();
	return ret_val;
}

OtbSymCipher *otb_local_crypto_get_sym_cipher_with_ref()
{
	otb_local_crypto_lock_read();
	OtbSymCipher *sym_cipher=otb_local_crypto_sym_cipher;
	g_object_ref(sym_cipher);
	otb_local_crypto_unlock_read();
	return sym_cipher;
}