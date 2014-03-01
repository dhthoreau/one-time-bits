/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_ASYM_CIPHER_H
#define OTB_ASYM_CIPHER_H

#include <glib-object.h>
#include <openssl/evp.h>

#include "sym-cipher.h"

typedef EVP_CIPHER_CTX OtbAsymCipherContext;

#define otb_asym_cipher_context_free(cipher_context)	EVP_CIPHER_CTX_free(cipher_context)

#define OTB_ASYM_CIPHER_DEFAULT_KEY_SIZE	4096

#define OTB_ASYM_CIPHER_PROP_SYM_CIPHER	"sym-cipher"

#define OTB_TYPE_ASYM_CIPHER			(otb_asym_cipher_get_type())
#define OTB_ASYM_CIPHER(obj)			(G_TYPE_CHECK_INSTANCE_CAST((obj), OTB_TYPE_ASYM_CIPHER, OtbAsymCipher))
#define OTB_IS_ASYM_CIPHER(obj)			(G_TYPE_CHECK_INSTANCE_TYPE((obj), OTB_TYPE_ASYM_CIPHER))
#define OTB_ASYM_CIPHER_CLASS(klass)	(G_TYPE_CHECK_CLASS_CAST((klass), OTB_TYPE_ASYM_CIPHER, OtbAsymCipherClass))
#define OTB_IS_ASYM_CIPHER_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE((klass), OTB_TYPE_ASYM_CIPHER))
#define OTB_ASYM_CIPHER_GET_CLASS(obj)	(G_TYPE_CHECK_CLASS_TYPE((obj), OTB_TYPE_ASYM_CIPHER, OtbAsymCipherClass))

typedef struct _OtbAsymCipher OtbAsymCipher;
typedef struct _OtbAsymCipherClass OtbAsymCipherClass;
typedef struct _OtbAsymCipherPrivate OtbAsymCipherPrivate;

struct _OtbAsymCipher
{
	GObject parent_instance;
	OtbAsymCipherPrivate *priv;
};

struct _OtbAsymCipherClass
{
	GObjectClass parent_class;
};

GType otb_asym_cipher_get_type();

void otb_asym_cipher_set_encrypted_private_key(const OtbAsymCipher *asym_cipher, GBytes *encrypted_private_key, OtbSymCipher *private_key_sym_cipher, GBytes *private_key_iv);
GBytes *otb_asym_cipher_get_encrypted_private_key(const OtbAsymCipher *asym_cipher, OtbSymCipher *private_key_sym_cipher, GBytes **private_key_iv_out);
void otb_asym_cipher_set_public_key(const OtbAsymCipher *asym_cipher, char *public_key);	// FARE - Dovrebbe essere una property.
char *otb_asym_cipher_get_public_key(const OtbAsymCipher *asym_cipher);
gboolean otb_asym_cipher_generate_random_keys(OtbAsymCipher *asym_cipher, size_t key_size);
unsigned char *otb_asym_cipher_create_encryption_buffer(const OtbAsymCipher *asym_cipher, size_t plain_bytes_buffer_size, size_t *encryption_buffer_size_out);
unsigned char *otb_asym_cipher_create_decryption_buffer(const OtbAsymCipher *asym_cipher, size_t encrypted_bytes_buffer_size, size_t *decryption_buffer_size_out);
OtbAsymCipherContext *otb_asym_cipher_init_encryption(const OtbAsymCipher *asym_cipher, GBytes **encrypted_key_out, GBytes **iv_out);
OtbAsymCipherContext *otb_asym_cipher_init_decryption(const OtbAsymCipher *asym_cipher, GBytes *encrypted_key, GBytes *iv);
size_t otb_asym_cipher_encrypt(OtbAsymCipherContext *asym_cipher_context, const void *plain_bytes, size_t plain_bytes_size, void *encrypted_bytes_out);
size_t otb_asym_cipher_decrypt(OtbAsymCipherContext *asym_cipher_context, const void *encrypted_bytes, size_t encrypted_bytes_size, void *plain_bytes_out);
size_t otb_asym_cipher_finish_encrypt(OtbAsymCipherContext *asym_cipher_context, void *encrypted_bytes_out);
size_t otb_asym_cipher_finish_decrypt(OtbAsymCipherContext *asym_cipher_context, void *plain_bytes_out);

#endif
