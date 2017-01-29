/**
 * Copyright © 2015 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_ASYM_CIPHER_H
#define OTB_ASYM_CIPHER_H

#include <glib-object.h>
#include <openssl/evp.h>

#include "openssl-util.h"
#include "sym-cipher.h"

#define OTB_ASYM_CIPHER_DEFAULT_KEY_SIZE	4096
#define OTB_ASYM_CIPHER_DEFAULT_CIPHER		"AES-256-CBC"

typedef EVP_CIPHER_CTX OtbAsymCipherContext;

#define otb_asym_cipher_context_free(cipher_context)					EVP_CIPHER_CTX_free(cipher_context)
#define otb_asym_cipher_dispose_decryption_buffer(decryption_buffer)	otb_openssl_dispose_decryption_buffer((decryption_buffer))

#define OTB_ASYM_CIPHER_PROP_SYM_CIPHER_NAME	"sym-cipher-name"
#define OTB_ASYM_CIPHER_PROP_KEY_SIZE			"key-size"
#define OTB_ASYM_CIPHER_PROP_PUBLIC_KEY			"public-key"

#define OTB_TYPE_ASYM_CIPHER			(otb_asym_cipher_get_type())
#define OTB_ASYM_CIPHER(obj)			(G_TYPE_CHECK_INSTANCE_CAST((obj), OTB_TYPE_ASYM_CIPHER, OtbAsymCipher))
#define OTB_IS_ASYM_CIPHER(obj)			(G_TYPE_CHECK_INSTANCE_TYPE((obj), OTB_TYPE_ASYM_CIPHER))
#define OTB_ASYM_CIPHER_CLASS(klass)	(G_TYPE_CHECK_CLASS_CAST((klass), OTB_TYPE_ASYM_CIPHER, OtbAsymCipherClass))
#define OTB_IS_ASYM_CIPHER_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE((klass), OTB_TYPE_ASYM_CIPHER))
#define OTB_ASYM_CIPHER_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS((obj), OTB_TYPE_ASYM_CIPHER, OtbAsymCipherClass))

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
gboolean otb_asym_cipher_generate_random_keys(OtbAsymCipher *asym_cipher);
unsigned char *otb_asym_cipher_create_encryption_buffer(const OtbAsymCipher *asym_cipher, size_t plain_bytes_buffer_size);	// FARE - size_t è il migliore? (In generale.)
void *otb_asym_cipher_create_decryption_buffer(const OtbAsymCipher *asym_cipher, size_t encrypted_bytes_buffer_size);
OtbAsymCipherContext *otb_asym_cipher_init_encryption(const OtbAsymCipher *asym_cipher, GBytes **encrypted_key_out, GBytes **iv_out);
OtbAsymCipherContext *otb_asym_cipher_init_decryption(const OtbAsymCipher *asym_cipher, GBytes *encrypted_key, GBytes *iv);
size_t otb_asym_cipher_encrypt_next(OtbAsymCipherContext *asym_cipher_context, const void *plain_bytes, size_t plain_bytes_size, unsigned char *encrypted_bytes);
size_t otb_asym_cipher_decrypt_next(OtbAsymCipherContext *asym_cipher_context, const unsigned char *encrypted_bytes, size_t encrypted_bytes_size, void *plain_bytes);
size_t otb_asym_cipher_finish_encrypt(OtbAsymCipherContext *asym_cipher_context, unsigned char *encrypted_bytes);
size_t otb_asym_cipher_finish_decrypt(OtbAsymCipherContext *asym_cipher_context, void *plain_bytes);
unsigned char *otb_asym_cipher_encrypt(const OtbAsymCipher *asym_cipher, const void *plain_bytes, size_t plain_bytes_size, GBytes **encrypted_key_out, GBytes **iv_out, size_t *encrypted_bytes_size_out);
void *otb_asym_cipher_decrypt(const OtbAsymCipher *asym_cipher, const unsigned char *encrypted_bytes, size_t encrypted_bytes_size, GBytes *encrypted_key, GBytes *iv, size_t *plain_bytes_size_out);

#endif
