/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_CIPHER_H
#define OTB_CIPHER_H

#include <glib-object.h>
#include <openssl/evp.h>

typedef EVP_CIPHER_CTX OtbCipherContext;
typedef char OtbCipherSalt[PKCS5_SALT_LEN];

#define otb_cipher_context_free(cipher_context)	EVP_CIPHER_CTX_free(cipher_context)

#define OTB_CIPHER_PROP_CIPHER			"cipher"
#define OTB_CIPHER_PROP_MESSAGE_DIGEST	"message_digest"
#define OTB_CIPHER_PROP_HASH_ITERATIONS	"hash_iterations"

#define OTB_TYPE_CIPHER				(otb_cipher_get_type())
#define OTB_CIPHER(obj)				(G_TYPE_CHECK_INSTANCE_CAST((obj), OTB_TYPE_CIPHER, OtbCipher))
#define OTB_IS_CIPHER(obj)			(G_TYPE_CHECK_INSTANCE_TYPE((obj), OTB_TYPE_CIPHER))
#define OTB_CIPHER_CLASS(klass)		(G_TYPE_CHECK_CLASS_CAST((klass), OTB_TYPE_CIPHER, OtbCipherClass))
#define OTB_IS_CIPHER_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE((klass), OTB_TYPE_CIPHER))
#define OTB_CIPHER_GET_CLASS(obj)	(G_TYPE_CHECK_CLASS_TYPE((obj), OTB_TYPE_CIPHER, OtbCipherClass))

typedef struct _OtbCipher OtbCipher;
typedef struct _OtbCipherClass OtbCipherClass;
typedef struct _OtbCipherPrivate OtbCipherPrivate;

struct _OtbCipher
{
	GObject parent_instance;
	OtbCipherPrivate *priv;
};

struct _OtbCipherClass
{
	GObjectClass parent_class;
};

GType otb_cipher_get_type();

GBytes *otb_cipher_hash_passphrase(const OtbCipher *cipher, const char *passphrase, OtbCipherSalt salt_out);
gboolean otb_cipher_validate_passphrase(const OtbCipher *cipher, const char *passphrase, GBytes *passphrase_hash, OtbCipherSalt salt);
gboolean otb_cipher_unwrap_key(OtbCipher *cipher, GBytes *wrapped_key, const char *passphrase, OtbCipherSalt salt);
GBytes *otb_cipher_wrap_key(const OtbCipher *cipher, const char *passphrase, OtbCipherSalt salt_out);
gboolean otb_cipher_generate_random_key(OtbCipher *cipher);
unsigned char *otb_cipher_create_encryption_buffer(const OtbCipher *cipher, size_t plain_bytes_buffer_size, size_t *encryption_buffer_size_out);
unsigned char *otb_cipher_create_decryption_buffer(const OtbCipher *cipher, size_t encrypted_bytes_buffer_size, size_t *decryption_buffer_size_out);
OtbCipherContext *otb_cipher_init_encryption(const OtbCipher *cipher, GBytes **iv_out);
OtbCipherContext *otb_cipher_init_decryption(const OtbCipher *cipher, GBytes *iv);
size_t otb_cipher_encrypt(OtbCipherContext *cipher_context, const unsigned char *plain_bytes, size_t plain_bytes_size, unsigned char *encrypted_bytes_out);
size_t otb_cipher_decrypt(OtbCipherContext *cipher_context, const unsigned char *encrypted_bytes, size_t encrypted_bytes_size, unsigned char *plain_bytes_out);
size_t otb_cipher_finish_encrypt(OtbCipherContext *cipher_context, unsigned char *encrypted_bytes_out);
size_t otb_cipher_finish_decrypt(OtbCipherContext *cipher_context, unsigned char *plain_bytes_out);

#endif
