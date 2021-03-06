/**
 * Copyright © 2017 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_SYM_CIPHER_H
#define OTB_SYM_CIPHER_H

#include <glib-object.h>
#include <openssl/evp.h>

#include "openssl-util.h"

#define OTB_SYM_CIPHER_SALT_BYTES_LENGTH	PKCS5_SALT_LEN

#define OTB_SYM_CIPHER_DEFAULT_CIPHER			"AES-256-CBC"
#define OTB_SYM_CIPHER_DEFAULT_MESSAGE_DIGEST	"SHA512"
#define OTB_SYM_CIPHER_DEFAULT_HASH_ITERATIONS	20480

typedef EVP_CIPHER_CTX OtbSymCipherContext;
typedef struct _OtbSymCipherSalt OtbSymCipherSalt;

#define otb_sym_cipher_context_free(sym_cipher_context)				EVP_CIPHER_CTX_free(sym_cipher_context)
#define otb_sym_cipher_dispose_decryption_buffer(decryption_buffer)	otb_openssl_dispose_decryption_buffer(decryption_buffer)

#define OTB_SYM_CIPHER_PROP_CIPHER			"cipher"
#define OTB_SYM_CIPHER_PROP_MESSAGE_DIGEST	"message-digest"
#define OTB_SYM_CIPHER_PROP_HASH_ITERATIONS	"hash-iterations"

#define OTB_TYPE_SYM_CIPHER				(otb_sym_cipher_get_type())
#define OTB_SYM_CIPHER(obj)				(G_TYPE_CHECK_INSTANCE_CAST((obj), OTB_TYPE_SYM_CIPHER, OtbSymCipher))
#define OTB_IS_SYM_CIPHER(obj)			(G_TYPE_CHECK_INSTANCE_TYPE((obj), OTB_TYPE_SYM_CIPHER))
#define OTB_SYM_CIPHER_CLASS(klass)		(G_TYPE_CHECK_CLASS_CAST((klass), OTB_TYPE_SYM_CIPHER, OtbSymCipherClass))
#define OTB_IS_SYM_CIPHER_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE((klass), OTB_TYPE_SYM_CIPHER))
#define OTB_SYM_CIPHER_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS((obj), OTB_TYPE_SYM_CIPHER, OtbSymCipherClass))

typedef struct _OtbSymCipher OtbSymCipher;
typedef struct _OtbSymCipherClass OtbSymCipherClass;
typedef struct _OtbSymCipherPrivate OtbSymCipherPrivate;

struct _OtbSymCipher
{
	GObject parent_instance;
	OtbSymCipherPrivate *priv;
};

struct _OtbSymCipherClass
{
	GObjectClass parent_class;
};

GType otb_sym_cipher_get_type(void);

GBytes *otb_sym_cipher_hash_passphrase(const OtbSymCipher *sym_cipher, const char *passphrase, OtbSymCipherSalt **sym_cipher_salt_out);
gboolean otb_sym_cipher_validate_passphrase(const OtbSymCipher *sym_cipher, const char *passphrase, GBytes *passphrase_hash, const OtbSymCipherSalt *sym_cipher_salt);
gboolean otb_sym_cipher_unwrap_key(OtbSymCipher *sym_cipher, GBytes *wrapped_key, const char *passphrase, const OtbSymCipherSalt *sym_cipher_salt);
GBytes *otb_sym_cipher_wrap_key(const OtbSymCipher *sym_cipher, const char *passphrase, OtbSymCipherSalt **sym_cipher_salt_out);
gboolean otb_sym_cipher_generate_random_key(OtbSymCipher *sym_cipher);
unsigned char *otb_sym_cipher_create_encryption_buffer(const OtbSymCipher *sym_cipher, size_t plain_bytes_buffer_size);
void *otb_sym_cipher_create_decryption_buffer(const OtbSymCipher *sym_cipher, size_t encrypted_bytes_buffer_size);
OtbSymCipherContext *otb_sym_cipher_init_encryption(const OtbSymCipher *sym_cipher, GBytes **iv_out);
OtbSymCipherContext *otb_sym_cipher_init_decryption(const OtbSymCipher *sym_cipher, GBytes *iv);
size_t otb_sym_cipher_encrypt_next(OtbSymCipherContext *sym_cipher_context, const void *plain_bytes, size_t plain_bytes_size, unsigned char *encrypted_bytes);
size_t otb_sym_cipher_decrypt_next(OtbSymCipherContext *sym_cipher_context, const unsigned char *encrypted_bytes, size_t encrypted_bytes_size, void *plain_bytes);
size_t otb_sym_cipher_finish_encrypt(OtbSymCipherContext *sym_cipher_context, unsigned char *encrypted_bytes);
size_t otb_sym_cipher_finish_decrypt(OtbSymCipherContext *sym_cipher_context, void *plain_bytes);
size_t otb_sym_cipher_encrypt(const OtbSymCipher *sym_cipher, const void *plain_bytes, size_t plain_bytes_size, GBytes **iv_out, unsigned char **encrypted_bytes_out);
size_t otb_sym_cipher_decrypt(const OtbSymCipher *sym_cipher, const unsigned char *encrypted_bytes, size_t encrypted_bytes_size, GBytes *iv, void **plain_bytes_out);
const unsigned char *otb_sym_cipher_salt_get_bytes(const OtbSymCipherSalt *sym_cipher_salt);
OtbSymCipherSalt *otb_sym_cipher_salt_from_bytes(const unsigned char *sym_cipher_salt_bytes);
void otb_sym_cipher_salt_free(OtbSymCipherSalt *sym_cipher_salt);

#endif
