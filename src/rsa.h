/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_RSA_H
#define OTB_RSA_H

#include <glib-object.h>
#include <openssl/evp.h>

#include "cipher.h"

typedef EVP_CIPHER_CTX OtbRsaContext;

#define otb_rsa_context_free(cipher_context)	EVP_CIPHER_CTX_free(cipher_context)

#define OTB_RSA_PROP_NEW_KEY_LENGTH	"new-key-length"
#define OTB_RSA_PROP_CIPHER			"cipher"

#define OTB_TYPE_RSA			(otb_rsa_get_type())
#define OTB_RSA(obj)			(G_TYPE_CHECK_INSTANCE_CAST((obj), OTB_TYPE_RSA, OtbRsa))
#define OTB_IS_RSA(obj)			(G_TYPE_CHECK_INSTANCE_TYPE((obj), OTB_TYPE_RSA))
#define OTB_RSA_CLASS(klass)	(G_TYPE_CHECK_CLASS_CAST((klass), OTB_TYPE_RSA, OtbRsaClass))
#define OTB_IS_RSA_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE((klass), OTB_TYPE_RSA))
#define OTB_RSA_GET_CLASS(obj)	(G_TYPE_CHECK_CLASS_TYPE((obj), OTB_TYPE_RSA, OtbRsaClass))

typedef struct _OtbRsa OtbRsa;
typedef struct _OtbRsaClass OtbRsaClass;
typedef struct _OtbRsaPrivate OtbRsaPrivate;

struct _OtbRsa
{
	GObject parent_instance;
	OtbRsaPrivate *priv;
};

struct _OtbRsaClass
{
	GObjectClass parent_class;
};

GType otb_rsa_get_type();

gboolean otb_rsa_set_public_key(const OtbRsa *rsa, GBytes *public_key);
GBytes *otb_rsa_get_public_key(const OtbRsa *rsa);
gboolean otb_rsa_set_private_key(const OtbRsa *rsa, GBytes *encrypted_private_key, const OtbCipher *cipher, GBytes *iv);
GBytes *otb_rsa_get_private_key(const OtbRsa *rsa, const OtbCipher *cipher, GBytes **iv);
gboolean otb_rsa_generate_random_keys(OtbRsa *rsa);
unsigned char *otb_rsa_create_encryption_buffer(const OtbRsa *rsa, size_t plain_bytes_buffer_size, size_t *encryption_buffer_size_out);
unsigned char *otb_rsa_create_decryption_buffer(const OtbRsa *rsa, size_t encrypted_bytes_buffer_size, size_t *decryption_buffer_size_out);
OtbRsaContext *otb_rsa_init_encryption(const OtbRsa *rsa, GBytes **iv_out, GBytes **encrypted_key_out);
OtbRsaContext *otb_rsa_init_decryption(const OtbRsa *rsa, GBytes *iv, GBytes *encrypted_key);
size_t otb_rsa_encrypt(OtbRsaContext *rsa_context, const unsigned char *plain_bytes, size_t plain_bytes_size, unsigned char *encrypted_bytes_out);
size_t otb_rsa_decrypt(OtbRsaContext *rsa_context, const unsigned char *encrypted_bytes, size_t encrypted_bytes_size, unsigned char *plain_bytes_out);
size_t otb_rsa_finish_encrypt(OtbRsaContext *rsa_context, unsigned char *encrypted_bytes_out);
size_t otb_rsa_finish_decrypt(OtbRsaContext *rsa_context, unsigned char *plain_bytes_out);

#endif
