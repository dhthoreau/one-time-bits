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

typedef EVP_CIPHER_CTX OtbRSAContext;

#define otb_rsa_context_free(cipher_context)	EVP_CIPHER_CTX_free(cipher_context)

#define OTB_RSA_PROP_NEW_KEY_LENGTH	"new-key-length"
#define OTB_RSA_PROP_CIPHER			"cipher"

#define OTB_TYPE_RSA			(otb_rsa_get_type())
#define OTB_RSA(obj)			(G_TYPE_CHECK_INSTANCE_CAST((obj), OTB_TYPE_RSA, OtbRSA))
#define OTB_IS_RSA(obj)			(G_TYPE_CHECK_INSTANCE_TYPE((obj), OTB_TYPE_RSA))
#define OTB_RSA_CLASS(klass)	(G_TYPE_CHECK_CLASS_CAST((klass), OTB_TYPE_RSA, OtbRSAClass))
#define OTB_IS_RSA_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE((klass), OTB_TYPE_RSA))
#define OTB_RSA_GET_CLASS(obj)	(G_TYPE_CHECK_CLASS_TYPE((obj), OTB_TYPE_RSA, OtbRSAClass))

typedef struct _OtbRSA OtbRSA;
typedef struct _OtbRSAClass OtbRSAClass;
typedef struct _OtbRSAPrivate OtbRSAPrivate;

struct _OtbRSA
{
	GObject parent_instance;
	OtbRSAPrivate *priv;
};

struct _OtbRSAClass
{
	GObjectClass parent_class;
};

GType otb_rsa_get_type();

gboolean otb_rsa_set_public_key(OtbRSA *rsa, GBytes *key);
GBytes *otb_rsa_get_public_key(OtbRSA *rsa);
gboolean otb_rsa_generate_keys(OtbRSA *rsa, size_t key_size);
OtbRSAContext *otb_rsa_init_encryption(const OtbRSA *rsa, GBytes **iv_out, GBytes **encrypted_key_out);
OtbRSAContext *otb_rsa_init_decryption(const OtbRSA *rsa, GBytes *iv, GBytes *encrypted_key);
size_t otb_rsa_encrypt(OtbRSAContext *rsa_context, const char *plain_bytes, size_t plain_bytes_size, char *encrypted_bytes_out);
size_t otb_rsa_decrypt(OtbRSAContext *rsa_context, const char *encrypted_bytes, size_t encrypted_bytes_size, char *plain_bytes_out);
size_t otb_rsa_finish_encrypt(OtbRSAContext *rsa_context, char *encrypted_bytes_out);
size_t otb_rsa_finish_decrypt(OtbRSAContext *rsa_context, char *plain_bytes_out);

#endif
