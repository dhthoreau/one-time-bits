/**
 * Copyright © 2017 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_PAD_DB_H
#define OTB_PAD_DB_H

#include <gio/gio.h>
#include <glib-object.h>
#include <stdio.h>
#include <sys/types.h>

#include "memory.h"
#include "pad-rec.h"
#include "unique-id.h"

#define otb_pad_db_dispose_decryption_buffer(decryption_buffer)	otb_free_locked((decryption_buffer))

typedef enum
{
	OTB_PAD_DB_CRYPT_RESULT_SUCCESS,
	OTB_PAD_DB_CRYPT_RESULT_SUCCESS_PAD_STATUS_UPDATE_FAILED,
	OTB_PAD_DB_CRYPT_RESULT_FAILURE,
	OTB_PAD_DB_CRYPT_RESULT_NOT_ENOUGH_PADS,
	OTB_PAD_DB_CRYPT_RESULT_MISSING_PAD,
	OTB_PAD_DB_CRYPT_RESULT_UNSUPPORTED_FILE_FORMAT
} OtbPadDbCryptResult;

typedef struct _OtbCipherContext OtbCipherContext;

#define OTB_PAD_DB_PROP_BASE_PATH			"base-path"
#define OTB_PAD_DB_PROP_MAX_SIZE			"max-size"
#define OTB_PAD_DB_PROP_NEW_PAD_MIN_SIZE	"new-pad-min-size"
#define OTB_PAD_DB_PROP_NEW_PAD_MAX_SIZE	"new-pad-max-size"
#define OTB_PAD_DB_PROP_NEW_PAD_EXPIRATION	"new-pad-expiration"

#define OTB_TYPE_PAD_DB				(otb_pad_db_get_type())
#define OTB_PAD_DB(obj)				(G_TYPE_CHECK_INSTANCE_CAST((obj), OTB_TYPE_PAD_DB, OtbPadDb))
#define OTB_IS_PAD_DB(obj)			(G_TYPE_CHECK_INSTANCE_TYPE((obj), OTB_TYPE_PAD_DB))
#define OTB_PAD_DB_CLASS(klass)		(G_TYPE_CHECK_CLASS_CAST((klass), OTB_TYPE_PAD_DB, OtbPadDbClass))
#define OTB_IS_PAD_DB_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE((klass), OTB_TYPE_PAD_DB))
#define OTB_PAD_DB_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS((obj), OTB_TYPE_PAD_DB, OtbPadDbClass))

typedef struct _OtbPadDb OtbPadDb;
typedef struct _OtbPadDbClass OtbPadDbClass;
typedef struct _OtbPadDbPrivate OtbPadDbPrivate;

struct _OtbPadDb
{
	GObject parent_instance;
	OtbPadDbPrivate *priv;
};

struct _OtbPadDbClass
{
	GObjectClass parent_class;
};

GType otb_pad_db_get_type(void);

gboolean otb_pad_db_save(const OtbPadDb *pad_db);
OtbPadDb *otb_pad_db_create_in_directory(const char *base_path);
OtbPadDb *otb_pad_db_load_from_directory(const char *base_path);
gboolean otb_pad_db_delete(const OtbPadDb *pad_db);
gboolean otb_pad_db_create_unsent_pad(const OtbPadDb *pad_db);
OtbPadIO *otb_pad_db_add_incoming_pad(const OtbPadDb *pad_db, const OtbUniqueId *unique_id, int32_t size, long long expiration);	// FARE - Deve confermare che la dimensione finale è veramente == size.
GSList *otb_pad_db_get_ids_of_pads_in_status(const OtbPadDb *pad_db, OtbPadRecStatus status);
gboolean otb_pad_db_mark_pad_as_sent(const OtbPadDb *pad_db, const OtbUniqueId *unique_id);
gboolean otb_pad_db_mark_pad_as_received(const OtbPadDb *pad_db, const OtbUniqueId *unique_id);
OtbUniqueId *otb_pad_db_fetch_random_rec_id(const OtbPadDb *pad_db, OtbPadRecStatus status);
int32_t otb_pad_db_get_pad_size(const OtbPadDb *pad_db, const OtbUniqueId *unique_id);
long long otb_pad_db_get_pad_expiration(const OtbPadDb *pad_db, const OtbUniqueId *unique_id);
OtbPadIO *otb_pad_db_open_pad_for_read(OtbPadDb *pad_db, const OtbUniqueId *unique_id);
gboolean otb_pad_db_close_pad(const OtbPadDb *pad_db, OtbPadIO *pad_io);
gboolean otb_pad_db_remove_pad(const OtbPadDb *pad_db, const OtbUniqueId *unique_id);
gboolean otb_pad_db_remove_expired_pads(const OtbPadDb *pad_db);
OtbCipherContext *otb_cipher_context_new(OtbPadDb *pad_db);
gboolean otb_encrypt(OtbCipherContext *cipher_context, const void *plain_bytes, size_t plain_bytes_size, unsigned char **encrypted_bytes_out, size_t *encrypted_bytes_size_out);
OtbPadDbCryptResult otb_finish_encrypt(OtbCipherContext *cipher_context);
gboolean otb_decrypt(OtbCipherContext *cipher_context, const unsigned char *encrypted_bytes, size_t encrypted_bytes_size, void **plain_bytes_out, size_t *plain_bytes_size_out);
OtbPadDbCryptResult otb_finish_decrypt(OtbCipherContext *cipher_context);

#endif
