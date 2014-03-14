/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_PAD_REC_H
#define OTB_PAD_REC_H

#include <glib-object.h>
#include <stdio.h>
#include <sys/types.h>

#include "unique-id.h"

typedef enum
{
	OTB_PAD_REC_STATUS_UNSENT,
	OTB_PAD_REC_STATUS_SENT,
	OTB_PAD_REC_STATUS_BEING_CONSUMED,
	OTB_PAD_REC_STATUS_CONSUMED,
	OTB_PAD_REC_STATUS_RECEIVED,
	OTB_PAD_REC_STATUS_DEAD,
	OTB_PAD_REC_STATUS_OUT_OF_BOUNDS
} OtbPadRecStatus;

#define OTB_PAD_REC_PROP_UNIQUE_ID	"unique-id"
#define OTB_PAD_REC_PROP_STATUS		"status"
#define OTB_PAD_REC_PROP_BASE_PATH	"base-path"
#define OTB_PAD_REC_PROP_BASE_NAME	"base-name"
#define OTB_PAD_REC_PROP_SIZE		"size"

#define OTB_TYPE_PAD_REC				(otb_pad_rec_get_type())
#define OTB_PAD_REC(obj)				(G_TYPE_CHECK_INSTANCE_CAST((obj), OTB_TYPE_PAD_REC, OtbPadRec))
#define OTB_IS_PAD_REC(obj)				(G_TYPE_CHECK_INSTANCE_TYPE((obj), OTB_TYPE_PAD_REC))
#define OTB_PAD_REC_CLASS(klass)		(G_TYPE_CHECK_CLASS_CAST((klass), OTB_TYPE_PAD_REC, OtbPadRecClass))
#define OTB_IS_PAD_REC_CLASS(klass)		(G_TYPE_CHECK_CLASS_TYPE((klass), OTB_TYPE_PAD_REC))
#define OTB_PAD_REC_GET_CLASS(obj)		(G_TYPE_INSTANCE_GET_CLASS((obj), OTB_TYPE_PAD_REC, OtbPadRecClass))

typedef struct _OtbPadRec OtbPadRec;
typedef struct _OtbPadRecClass OtbPadRecClass;
typedef struct _OtbPadRecPrivate OtbPadRecPrivate;
typedef struct _OtbPadIO OtbPadIO;

struct _OtbPadRec
{
	GObject parent_instance;
	OtbPadRecPrivate *priv;
};

struct _OtbPadRecClass
{
	GObjectClass parent_class;
};

GType otb_pad_rec_get_type();

int otb_pad_rec_compare_by_id(const OtbPadRec *pad_rec, const OtbUniqueId *unique_id);
gboolean otb_pad_rec_save(const OtbPadRec *pad_rec);
OtbPadRec *otb_pad_rec_load(const char *base_path, const char *file_name);
gboolean otb_pad_rec_generate_pad_file(OtbPadRec *pad_rec);
OtbPadIO *otb_pad_rec_open_pad_for_write(OtbPadRec *pad_rec);
OtbPadIO *otb_pad_rec_open_pad_for_read(OtbPadRec *pad_rec, gboolean auto_rewind);
gboolean otb_pad_rec_delete(const OtbPadRec *pad_rec);
gboolean otb_pad_write(const OtbPadIO *pad_io, const void *input_buffer, size_t input_buffer_size);
gboolean otb_pad_read(OtbPadIO *pad_io, void **output_buffer, size_t *output_buffer_size);
gboolean otb_pad_read_byte(OtbPadIO *pad_io, unsigned char *output_byte);
gboolean otb_pad_has_more_bytes(const OtbPadIO *pad_io);
gboolean otb_pad_io_free(OtbPadIO *pad_io);

#endif
