/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <glib/gi18n.h>

#include "io.h"
#include "pad-db.h"
#include "random.h"
#include "settings.h"

struct _OtbCipherContext
{
	size_t plain_buffer_length;
	unsigned char *plain_buffer;
	size_t encrypted_buffer_length;
	unsigned char *encrypted_buffer;
	OtbPadIO *current_pad_io;
	OtbPadIO *previous_pad_io;
};

struct _OtbPadDbPrivate
{
	GRWLock lock;
	char *base_path;
	char *file_path;
	unsigned long long max_size;
	off_t new_pad_min_size;
	off_t new_pad_max_size;
	long long new_pad_expiration;
	GSList *pad_recs;
	OtbPadIO *open_pad_io;
};

#define DEFAULT_MAX_SIZE			10485760LL
#define DEFAULT_NEW_PAD_MIN_SIZE	10240
#define DEFAULT_NEW_PAD_MAX_SIZE	20480
#define MINIMUM_NEW_PAD_SIZE		1024
#define DEFAULT_NEW_PAD_EXPIRATION	31536000000000
#define MINIMUM_NEW_PAD_EXPIRATION	86400000000

enum
{
	PROP_0,
	PROP_BASE_PATH,
	PROP_MAX_SIZE,
	PROP_NEW_PAD_MIN_SIZE,
	PROP_NEW_PAD_MAX_SIZE,
	PROP_NEW_PAD_EXPIRATION
};

static void otb_pad_db_dispose(GObject *object);
static void otb_pad_db_finalize(GObject *object);
static void otb_pad_db_set_property(GObject *object, unsigned int prop_id, const GValue *value, GParamSpec *pspec);
static void otb_pad_db_get_property(GObject *object, unsigned int prop_id, GValue *value, GParamSpec *pspec);

G_DEFINE_TYPE(OtbPadDb, otb_pad_db, G_TYPE_OBJECT);

static void otb_pad_db_class_init(OtbPadDbClass *klass)
{
	GObjectClass *object_class=G_OBJECT_CLASS(klass);
	object_class->dispose=otb_pad_db_dispose;
	object_class->finalize=otb_pad_db_finalize;
	object_class->set_property=otb_pad_db_set_property;
	object_class->get_property=otb_pad_db_get_property;
	g_object_class_install_property(object_class, PROP_BASE_PATH, g_param_spec_string(OTB_PAD_DB_PROP_BASE_PATH, _("Base path"), _("Directory where the database will be saved"), NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property(object_class, PROP_MAX_SIZE, g_param_spec_uint64(OTB_PAD_DB_PROP_MAX_SIZE, _("Max size"), _("Maximum size of the database"), 0, G_MAXINT64, DEFAULT_MAX_SIZE, G_PARAM_READABLE));
	g_object_class_install_property(object_class, PROP_NEW_PAD_MIN_SIZE, g_param_spec_int(OTB_PAD_DB_PROP_NEW_PAD_MIN_SIZE, _("New pad min size"), _("Minimum size for a newly created pad"), 0, G_MAXINT, DEFAULT_NEW_PAD_MIN_SIZE, G_PARAM_READABLE));
	g_object_class_install_property(object_class, PROP_NEW_PAD_MAX_SIZE, g_param_spec_int(OTB_PAD_DB_PROP_NEW_PAD_MAX_SIZE, _("New pad max size"), _("Maximum size for a newly created pad"), MINIMUM_NEW_PAD_SIZE, G_MAXINT, DEFAULT_NEW_PAD_MAX_SIZE, G_PARAM_READABLE));
	g_object_class_install_property(object_class, PROP_NEW_PAD_EXPIRATION, g_param_spec_int64(OTB_PAD_DB_PROP_NEW_PAD_EXPIRATION, _("New pad expiration"), _("Time interval of expiration for a newly created pad"), MINIMUM_NEW_PAD_EXPIRATION, G_MAXINT64, DEFAULT_NEW_PAD_EXPIRATION, G_PARAM_READABLE));
	g_type_class_add_private(klass, sizeof(OtbPadDbPrivate));
}

static void otb_pad_db_init(OtbPadDb *pad_db)
{
	pad_db->priv=G_TYPE_INSTANCE_GET_PRIVATE(pad_db, OTB_TYPE_PAD_DB, OtbPadDbPrivate);
	g_rw_lock_init(&pad_db->priv->lock);
	pad_db->priv->base_path=NULL;
	pad_db->priv->file_path=NULL;
	pad_db->priv->max_size=DEFAULT_MAX_SIZE;
	pad_db->priv->new_pad_min_size=DEFAULT_NEW_PAD_MIN_SIZE;
	pad_db->priv->new_pad_max_size=DEFAULT_NEW_PAD_MAX_SIZE;
	pad_db->priv->new_pad_expiration=DEFAULT_NEW_PAD_EXPIRATION;
	pad_db->priv->open_pad_io=NULL;
	pad_db->priv->pad_recs=NULL;
}

static void otb_pad_db_free_pad_rec_list(const OtbPadDb *pad_db)
{
	g_slist_free_full(pad_db->priv->pad_recs, g_object_unref);
	pad_db->priv->pad_recs=NULL;
}

static void otb_pad_db_dispose(GObject *object)
{
	g_return_if_fail(object!=NULL);
	g_return_if_fail(OTB_IS_PAD_DB(object));
	OtbPadDb *pad_db=OTB_PAD_DB(object);
	otb_pad_db_free_pad_rec_list(pad_db);
	G_OBJECT_CLASS(otb_pad_db_parent_class)->dispose(object);
}

static void otb_pad_db_finalize(GObject *object)
{
	g_return_if_fail(object!=NULL);
	g_return_if_fail(OTB_IS_PAD_DB(object));
	OtbPadDb *pad_db=OTB_PAD_DB(object);
	g_rw_lock_clear(&pad_db->priv->lock);
	g_free(pad_db->priv->base_path);
	g_free(pad_db->priv->file_path);
	if(pad_db->priv->open_pad_io!=NULL)
		otb_pad_io_free(pad_db->priv->open_pad_io);
	G_OBJECT_CLASS(otb_pad_db_parent_class)->finalize(object);
}

static void otb_pad_db_set_base_path(const OtbPadDb *pad_db, const char *base_path)
{
	g_free(pad_db->priv->base_path);
	pad_db->priv->base_path=g_strdup(base_path);
	g_free(pad_db->priv->file_path);
	pad_db->priv->file_path=g_build_filename(base_path, "db.otb", NULL);
}

#define otb_pad_db_lock_read(pad_db)	(g_rw_lock_reader_lock(&(pad_db)->priv->lock))
#define otb_pad_db_unlock_read(pad_db)	(g_rw_lock_reader_unlock(&(pad_db)->priv->lock))
#define otb_pad_db_lock_write(pad_db)	(g_rw_lock_writer_lock(&(pad_db)->priv->lock))
#define otb_pad_db_unlock_write(pad_db)	(g_rw_lock_writer_unlock(&(pad_db)->priv->lock))

static void otb_pad_db_set_property(GObject *object, unsigned int prop_id, const GValue *value, GParamSpec *pspec)
{
	OtbPadDb *pad_db=OTB_PAD_DB(object);
	otb_pad_db_lock_write(pad_db);
	switch(prop_id)
	{
		case PROP_BASE_PATH:
		{
			otb_pad_db_set_base_path(pad_db, g_value_get_string(value));
			break;
		}
		default:
		{
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
		}
	}
	otb_pad_db_unlock_write(pad_db);
}

static void otb_pad_db_get_property(GObject *object, unsigned int prop_id, GValue *value, GParamSpec *pspec)
{
	OtbPadDb *pad_db=OTB_PAD_DB(object);
	otb_pad_db_lock_read(pad_db);
	switch(prop_id)
	{
		case PROP_BASE_PATH:
		{
			g_value_set_string(value, pad_db->priv->base_path);
			break;
		}
		case PROP_MAX_SIZE:
		{
			g_value_set_uint64(value, pad_db->priv->max_size);
			break;
		}
		case PROP_NEW_PAD_MIN_SIZE:
		{
			g_value_set_int(value, pad_db->priv->new_pad_min_size);
			break;
		}
		case PROP_NEW_PAD_MAX_SIZE:
		{
			g_value_set_int(value, pad_db->priv->new_pad_max_size);
			break;
		}
		case PROP_NEW_PAD_EXPIRATION:
		{
			g_value_set_int64(value, pad_db->priv->new_pad_expiration);
			break;
		}
		default:
		{
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
		}
	}
	otb_pad_db_unlock_read(pad_db);
}

#define SAVE_GROUP					"pad-db"
#define SAVE_KEY_MAX_SIZE			"max-size"
#define SAVE_KEY_NEW_PAD_MIN_SIZE	"new-pad-min-size"
#define SAVE_KEY_NEW_PAD_MAX_SIZE	"new-pad-max-size"
#define SAVE_KEY_NEW_PAD_EXPIRATION	"new-pad-expiration"

static gboolean otb_pad_db_save(const OtbPadDb *pad_db)
{
	gboolean ret_val=TRUE;
	if(G_LIKELY(otb_mkdir_with_parents(pad_db->priv->base_path)))
	{
		GKeyFile *key_file=g_key_file_new();
		g_key_file_set_uint64(key_file, SAVE_GROUP, SAVE_KEY_MAX_SIZE, pad_db->priv->max_size);
		g_key_file_set_integer(key_file, SAVE_GROUP, SAVE_KEY_NEW_PAD_MIN_SIZE, pad_db->priv->new_pad_min_size);
		g_key_file_set_integer(key_file, SAVE_GROUP, SAVE_KEY_NEW_PAD_MAX_SIZE, pad_db->priv->new_pad_max_size);
		g_key_file_set_int64(key_file, SAVE_GROUP, SAVE_KEY_NEW_PAD_EXPIRATION, pad_db->priv->new_pad_expiration);
		ret_val=otb_settings_save_key_file(key_file, pad_db->priv->file_path);
		g_key_file_unref(key_file);
	}
	else
		ret_val=FALSE;
	return ret_val;
}

OtbPadDb *otb_pad_db_create_in_directory(const char *base_path)
{
	OtbPadDb *pad_db=g_object_new(OTB_TYPE_PAD_DB, OTB_PAD_DB_PROP_BASE_PATH, base_path, NULL);
	if(G_UNLIKELY(g_file_test(pad_db->priv->file_path, G_FILE_TEST_EXISTS) || !otb_pad_db_save(pad_db)))
	{
		g_object_unref(pad_db);
		pad_db=NULL;
	}
	return pad_db;
}

static gboolean otb_pad_db_load(const OtbPadDb *pad_db)
{
	gboolean ret_val=TRUE;
	GKeyFile *key_file=otb_settings_load_key_file_from_file(pad_db->priv->file_path);
	if(G_UNLIKELY(key_file==NULL))
		ret_val=FALSE;
	else if(G_UNLIKELY((pad_db->priv->max_size=otb_settings_get_uint64(key_file, SAVE_GROUP, SAVE_KEY_MAX_SIZE, 0))==0))
		ret_val=FALSE;
	else if(G_UNLIKELY((pad_db->priv->new_pad_min_size=otb_settings_get_int(key_file, SAVE_GROUP, SAVE_KEY_NEW_PAD_MIN_SIZE, -1))==-1))
		ret_val=FALSE;
	else if(G_UNLIKELY((pad_db->priv->new_pad_max_size=otb_settings_get_int(key_file, SAVE_GROUP, SAVE_KEY_NEW_PAD_MAX_SIZE, -1))==-1))
		ret_val=FALSE;
	else if(G_UNLIKELY((pad_db->priv->new_pad_expiration=otb_settings_get_int64(key_file, SAVE_GROUP, SAVE_KEY_NEW_PAD_EXPIRATION, -1))==-1))
		ret_val=FALSE;
	if(G_LIKELY(key_file!=NULL))
		g_key_file_unref(key_file);
	return ret_val;
}

static OtbPadRec *otb_pad_db_find_pad_rec_by_id_no_ref(const OtbPadDb *pad_db, const OtbUniqueId *unique_id)
{
	OtbPadRec *ret_val=NULL;
	for(const GSList *curr_element=pad_db->priv->pad_recs; ret_val==NULL && curr_element!=NULL; curr_element=g_slist_next(curr_element))
	{
		OtbPadRec *pad_rec=OTB_PAD_REC(curr_element->data);
		if(otb_pad_rec_compare_by_id(pad_rec, unique_id)==0)
			ret_val=pad_rec;
	}
	return ret_val;
}

static off_t otb_pad_db_get_curr_size(const OtbPadDb *pad_db)
{
	off_t curr_size=0;
	for(const GSList *curr_element=pad_db->priv->pad_recs; curr_element!=NULL; curr_element=g_slist_next(curr_element))
	{
		OtbPadRec *pad_rec=OTB_PAD_REC(curr_element->data);
		off_t pad_size;
		g_object_get(pad_rec, OTB_PAD_REC_PROP_SIZE, &pad_size, NULL);
		if(G_LIKELY(pad_size>0))
			curr_size+=pad_size;
	}
	return curr_size;
}

static gboolean otb_pad_db_add_pad_rec(const OtbPadDb *pad_db, OtbPadRec *pad_rec)
{
	gboolean ret_val=TRUE;
	OtbUniqueId *unique_id=NULL;
	off_t pad_size;
	g_object_get(pad_rec, OTB_PAD_REC_PROP_UNIQUE_ID, &unique_id, OTB_PAD_REC_PROP_SIZE, &pad_size, NULL);
	if(G_UNLIKELY(otb_pad_db_find_pad_rec_by_id_no_ref(pad_db, unique_id)!=NULL))
	{
		g_message(_("Failed to add record due to non-unique ID."));
		ret_val=FALSE;
	}
	else if(G_UNLIKELY(otb_pad_db_get_curr_size(pad_db)+pad_size>pad_db->priv->max_size))
	{
		g_message(_("Failed to add record due to database size limitation."));
		ret_val=FALSE;
	}
	else if(G_UNLIKELY(otb_pad_rec_save(pad_rec)))
		pad_db->priv->pad_recs=g_slist_prepend(pad_db->priv->pad_recs, pad_rec);
	otb_unique_id_unref(unique_id);
	return ret_val;
}

static gboolean otb_pad_db_load_all_recs(const OtbPadDb *pad_db)
{
	gboolean ret_val=TRUE;
	GDir *pad_db_directory=otb_open_directory(pad_db->priv->base_path);
	if(G_UNLIKELY(pad_db_directory==NULL))
		ret_val=FALSE;
	else
	{
		otb_pad_db_free_pad_rec_list(pad_db);
		const char *file_name;
		while((file_name=g_dir_read_name(pad_db_directory)) && ret_val)
		{
			if(g_str_has_suffix(file_name, ".rec"))
			{
				OtbPadRec *pad_rec=otb_pad_rec_load(pad_db->priv->base_path, file_name);
				if(G_UNLIKELY(pad_rec==NULL))
					ret_val=FALSE;
				pad_db->priv->pad_recs=g_slist_prepend(pad_db->priv->pad_recs, pad_rec);
			}
		}
		g_dir_close(pad_db_directory);
	}
	return ret_val;
}

OtbPadDb *otb_pad_db_load_from_directory(const char *base_path)
{
	OtbPadDb *pad_db=g_object_new(OTB_TYPE_PAD_DB, OTB_PAD_DB_PROP_BASE_PATH, base_path, NULL);
	gboolean load_successful=TRUE;
	if(G_UNLIKELY(!otb_pad_db_load(pad_db)))
		load_successful=FALSE;
	else if(G_UNLIKELY(!otb_pad_db_load_all_recs(pad_db)))
		load_successful=FALSE;
	if(G_UNLIKELY(!load_successful))
	{
		g_object_unref(pad_db);
		pad_db=NULL;
	}
	return pad_db;
}

static gboolean otb_pad_db_remove_pad_rec(const OtbPadDb *pad_db, OtbPadRec *pad_rec)
{
	gboolean ret_val=otb_pad_rec_delete(pad_rec);
	if(G_LIKELY(ret_val))
	{
		pad_db->priv->pad_recs=g_slist_remove(pad_db->priv->pad_recs, pad_rec);
		g_object_unref(pad_rec);
	}
	return ret_val;
}

gboolean otb_pad_db_delete(const OtbPadDb *pad_db)
{
	gboolean ret_val=TRUE;
	otb_pad_db_lock_write(pad_db);
	while(pad_db->priv->pad_recs!=NULL)
		ret_val=otb_pad_db_remove_pad_rec(pad_db, OTB_PAD_REC(pad_db->priv->pad_recs->data)) && TRUE;
	otb_pad_db_free_pad_rec_list(pad_db);
	ret_val=otb_delete_dir(pad_db->priv->base_path) && TRUE;
	otb_pad_db_unlock_write(pad_db);
	return ret_val;
}

gboolean otb_pad_db_set_max_size(const OtbPadDb *pad_db, off_t max_size)
{
	gboolean ret_val=TRUE;
	otb_pad_db_lock_write(pad_db);
	off_t old_max_size=pad_db->priv->max_size;
	pad_db->priv->max_size=max_size;
	if(G_UNLIKELY(!otb_pad_db_save(pad_db)))
	{
		pad_db->priv->max_size=old_max_size;
		ret_val=FALSE;
	}
	otb_pad_db_unlock_write(pad_db);
	return ret_val;
}

gboolean otb_pad_db_set_new_pad_min_size(const OtbPadDb *pad_db, off_t new_pad_min_size)
{
	gboolean ret_val=TRUE;
	if(new_pad_min_size<MINIMUM_NEW_PAD_SIZE)
		ret_val=FALSE;
	else
	{
		otb_pad_db_lock_write(pad_db);
		off_t old_pad_min_size=pad_db->priv->new_pad_min_size;
		off_t old_pad_max_size=pad_db->priv->new_pad_max_size;
		pad_db->priv->new_pad_min_size=new_pad_min_size;
		if(pad_db->priv->new_pad_min_size>pad_db->priv->new_pad_max_size)
			pad_db->priv->new_pad_max_size=pad_db->priv->new_pad_min_size;
		if(G_UNLIKELY(!otb_pad_db_save(pad_db)))
		{
			pad_db->priv->new_pad_min_size=old_pad_min_size;
			pad_db->priv->new_pad_max_size=old_pad_max_size;
			ret_val=FALSE;
		}
		otb_pad_db_unlock_write(pad_db);
	}
	return ret_val;
}

gboolean otb_pad_db_set_new_pad_max_size(const OtbPadDb *pad_db, off_t new_pad_max_size)
{
	gboolean ret_val=TRUE;
	if(new_pad_max_size<MINIMUM_NEW_PAD_SIZE || new_pad_max_size<pad_db->priv->new_pad_min_size)
		ret_val=FALSE;
	else
	{
		otb_pad_db_lock_write(pad_db);
		off_t old_pad_min_size=pad_db->priv->new_pad_min_size;
		off_t old_pad_max_size=pad_db->priv->new_pad_max_size;
		pad_db->priv->new_pad_max_size=new_pad_max_size;
		if(pad_db->priv->new_pad_min_size>pad_db->priv->new_pad_max_size)
			pad_db->priv->new_pad_max_size=pad_db->priv->new_pad_min_size;
		if(G_UNLIKELY(!otb_pad_db_save(pad_db)))
		{
			pad_db->priv->new_pad_min_size=old_pad_min_size;
			pad_db->priv->new_pad_max_size=old_pad_max_size;
			ret_val=FALSE;
		}
		otb_pad_db_unlock_write(pad_db);
	}
	return ret_val;
}

gboolean otb_pad_db_set_new_pad_expiration(const OtbPadDb *pad_db, long long new_pad_expiration)
{
	gboolean ret_val=TRUE;
	otb_pad_db_lock_write(pad_db);
	long long old_new_pad_expiration=pad_db->priv->new_pad_expiration;
	pad_db->priv->new_pad_expiration=new_pad_expiration;
	if(G_UNLIKELY(!otb_pad_db_save(pad_db)))
	{
		pad_db->priv->new_pad_expiration=old_new_pad_expiration;
		ret_val=FALSE;
	}
	otb_pad_db_unlock_write(pad_db);
	return ret_val;
}

gboolean otb_pad_db_remove_pad(const OtbPadDb *pad_db, const OtbUniqueId *unique_id)
{
	gboolean ret_val=TRUE;
	otb_pad_db_lock_write(pad_db);
	OtbPadRec *pad_rec=otb_pad_db_find_pad_rec_by_id_no_ref(pad_db, unique_id);
	if(G_UNLIKELY(pad_rec!=NULL && !otb_pad_db_remove_pad_rec(pad_db, pad_rec)))
		ret_val=FALSE;
	otb_pad_db_unlock_write(pad_db);
	return ret_val;
}

gboolean otb_pad_db_remove_expired_pads(const OtbPadDb *pad_db)
{
	gboolean ret_val=TRUE;
	GSList *pad_recs_to_remove=NULL;
	long long now=g_get_real_time();
	for(const GSList *curr_element=pad_db->priv->pad_recs; curr_element!=NULL; curr_element=g_slist_next(curr_element))
	{
		OtbPadRec *pad_rec=OTB_PAD_REC(curr_element->data);
		long long pad_rec_expiration;
		g_object_get(pad_rec, OTB_PAD_REC_PROP_EXPIRATION, &pad_rec_expiration, NULL);
		if(G_UNLIKELY(now>pad_rec_expiration))
			pad_recs_to_remove=g_slist_prepend(pad_recs_to_remove, pad_rec);
	}
	for(const GSList *curr_element=pad_recs_to_remove; curr_element!=NULL && ret_val; curr_element=g_slist_next(curr_element))
	{
		OtbPadRec *pad_rec=OTB_PAD_REC(curr_element->data);
		if(G_UNLIKELY(!otb_pad_db_remove_pad_rec(pad_db, pad_rec)))
			ret_val=FALSE;
	}
	g_slist_free(pad_recs_to_remove);
	return ret_val;
}

static gboolean otb_pad_db_remove_dead_pads(const OtbPadDb *pad_db)
{
	gboolean ret_val=TRUE;
	GSList *pad_recs_to_remove=NULL;
	for(const GSList *curr_element=pad_db->priv->pad_recs; curr_element!=NULL; curr_element=g_slist_next(curr_element))
	{
		OtbPadRec *pad_rec=OTB_PAD_REC(curr_element->data);
		OtbPadRecStatus pad_rec_status;
		g_object_get(pad_rec, OTB_PAD_REC_PROP_STATUS, &pad_rec_status, NULL);
		if(pad_rec_status==OTB_PAD_REC_STATUS_DEAD)
			pad_recs_to_remove=g_slist_prepend(pad_recs_to_remove, pad_rec);
	}
	for(const GSList *curr_element=pad_recs_to_remove; curr_element!=NULL && ret_val; curr_element=g_slist_next(curr_element))
	{
		OtbPadRec *pad_rec=OTB_PAD_REC(curr_element->data);
		if(G_UNLIKELY(!otb_pad_db_remove_pad_rec(pad_db, pad_rec)))
			ret_val=FALSE;
	}
	g_slist_free(pad_recs_to_remove);
	return ret_val;
}

gboolean otb_pad_db_create_unsent_pad(const OtbPadDb *pad_db)
{
	gboolean ret_val=TRUE;
	otb_pad_db_lock_write(pad_db);
	off_t new_pad_size;
	if(G_UNLIKELY(!otb_random_bytes(&new_pad_size, sizeof new_pad_size)))
		ret_val=FALSE;
	else
	{
		new_pad_size=otb_modulo(new_pad_size, (pad_db->priv->new_pad_max_size-pad_db->priv->new_pad_min_size+1))+pad_db->priv->new_pad_min_size;
		long long expiration=g_get_real_time()+pad_db->priv->new_pad_expiration;
		OtbPadRec *pad_rec=g_object_new(OTB_TYPE_PAD_REC, OTB_PAD_REC_PROP_BASE_PATH, pad_db->priv->base_path, OTB_PAD_REC_PROP_SIZE, new_pad_size, OTB_PAD_REC_PROP_EXPIRATION, expiration, NULL);
		if(G_UNLIKELY(!otb_pad_db_add_pad_rec(pad_db, pad_rec)))
		{
			ret_val=FALSE;
			g_object_unref(pad_rec);
		}
		else if(G_UNLIKELY(!otb_pad_rec_generate_pad_file(pad_rec)))
		{
			otb_pad_db_remove_pad_rec(pad_db, pad_rec);
			ret_val=FALSE;
		}
	}
	otb_pad_db_unlock_write(pad_db);
	return ret_val;
}

OtbPadIO *otb_pad_db_add_incoming_pad(const OtbPadDb *pad_db, const OtbUniqueId *unique_id, off_t size, long long expiration)
{
	OtbPadIO *pad_io=NULL;
	otb_pad_db_lock_write(pad_db);
	if(G_UNLIKELY(pad_db->priv->open_pad_io==NULL))
	{
		OtbPadRec *pad_rec=g_object_new(OTB_TYPE_PAD_REC, OTB_PAD_REC_PROP_UNIQUE_ID, unique_id, OTB_PAD_REC_PROP_STATUS, OTB_PAD_REC_STATUS_INCOMING, OTB_PAD_REC_PROP_BASE_PATH, pad_db->priv->base_path, OTB_PAD_REC_PROP_SIZE, size, OTB_PAD_REC_PROP_EXPIRATION, expiration, NULL);
		if(G_UNLIKELY(!otb_pad_db_add_pad_rec(pad_db, pad_rec)))
			g_object_unref(pad_rec);
		else if(G_UNLIKELY((pad_io=otb_pad_rec_open_pad_for_write(pad_rec))==NULL))
			otb_pad_db_remove_pad_rec(pad_db, pad_rec);
		else
			pad_db->priv->open_pad_io=pad_io;
	}
	otb_pad_db_unlock_write(pad_db);
	return pad_io;
}

GSList *otb_pad_db_get_ids_of_pads_in_status(const OtbPadDb *pad_db, OtbPadRecStatus status)
{
	GSList *selected_pad_ids=NULL;
	for(const GSList *curr_element=pad_db->priv->pad_recs; curr_element!=NULL; curr_element=g_slist_next(curr_element))
	{
		OtbPadRec *pad_rec=OTB_PAD_REC(curr_element->data);
		OtbPadRecStatus pad_rec_status;
		g_object_get(pad_rec, OTB_PAD_REC_PROP_STATUS, &pad_rec_status, NULL);
		if(pad_rec_status==status)
		{
			OtbUniqueId *unique_id=NULL;
			g_object_get(pad_rec, OTB_PAD_REC_PROP_UNIQUE_ID, &unique_id, NULL);
			selected_pad_ids=g_slist_prepend(selected_pad_ids, unique_id);
		}
	}
	return selected_pad_ids;
}

static gboolean otb_pad_db_transition_status_of_pad(const OtbPadDb *pad_db, const OtbUniqueId *unique_id, OtbPadRecStatus prerequisite_status, OtbPadRecStatus new_status)
{
	gboolean ret_val=TRUE;
	OtbPadRec *pad_rec=otb_pad_db_find_pad_rec_by_id_no_ref(pad_db, unique_id);
	OtbPadRecStatus pad_rec_status;
	g_object_get(pad_rec, OTB_PAD_REC_PROP_STATUS, &pad_rec_status, NULL);
	if(G_UNLIKELY(pad_rec_status!=prerequisite_status))
		ret_val=FALSE;
	else
	{
		g_object_set(pad_rec, OTB_PAD_REC_PROP_STATUS, new_status, NULL);
		if(G_UNLIKELY(!otb_pad_rec_save(pad_rec)))
		{
			g_object_set(pad_rec, OTB_PAD_REC_PROP_STATUS, prerequisite_status, NULL);
			ret_val=FALSE;
		}
	}
	return ret_val;
}

static gboolean otb_pad_db_transition_status_of_pads(const OtbPadDb *pad_db, OtbPadRecStatus prerequisite_status, OtbPadRecStatus new_status)
{
	gboolean ret_val=TRUE;
	for(const GSList *curr_element=pad_db->priv->pad_recs; ret_val && curr_element!=NULL; curr_element=g_slist_next(curr_element))
	{
		OtbPadRec *pad_rec=OTB_PAD_REC(curr_element->data);
		OtbPadRecStatus pad_rec_status;
		g_object_get(pad_rec, OTB_PAD_REC_PROP_STATUS, &pad_rec_status, NULL);
		if(pad_rec_status==prerequisite_status)
		{
			OtbUniqueId *unique_id=NULL;
			g_object_get(pad_rec, OTB_PAD_REC_PROP_UNIQUE_ID, &unique_id, NULL);
			ret_val=otb_pad_db_transition_status_of_pad(pad_db, unique_id, prerequisite_status, new_status);
			otb_unique_id_unref(unique_id);
		}
	}
	return ret_val;
}

gboolean otb_pad_db_mark_pad_as_sent(const OtbPadDb *pad_db, const OtbUniqueId *unique_id)
{
	gboolean ret_val;
	otb_pad_db_lock_write(pad_db);
	ret_val=otb_pad_db_transition_status_of_pad(pad_db, unique_id, OTB_PAD_REC_STATUS_UNSENT, OTB_PAD_REC_STATUS_SENT);
	otb_pad_db_unlock_write(pad_db);
	return ret_val;
}

gboolean otb_pad_db_mark_pad_as_received(const OtbPadDb *pad_db, const OtbUniqueId *unique_id)
{
	gboolean ret_val;
	otb_pad_db_lock_write(pad_db);
	ret_val=otb_pad_db_transition_status_of_pad(pad_db, unique_id, OTB_PAD_REC_STATUS_INCOMING, OTB_PAD_REC_STATUS_RECEIVED);
	otb_pad_db_unlock_write(pad_db);
	return ret_val;
}

static OtbUniqueId *otb_pad_db_fetch_random_rec_id_no_lock(const OtbPadDb *pad_db, OtbPadRecStatus status)
{
	OtbUniqueId *random_unique_id=NULL;
	GSList *candidate_pad_recs=NULL;
	unsigned int candidate_count=0;
	for(const GSList *curr_element=pad_db->priv->pad_recs; curr_element!=NULL; curr_element=g_slist_next(curr_element))
	{
		OtbPadRec *pad_rec=OTB_PAD_REC(curr_element->data);
		OtbPadRecStatus pad_rec_status;
		g_object_get(pad_rec, OTB_PAD_REC_PROP_STATUS, &pad_rec_status, NULL);
		if(pad_rec_status==status)
		{
			candidate_pad_recs=g_slist_prepend(candidate_pad_recs, pad_rec);
			candidate_count++;
		}
	}
	if(candidate_count!=0)
	{
		unsigned int nth;
		if(G_UNLIKELY(otb_random_bytes(&nth, sizeof nth)))
		{
			nth=otb_modulo(nth, candidate_count);
			OtbPadRec *random_pad_rec=g_slist_nth(candidate_pad_recs, nth)->data;
			g_object_get(random_pad_rec, OTB_PAD_REC_PROP_UNIQUE_ID, &random_unique_id, NULL);
		}
	}
	g_slist_free(candidate_pad_recs);
	return random_unique_id;
}

OtbUniqueId *otb_pad_db_fetch_random_rec_id(const OtbPadDb *pad_db, OtbPadRecStatus status)
{
	otb_pad_db_lock_read(pad_db);
	OtbUniqueId *unique_id=otb_pad_db_fetch_random_rec_id_no_lock(pad_db, status);
	otb_pad_db_unlock_read(pad_db);
	return unique_id;
}

off_t otb_pad_db_get_pad_size(const OtbPadDb *pad_db, const OtbUniqueId *unique_id)
{
	otb_pad_db_lock_read(pad_db);
	OtbPadRec *pad_rec=otb_pad_db_find_pad_rec_by_id_no_ref(pad_db, unique_id);
	off_t pad_size=-1;
	if(G_LIKELY(pad_rec!=NULL))
		g_object_get(pad_rec, OTB_PAD_REC_PROP_SIZE, &pad_size, NULL);
	otb_pad_db_unlock_read(pad_db);
	return pad_size;
}

long long otb_pad_db_get_pad_expiration(const OtbPadDb *pad_db, const OtbUniqueId *unique_id)
{
	otb_pad_db_lock_read(pad_db);
	OtbPadRec *pad_rec=otb_pad_db_find_pad_rec_by_id_no_ref(pad_db, unique_id);
	long long pad_expiration=-1;
	if(G_LIKELY(pad_rec!=NULL))
		g_object_get(pad_rec, OTB_PAD_REC_PROP_EXPIRATION, &pad_expiration, NULL);
	otb_pad_db_unlock_read(pad_db);
	return pad_expiration;
}

OtbPadIO *otb_pad_db_open_pad_for_read(OtbPadDb *pad_db, const OtbUniqueId *unique_id)
{
	OtbPadIO *pad_io=NULL;
	otb_pad_db_lock_read(pad_db);
	if(G_LIKELY(pad_db->priv->open_pad_io==NULL))
	{
		OtbPadRec *pad_rec;
		if((pad_rec=otb_pad_db_find_pad_rec_by_id_no_ref(pad_db, unique_id))!=NULL)
			pad_io=otb_pad_rec_open_pad_for_read(pad_rec, FALSE);
		if(G_LIKELY(pad_io!=NULL))
			pad_db->priv->open_pad_io=pad_io;
	}
	otb_pad_db_unlock_read(pad_db);
	return pad_io;
}

gboolean otb_pad_db_close_pad(const OtbPadDb *pad_db, OtbPadIO *pad_io)
{
	if(G_UNLIKELY(pad_db->priv->open_pad_io==NULL || pad_db->priv->open_pad_io!=pad_io))
		return FALSE;
	pad_db->priv->open_pad_io=NULL;
	otb_pad_io_free(pad_io);
	return TRUE;
}

static gboolean otb_pad_db_crypt_bytes(size_t bytes_to_crypt, const void *input_bytes, void *output_bytes, OtbCipherContext *cipher_context)
{
	gboolean ret_val=TRUE;
	for(size_t loop_count=0; ret_val && loop_count<bytes_to_crypt; loop_count++)
	{
		unsigned char input_byte;
		unsigned char current_pad_byte=0;
		unsigned char previous_pad_byte=0;
		input_byte=((unsigned char*)input_bytes)[loop_count];
		if(G_UNLIKELY(cipher_context->current_pad_io!=NULL && !otb_pad_read_byte(cipher_context->current_pad_io, &current_pad_byte)))
			ret_val=FALSE;
		else if(G_UNLIKELY(cipher_context->previous_pad_io!=NULL && !otb_pad_read_byte(cipher_context->previous_pad_io, &previous_pad_byte)))
			ret_val=FALSE;
		else
		{
			char output_byte=(input_byte ^ current_pad_byte ^ previous_pad_byte);
			((unsigned char*)output_bytes)[loop_count]=output_byte;
		}
	}
	return ret_val;
}

#define CURRENT_ENCRYPTION_FORMAT_VERSION	'\x00'

OtbPadDbCryptResults otb_pad_db_encrypt(const OtbPadDb *pad_db, OtbCipherContext *cipher_context, const void *plain_bytes, size_t plain_bytes_size, unsigned char **encrypted_bytes_out, size_t *encrypted_bytes_size_out)
{
	OtbPadDbCryptResults encryption_result=OTB_PAD_DB_CRYPT_RESULT_SUCCESS;
	otb_pad_db_lock_write(pad_db);
	const unsigned char format_version=CURRENT_ENCRYPTION_FORMAT_VERSION;
	*encrypted_bytes_out=NULL;
	*encrypted_bytes_size_out=0;
	for(size_t plain_position=0, encrypted_bytes_buffer_size=plain_bytes_size+sizeof format_version+OTB_UNIQUE_ID_BYTES_LENGTH; encryption_result==OTB_PAD_DB_CRYPT_RESULT_SUCCESS && plain_position<plain_bytes_size; encrypted_bytes_buffer_size+=OTB_UNIQUE_ID_BYTES_LENGTH)
	{
		*encrypted_bytes_out=g_realloc(*encrypted_bytes_out, encrypted_bytes_buffer_size);
		if(G_UNLIKELY(*encrypted_bytes_size_out==0))
		{
			*encrypted_bytes_out[0]=format_version;
			*encrypted_bytes_size_out=sizeof format_version;
		}
		OtbPadRec *pad_rec=NULL;
		off_t pad_size=-1;
		OtbUniqueId *unique_id=otb_pad_db_fetch_random_rec_id_no_lock(pad_db, OTB_PAD_REC_STATUS_SENT);
		if(G_UNLIKELY(unique_id==NULL))
			encryption_result=OTB_PAD_DB_CRYPT_RESULT_NOT_ENOUGH_PADS;
		else if(G_UNLIKELY(!otb_pad_db_crypt_bytes(OTB_UNIQUE_ID_BYTES_LENGTH, otb_unique_id_get_bytes(unique_id), *encrypted_bytes_out+*encrypted_bytes_size_out, cipher_context)))
			encryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
		else if(G_UNLIKELY((pad_rec=otb_pad_db_find_pad_rec_by_id_no_ref(pad_db, unique_id))==NULL))
			encryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
		else if(g_object_get(pad_rec, OTB_PAD_REC_PROP_SIZE, &pad_size, NULL), G_UNLIKELY(pad_size<0))
			encryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
		else if(G_UNLIKELY((cipher_context->current_pad_io=otb_pad_rec_open_pad_for_read(pad_rec, TRUE))==NULL))
			encryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
		else
		{
			size_t bytes_to_crypt_max_from_pad=pad_size-OTB_UNIQUE_ID_BYTES_LENGTH;
			size_t bytes_to_crypt_max_from_plain_bytes=plain_bytes_size-plain_position;
			size_t bytes_to_crypt=MIN(bytes_to_crypt_max_from_pad, bytes_to_crypt_max_from_plain_bytes);
			if(G_UNLIKELY(!otb_pad_db_crypt_bytes(bytes_to_crypt, (unsigned char*)plain_bytes+plain_position, *encrypted_bytes_out+*encrypted_bytes_size_out+OTB_UNIQUE_ID_BYTES_LENGTH, cipher_context)))
				encryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
			else
			{
				g_object_set(pad_rec, OTB_PAD_REC_PROP_STATUS, OTB_PAD_REC_STATUS_BEING_CONSUMED, NULL);
				plain_position+=bytes_to_crypt;
				*encrypted_bytes_size_out+=OTB_UNIQUE_ID_BYTES_LENGTH+bytes_to_crypt;
			}
		}
		otb_unique_id_unref(unique_id);
		if(G_UNLIKELY(cipher_context->previous_pad_io!=NULL && !otb_pad_io_free(cipher_context->previous_pad_io) && encryption_result==OTB_PAD_DB_CRYPT_RESULT_SUCCESS))
			encryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
		cipher_context->previous_pad_io=cipher_context->current_pad_io;
		cipher_context->current_pad_io=NULL;
	}
	if(G_UNLIKELY(cipher_context->previous_pad_io!=NULL && !otb_pad_io_free(cipher_context->previous_pad_io) && encryption_result==OTB_PAD_DB_CRYPT_RESULT_SUCCESS))
		encryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
	cipher_context->previous_pad_io=NULL;
	if(G_UNLIKELY(encryption_result==OTB_PAD_DB_CRYPT_RESULT_SUCCESS && !otb_pad_db_transition_status_of_pads(pad_db, OTB_PAD_REC_STATUS_BEING_CONSUMED, OTB_PAD_REC_STATUS_CONSUMED)))
	{
		g_warning(_("Failed to update the status of all pads used to encrypt a file, though file itself was fully encrypted. This could cause problems for the recipient of your encrypted files. Recomendation is that the encrypted file not be used."));
		encryption_result=OTB_PAD_DB_CRYPT_RESULT_SUCCESS_PAD_STATUS_UPDATE_FAILED;
	}
	otb_pad_db_transition_status_of_pads(pad_db, OTB_PAD_REC_STATUS_BEING_CONSUMED, OTB_PAD_REC_STATUS_SENT);
	if(G_UNLIKELY(encryption_result!=OTB_PAD_DB_CRYPT_RESULT_SUCCESS))
		g_free(*encrypted_bytes_out);
	if(G_UNLIKELY(encryption_result!=OTB_PAD_DB_CRYPT_RESULT_SUCCESS))
	{
		*encrypted_bytes_out=NULL;
		*encrypted_bytes_size_out=0;
	}
	otb_pad_db_unlock_write(pad_db);
	return encryption_result;
}

OtbPadDbCryptResults otb_pad_db_decrypt(const OtbPadDb *pad_db, OtbCipherContext *cipher_context, const unsigned char *encrypted_bytes, size_t encrypted_bytes_size, void **plain_bytes_out, size_t *plain_bytes_size_out)
{
	OtbPadDbCryptResults decryption_result=OTB_PAD_DB_CRYPT_RESULT_SUCCESS;
	const unsigned char format_version=encrypted_bytes[0];
	otb_pad_db_lock_write(pad_db);
	if(G_UNLIKELY(format_version!=CURRENT_ENCRYPTION_FORMAT_VERSION))
	{
		g_message(_("Failed to decrypt file due to unsupported file version number."));
		decryption_result=OTB_PAD_DB_CRYPT_RESULT_UNSUPPORTED_FILE_FORMAT;
	}
	else
	{
		unsigned char unique_id_bytes[OTB_UNIQUE_ID_BYTES_LENGTH];
		*plain_bytes_out=otb_malloc_locked(encrypted_bytes_size-sizeof format_version-OTB_UNIQUE_ID_BYTES_LENGTH);
		*plain_bytes_size_out=0;
		for(size_t encrypted_position=sizeof format_version; decryption_result==OTB_PAD_DB_CRYPT_RESULT_SUCCESS && encrypted_position<encrypted_bytes_size; )
		{
			off_t pad_size=-1;
			if(G_UNLIKELY(!otb_pad_db_crypt_bytes(OTB_UNIQUE_ID_BYTES_LENGTH, encrypted_bytes+encrypted_position, unique_id_bytes, cipher_context)))
				decryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
			else
			{
				OtbPadRec *pad_rec=NULL;
				OtbUniqueId *unique_id=otb_unique_id_from_bytes(unique_id_bytes);
				if(G_UNLIKELY((pad_rec=otb_pad_db_find_pad_rec_by_id_no_ref(pad_db, unique_id))==NULL))
					decryption_result=OTB_PAD_DB_CRYPT_RESULT_MISSING_PAD;
				else if(g_object_get(pad_rec, OTB_PAD_REC_PROP_SIZE, &pad_size, NULL), G_UNLIKELY(pad_size<0))
					decryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
				else if(G_UNLIKELY((cipher_context->current_pad_io=otb_pad_rec_open_pad_for_read(pad_rec, TRUE))==NULL))
					decryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
				else if(G_UNLIKELY(!otb_pad_db_crypt_bytes(pad_size-OTB_UNIQUE_ID_BYTES_LENGTH, encrypted_bytes+encrypted_position+OTB_UNIQUE_ID_BYTES_LENGTH, *(unsigned char**)plain_bytes_out+*plain_bytes_size_out, cipher_context)))
					decryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
				else
					g_object_set(pad_rec, OTB_PAD_REC_PROP_STATUS, OTB_PAD_REC_STATUS_DEAD, NULL);
				otb_unique_id_unref(unique_id);
			}
			if(G_UNLIKELY(cipher_context->previous_pad_io!=NULL && !otb_pad_io_free(cipher_context->previous_pad_io) && decryption_result==OTB_PAD_DB_CRYPT_RESULT_SUCCESS))
				decryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
			cipher_context->previous_pad_io=cipher_context->current_pad_io;
			cipher_context->current_pad_io=NULL;
			encrypted_position+=pad_size;
			*plain_bytes_size_out+=pad_size-OTB_UNIQUE_ID_BYTES_LENGTH;
		}
		if(G_UNLIKELY(cipher_context->previous_pad_io!=NULL && !otb_pad_io_free(cipher_context->previous_pad_io) && decryption_result==OTB_PAD_DB_CRYPT_RESULT_SUCCESS))
			decryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
		cipher_context->previous_pad_io=NULL;
		if(G_UNLIKELY(decryption_result==OTB_PAD_DB_CRYPT_RESULT_SUCCESS && !otb_pad_db_remove_dead_pads(pad_db)))
		{
			g_message(_("Failed to delete all pads used to decrypt a file, though file itself was fully decrypted. Recomendation is reset the pad database."));
			decryption_result=OTB_PAD_DB_CRYPT_RESULT_SUCCESS_PAD_STATUS_UPDATE_FAILED;
		}
		otb_pad_db_transition_status_of_pads(pad_db, OTB_PAD_REC_STATUS_DEAD, OTB_PAD_REC_STATUS_RECEIVED);
		if(G_UNLIKELY(decryption_result!=OTB_PAD_DB_CRYPT_RESULT_SUCCESS))
			g_free(*plain_bytes_out);
	}
	if(G_UNLIKELY(decryption_result!=OTB_PAD_DB_CRYPT_RESULT_SUCCESS))
	{
		*plain_bytes_out=NULL;
		*plain_bytes_size_out=0;
	}
	otb_pad_db_unlock_write(pad_db);
	return decryption_result;
}

OtbCipherContext *otb_cipher_context_new()
{
	OtbCipherContext *cipher_context=g_malloc(sizeof(OtbCipherContext));
	cipher_context->plain_buffer_length;
	cipher_context->plain_buffer=NULL;
	cipher_context->encrypted_buffer_length;
	cipher_context->encrypted_buffer=NULL;
	cipher_context->current_pad_io=NULL;
	cipher_context->previous_pad_io=NULL;
	return cipher_context;
}

void otb_cipher_context_free(OtbCipherContext *cipher_context)
{
	g_free(cipher_context->plain_buffer);
	g_free(cipher_context->encrypted_buffer);
	if(cipher_context->current_pad_io!=NULL)
		otb_pad_io_free(cipher_context->current_pad_io);
	if(cipher_context->previous_pad_io!=NULL)
		otb_pad_io_free(cipher_context->previous_pad_io);
	g_free(cipher_context);
}
