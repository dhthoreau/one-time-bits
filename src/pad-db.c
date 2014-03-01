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

struct _OtbPadDbPrivate
{
	GMutex mutex;
	char *base_path;
	char *file_path;
	off_t max_size;
	off_t new_pad_min_size;
	off_t new_pad_max_size;
	GSList *pad_recs;
	OtbPadIO *open_pad_io;
};

#define DEFAULT_MAX_SIZE			10485760
#define DEFAULT_NEW_PAD_MIN_SIZE	10240
#define DEFAULT_NEW_PAD_MAX_SIZE	20480
#define MINIMUM_NEW_PAD_SIZE		1024

enum
{
	PROP_0,
	PROP_BASE_PATH,
	PROP_MAX_SIZE,
	PROP_NEW_PAD_MIN_SIZE,
	PROP_NEW_PAD_MAX_SIZE
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
	g_object_class_install_property(object_class, PROP_MAX_SIZE, g_param_spec_int64(OTB_PAD_DB_PROP_MAX_SIZE, _("Max size"), _("Maximum size of the database"), 0, G_MAXINT64, DEFAULT_MAX_SIZE, G_PARAM_READABLE));
	g_object_class_install_property(object_class, PROP_NEW_PAD_MIN_SIZE, g_param_spec_int64(OTB_PAD_DB_PROP_NEW_PAD_MIN_SIZE, _("New pad min size"), _("Minimum size for a newly created pad"), 0, G_MAXINT64, DEFAULT_NEW_PAD_MIN_SIZE, G_PARAM_READABLE));
	g_object_class_install_property(object_class, PROP_NEW_PAD_MAX_SIZE, g_param_spec_int64(OTB_PAD_DB_PROP_NEW_PAD_MAX_SIZE, _("New pad max size"), _("Maximum size for a newly created pad"), 0, G_MAXINT64, DEFAULT_NEW_PAD_MAX_SIZE, G_PARAM_READABLE));
	g_type_class_add_private(klass, sizeof(OtbPadDbPrivate));
}

static void otb_pad_db_init(OtbPadDb *pad_db)
{
	pad_db->priv=G_TYPE_INSTANCE_GET_PRIVATE(pad_db, OTB_TYPE_PAD_DB, OtbPadDbPrivate);
	g_mutex_init(&pad_db->priv->mutex);
	pad_db->priv->base_path=NULL;
	pad_db->priv->file_path=NULL;
	pad_db->priv->max_size=DEFAULT_MAX_SIZE;
	pad_db->priv->new_pad_min_size=DEFAULT_NEW_PAD_MIN_SIZE;
	pad_db->priv->new_pad_max_size=DEFAULT_NEW_PAD_MAX_SIZE;
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
	g_mutex_clear(&pad_db->priv->mutex);
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

static void otb_pad_db_set_property(GObject *object, unsigned int prop_id, const GValue *value, GParamSpec *pspec)
{
	OtbPadDb *pad_db=OTB_PAD_DB(object);
	switch(prop_id)
	{
		case PROP_BASE_PATH:
			otb_pad_db_set_base_path(pad_db, g_value_get_string(value));
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
	}
}

static void otb_pad_db_get_property(GObject *object, unsigned int prop_id, GValue *value, GParamSpec *pspec)
{
	OtbPadDb *pad_db=OTB_PAD_DB(object);
	switch(prop_id)
	{
		case PROP_BASE_PATH:
			g_value_set_string(value, pad_db->priv->base_path);
			break;
		case PROP_MAX_SIZE:
			g_value_set_int64(value, pad_db->priv->max_size);
			break;
		case PROP_NEW_PAD_MIN_SIZE:
			g_value_set_int64(value, pad_db->priv->new_pad_min_size);
			break;
		case PROP_NEW_PAD_MAX_SIZE:
			g_value_set_int64(value, pad_db->priv->new_pad_max_size);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
	}
}

#define SAVE_GROUP					"pad-db"
#define SAVE_KEY_MAX_SIZE			"max-size"
#define SAVE_KEY_NEW_PAD_MIN_SIZE	"new-pad-min-size"
#define SAVE_KEY_NEW_PAD_MAX_SIZE	"new-pad-max-size"

static gboolean otb_pad_db_save(const OtbPadDb *pad_db)
{
	gboolean ret_val=TRUE;
	if(otb_mkdir_with_parents(pad_db->priv->base_path))
	{
		GKeyFile *key_file=g_key_file_new();
		g_key_file_set_int64(key_file, SAVE_GROUP, SAVE_KEY_MAX_SIZE, pad_db->priv->max_size);
		g_key_file_set_int64(key_file, SAVE_GROUP, SAVE_KEY_NEW_PAD_MIN_SIZE, pad_db->priv->new_pad_min_size);
		g_key_file_set_int64(key_file, SAVE_GROUP, SAVE_KEY_NEW_PAD_MAX_SIZE, pad_db->priv->new_pad_max_size);
		ret_val=otb_settings_save_key_file(key_file, pad_db->priv->file_path);
		g_key_file_unref(key_file);
	}
	return ret_val;
}

static void otb_pad_db_lock(const OtbPadDb *pad_db)
{
	g_mutex_lock(&pad_db->priv->mutex);
}

static void otb_pad_db_unlock(const OtbPadDb *pad_db)
{
	g_mutex_unlock(&pad_db->priv->mutex);
}

OtbPadDb *otb_pad_db_create_in_directory(const char *base_path)
{
	OtbPadDb *pad_db=g_object_new(OTB_TYPE_PAD_DB, OTB_PAD_DB_PROP_BASE_PATH, base_path, NULL);
	if(g_file_test(pad_db->priv->file_path, G_FILE_TEST_EXISTS) || !otb_pad_db_save(pad_db))
	{
		g_object_unref(pad_db);
		pad_db=NULL;
	}
	return pad_db;
}

static gboolean otb_pad_db_load(const OtbPadDb *pad_db)
{
	gboolean ret_val=TRUE;
	GKeyFile *key_file=otb_settings_load_key_file(pad_db->priv->file_path);
	if(key_file==NULL)
		ret_val=FALSE;
	else if((pad_db->priv->max_size=otb_settings_get_int64(key_file, SAVE_GROUP, SAVE_KEY_MAX_SIZE, -1))==-1)
		ret_val=FALSE;
	else if((pad_db->priv->new_pad_min_size=otb_settings_get_int64(key_file, SAVE_GROUP, SAVE_KEY_NEW_PAD_MIN_SIZE, -1))==-1)
		ret_val=FALSE;
	else if((pad_db->priv->new_pad_max_size=otb_settings_get_int64(key_file, SAVE_GROUP, SAVE_KEY_NEW_PAD_MAX_SIZE, -1))==-1)
		ret_val=FALSE;
	if(key_file!=NULL)
		g_key_file_unref(key_file);
	return ret_val;
}

static OtbPadRec *otb_pad_db_find_pad_rec_by_id(const OtbPadDb *pad_db, const uuid_t *unique_id)
{
	for(const GSList *curr_element=pad_db->priv->pad_recs; curr_element!=NULL; curr_element=(const GSList*)g_list_next(curr_element))
	{
		OtbPadRec *pad_rec=OTB_PAD_REC(curr_element->data);
		if(otb_pad_rec_compare_by_id((gpointer)pad_rec, (gpointer)unique_id)==0)
			return pad_rec;
	}
	return NULL;
}

static off_t otb_pad_db_get_curr_size(const OtbPadDb *pad_db)
{
	off_t curr_size=0;
	for(const GSList *curr_element=pad_db->priv->pad_recs; curr_element!=NULL; curr_element=(const GSList*)g_list_next(curr_element))
	{
		OtbPadRec *pad_rec=OTB_PAD_REC(curr_element->data);
		off_t pad_size;
		g_object_get(pad_rec, OTB_PAD_REC_PROP_SIZE, &pad_size, NULL);
		if(pad_size>0)
			curr_size+=pad_size;
	}
	return curr_size;
}

static gboolean otb_pad_db_add_pad_rec(const OtbPadDb *pad_db, OtbPadRec *pad_rec)
{
	gboolean ret_val=TRUE;
	const uuid_t *unique_id=NULL;
	g_object_get(pad_rec, OTB_PAD_REC_PROP_UNIQUE_ID, &unique_id, NULL);
	off_t pad_size;
	g_object_get(pad_rec, OTB_PAD_REC_PROP_SIZE, &pad_size, NULL);
	if(otb_pad_db_find_pad_rec_by_id(pad_db, unique_id)!=NULL)
	{
		g_message(_("Failed to add record due to non-unique ID."));
		ret_val=FALSE;
	}
	else if(otb_pad_db_get_curr_size(pad_db)+pad_size>pad_db->priv->max_size)
	{
		g_message(_("Failed to add record due to database size limitation."));
		ret_val=FALSE;
	}
	else if(otb_pad_rec_save(pad_rec))
		pad_db->priv->pad_recs=g_slist_prepend(pad_db->priv->pad_recs, pad_rec);
	return ret_val;
}

static gboolean otb_pad_db_load_all_recs(const OtbPadDb *pad_db)
{
	gboolean ret_val=TRUE;
	GError *error=NULL;
	GDir *pad_db_directory=g_dir_open(pad_db->priv->base_path, 0, &error);
	if(pad_db_directory==NULL)
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
				if(pad_rec==NULL)
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
	if(!otb_pad_db_load(pad_db))
		load_successful=FALSE;
	else if(!otb_pad_db_load_all_recs(pad_db))
		load_successful=FALSE;
	if(!load_successful)
	{
		g_object_unref(pad_db);
		pad_db=NULL;
	}
	return pad_db;
}

gboolean otb_pad_db_set_max_size(const OtbPadDb *pad_db, off_t max_size)
{
	gboolean ret_val=TRUE;
	otb_pad_db_lock(pad_db);
	off_t old_max_size=pad_db->priv->max_size;
	pad_db->priv->max_size=max_size;
	if(!otb_pad_db_save(pad_db))
	{
		pad_db->priv->max_size=old_max_size;
		ret_val=FALSE;
	}
	otb_pad_db_unlock(pad_db);
	return ret_val;
}

gboolean otb_pad_db_set_new_pad_min_size(const OtbPadDb *pad_db, off_t new_pad_min_size)
{
	gboolean ret_val=TRUE;
	if(new_pad_min_size<MINIMUM_NEW_PAD_SIZE)
		ret_val=FALSE;
	else
	{
		otb_pad_db_lock(pad_db);
		off_t old_pad_min_size=pad_db->priv->new_pad_min_size;
		off_t old_pad_max_size=pad_db->priv->new_pad_max_size;
		pad_db->priv->new_pad_min_size=new_pad_min_size;
		if(pad_db->priv->new_pad_min_size>pad_db->priv->new_pad_max_size)
			pad_db->priv->new_pad_max_size=pad_db->priv->new_pad_min_size;
		if(!otb_pad_db_save(pad_db))
		{
			pad_db->priv->new_pad_min_size=old_pad_min_size;
			pad_db->priv->new_pad_max_size=old_pad_max_size;
			ret_val=FALSE;
		}
		otb_pad_db_unlock(pad_db);
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
		otb_pad_db_lock(pad_db);
		off_t old_pad_min_size=pad_db->priv->new_pad_min_size;
		off_t old_pad_max_size=pad_db->priv->new_pad_max_size;
		pad_db->priv->new_pad_max_size=new_pad_max_size;
		if(pad_db->priv->new_pad_min_size>pad_db->priv->new_pad_max_size)
			pad_db->priv->new_pad_max_size=pad_db->priv->new_pad_min_size;
		if(!otb_pad_db_save(pad_db))
		{
			pad_db->priv->new_pad_min_size=old_pad_min_size;
			pad_db->priv->new_pad_max_size=old_pad_max_size;
			ret_val=FALSE;
		}
		otb_pad_db_unlock(pad_db);
	}
	return ret_val;
}

static gboolean otb_pad_db_remove_pad_rec(const OtbPadDb *pad_db, OtbPadRec *pad_rec)
{
	gboolean ret_val=TRUE;
	if(!otb_pad_rec_delete(pad_rec))
		ret_val=FALSE;
	else
	{
		pad_db->priv->pad_recs=g_slist_remove(pad_db->priv->pad_recs, pad_rec);
		g_object_unref(pad_rec);
	}
	return ret_val;
}

gboolean otb_pad_db_remove_pad(const OtbPadDb *pad_db, const uuid_t *unique_id)
{
	gboolean ret_val=TRUE;
	otb_pad_db_lock(pad_db);
	OtbPadRec *pad_rec=otb_pad_db_find_pad_rec_by_id(pad_db, unique_id);
	if(pad_rec!=NULL && !otb_pad_db_remove_pad_rec(pad_db, pad_rec))
		ret_val=FALSE;
	otb_pad_db_unlock(pad_db);
	return ret_val;
}

static gboolean otb_pad_db_remove_dead_pads(const OtbPadDb *pad_db)
{
	gboolean ret_val=TRUE;
	GSList *pad_recs_to_remove=NULL;
	for(const GSList *curr_element=pad_db->priv->pad_recs; curr_element!=NULL; curr_element=(const GSList*)g_list_next(curr_element))
	{
		OtbPadRec *pad_rec=OTB_PAD_REC(curr_element->data);
		OtbPadRecStatus pad_rec_status;
		g_object_get(pad_rec, OTB_PAD_REC_PROP_STATUS, &pad_rec_status, NULL);
		if(pad_rec_status==OTB_PAD_REC_STATUS_DEAD)
			pad_recs_to_remove=g_slist_prepend(pad_recs_to_remove, pad_rec);
	}
	for(const GSList *curr_element=pad_recs_to_remove; curr_element!=NULL && ret_val; curr_element=(const GSList*)g_list_next(curr_element))
	{
		OtbPadRec *pad_rec=OTB_PAD_REC(curr_element->data);
		if(!otb_pad_db_remove_pad_rec(pad_db, pad_rec))
			ret_val=FALSE;
	}
	g_slist_free(pad_recs_to_remove);
	return ret_val;
}

gboolean otb_pad_db_create_unsent_pad(const OtbPadDb *pad_db)
{
	gboolean ret_val=TRUE;
	otb_pad_db_lock(pad_db);
	off_t new_pad_size;
	if(!otb_random_bytes(&new_pad_size, sizeof new_pad_size))
		ret_val=FALSE;
	else
	{
		new_pad_size=otb_modulo(new_pad_size, (pad_db->priv->new_pad_max_size-pad_db->priv->new_pad_min_size+1))+pad_db->priv->new_pad_min_size;
		OtbPadRec *pad_rec=g_object_new(OTB_TYPE_PAD_REC, OTB_PAD_REC_PROP_BASE_PATH, pad_db->priv->base_path, OTB_PAD_REC_PROP_SIZE, new_pad_size, NULL);
		if(!otb_pad_db_add_pad_rec(pad_db, pad_rec))
		{
			ret_val=FALSE;
			g_object_unref(pad_rec);
		}
		else if(!otb_pad_rec_generate_pad_file(pad_rec))
		{
			otb_pad_db_remove_pad_rec(pad_db, pad_rec);
			ret_val=FALSE;
		}
	}
	otb_pad_db_unlock(pad_db);
	return ret_val;
}

OtbPadIO *otb_pad_db_add_received_pad(const OtbPadDb *pad_db, const uuid_t *unique_id, off_t size)
{
	OtbPadIO *pad_io=NULL;
	otb_pad_db_lock(pad_db);
	if(pad_db->priv->open_pad_io==NULL)
	{
		OtbPadRec *pad_rec=g_object_new(OTB_TYPE_PAD_REC, OTB_PAD_REC_PROP_UNIQUE_ID, unique_id, OTB_PAD_REC_PROP_STATUS, OTB_PAD_REC_STATUS_RECEIVED, OTB_PAD_REC_PROP_BASE_PATH, pad_db->priv->base_path, OTB_PAD_REC_PROP_SIZE, size, NULL);
		if(!otb_pad_db_add_pad_rec(pad_db, pad_rec))
			g_object_unref(pad_rec);
		else if((pad_io=otb_pad_rec_open_pad_for_write(pad_rec))==NULL)
			otb_pad_db_remove_pad_rec(pad_db, pad_rec);
	}
	if(pad_io==NULL)
		otb_pad_db_unlock(pad_db);
	else
		pad_db->priv->open_pad_io=pad_io;
	return pad_io;
}

GSList *otb_pad_db_get_ids_of_pads_in_status(const OtbPadDb *pad_db, OtbPadRecStatus status)
{
	GSList *selected_pad_recs=NULL;
	for(const GSList *curr_element=pad_db->priv->pad_recs; curr_element!=NULL; curr_element=(const GSList*)g_list_next(curr_element))
	{
		OtbPadRec *pad_rec=OTB_PAD_REC(curr_element->data);
		OtbPadRecStatus pad_rec_status;
		g_object_get(pad_rec, OTB_PAD_REC_PROP_STATUS, &pad_rec_status, NULL);
		if(pad_rec_status==status)
		{
			const uuid_t *unique_id=NULL;
			g_object_get(pad_rec, OTB_PAD_REC_PROP_UNIQUE_ID, &unique_id, NULL);
			selected_pad_recs=g_slist_prepend(selected_pad_recs, unique_id);
		}
	}
	return selected_pad_recs;
}

static gboolean otb_pad_db_transition_status_of_pad(const OtbPadDb *pad_db, const uuid_t *unique_id, OtbPadRecStatus prerequisite_status, OtbPadRecStatus new_status)
{
	gboolean ret_val=TRUE;
	OtbPadRec *pad_rec=otb_pad_db_find_pad_rec_by_id(pad_db, unique_id);
	OtbPadRecStatus pad_rec_status;
	g_object_get(pad_rec, OTB_PAD_REC_PROP_STATUS, &pad_rec_status, NULL);
	if(pad_rec_status!=prerequisite_status)
		ret_val=FALSE;
	else
	{
		g_object_set(pad_rec, OTB_PAD_REC_PROP_STATUS, new_status, NULL);
		if(!otb_pad_rec_save(pad_rec))
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
	for(const GSList *curr_element=pad_db->priv->pad_recs; ret_val && curr_element!=NULL; curr_element=(const GSList*)g_list_next(curr_element))
	{
		OtbPadRec *pad_rec=OTB_PAD_REC(curr_element->data);
		OtbPadRecStatus pad_rec_status;
		g_object_get(pad_rec, OTB_PAD_REC_PROP_STATUS, &pad_rec_status, NULL);
		if(pad_rec_status==prerequisite_status)
		{
			const uuid_t *unique_id=NULL;
			g_object_get(pad_rec, OTB_PAD_REC_PROP_UNIQUE_ID, &unique_id, NULL);
			ret_val=otb_pad_db_transition_status_of_pad(pad_db, unique_id, prerequisite_status, new_status);
		}
	}
	return ret_val;
}

gboolean otb_pad_db_mark_pad_as_sent(const OtbPadDb *pad_db, const uuid_t *unique_id)
{
	gboolean ret_val;
	otb_pad_db_lock(pad_db);
	ret_val=otb_pad_db_transition_status_of_pad(pad_db, unique_id, OTB_PAD_REC_STATUS_UNSENT, OTB_PAD_REC_STATUS_SENT);
	otb_pad_db_unlock(pad_db);
	return ret_val;
}

static const uuid_t *otb_pad_db_fetch_random_rec_id_no_lock(const OtbPadDb *pad_db, OtbPadRecStatus status)
{
	const uuid_t *unique_id=NULL;
	GSList *candidate_pads=NULL;
	unsigned int candidate_count=0;
	for(const GSList *curr_element=pad_db->priv->pad_recs; curr_element!=NULL; curr_element=(const GSList*)g_list_next(curr_element))
	{
		OtbPadRec *pad_rec=OTB_PAD_REC(curr_element->data);
		OtbPadRecStatus pad_rec_status;
		g_object_get(pad_rec, OTB_PAD_REC_PROP_STATUS, &pad_rec_status, NULL);
		if(pad_rec_status==status)
		{
			const uuid_t *unique_id=NULL;
			g_object_get(pad_rec, OTB_PAD_REC_PROP_UNIQUE_ID, &unique_id, NULL);
			candidate_pads=g_slist_prepend(candidate_pads, unique_id);
			candidate_count++;
		}
	}
	if(candidate_count!=0)
	{
		unsigned int nth;
		if(otb_random_bytes(&nth, sizeof nth))
		{
			nth=otb_modulo(nth, candidate_count);
			unique_id=g_slist_nth(candidate_pads, nth)->data;
		}
	}
	g_slist_free(candidate_pads);
	return unique_id;
}

const uuid_t *otb_pad_db_fetch_random_rec_id(const OtbPadDb *pad_db, OtbPadRecStatus status)
{
	otb_pad_db_lock(pad_db);
	const uuid_t *unique_id=otb_pad_db_fetch_random_rec_id_no_lock(pad_db, status);
	otb_pad_db_unlock(pad_db);
	return unique_id;
}

off_t otb_pad_db_get_pad_size(const OtbPadDb *pad_db, const uuid_t *unique_id)
{
	otb_pad_db_lock(pad_db);
	OtbPadRec *pad_rec=otb_pad_db_find_pad_rec_by_id(pad_db, unique_id);
	off_t pad_size=-1;
	if(pad_rec!=NULL)
		g_object_get(pad_rec, OTB_PAD_REC_PROP_SIZE, &pad_size, NULL);
	otb_pad_db_unlock(pad_db);
	return pad_size;
}

OtbPadIO *otb_pad_db_open_pad_for_read(const OtbPadDb *pad_db, const uuid_t *unique_id)
{
	const OtbPadRec *pad_rec;
	OtbPadIO *pad_io=NULL;
	otb_pad_db_lock(pad_db);
	if(pad_db->priv->open_pad_io==NULL)
		if((pad_rec=otb_pad_db_find_pad_rec_by_id(pad_db, unique_id))==NULL);
			pad_io=otb_pad_rec_open_pad_for_read(pad_rec, FALSE);
	if(pad_io==NULL)
		otb_pad_db_unlock(pad_db);
	else
		pad_db->priv->open_pad_io=pad_io;
	return pad_io;
}

gboolean otb_pad_db_close_pad(const OtbPadDb *pad_db)
{
	if(pad_db->priv->open_pad_io==NULL)
		return FALSE;
	otb_pad_io_free(pad_db->priv->open_pad_io);
	pad_db->priv->open_pad_io=NULL;
	otb_pad_db_unlock(pad_db);
	return TRUE;
}

static gboolean otb_pad_db_can_encrypt_file(const OtbPadDb *pad_db, const char *input_file_path)
{
	gboolean ret_val=FALSE;
	off_t bytes_needed_for_encryption=otb_get_file_size(input_file_path);
	off_t bytes_available_for_encryption=0;
	for(const GSList *curr_element=pad_db->priv->pad_recs; !ret_val && curr_element!=NULL; curr_element=(const GSList*)g_list_next(curr_element))
	{
		OtbPadRec *pad_rec=OTB_PAD_REC(curr_element->data);
		off_t pad_size;
		g_object_get(pad_rec, OTB_PAD_REC_PROP_SIZE, &pad_size, NULL);
		bytes_available_for_encryption+=pad_size-sizeof(uuid_t);
		if(bytes_available_for_encryption>=bytes_needed_for_encryption)
			ret_val=TRUE;
	}
	return ret_val;
}

static gboolean otb_pad_db_crypt_bytes(size_t bytes_to_crypt, const void *input_bytes, FILE *input_file, void *output_bytes, FILE *output_file, OtbPadIO *current_pad_io, OtbPadIO *previous_pad_io)
{
	gboolean ret_val=TRUE;
	for(unsigned int loop_count=0; ret_val && bytes_to_crypt>0 && (input_file==NULL || otb_file_has_more_bytes(input_file)); bytes_to_crypt--, loop_count++)
	{
		char input_byte;
		char current_pad_byte=0;
		char previous_pad_byte=0;
		if(input_bytes!=NULL)
			input_byte=((char*)input_bytes)[loop_count];
		if(input_file!=NULL && !otb_read_byte(&input_byte, input_file))
			ret_val=FALSE;
		else if(current_pad_io!=NULL && !otb_pad_read_byte(current_pad_io, &current_pad_byte))
			ret_val=FALSE;
		else if(previous_pad_io!=NULL && !otb_pad_read_byte(previous_pad_io, &previous_pad_byte))
			ret_val=FALSE;
		else
		{
			char output_byte=(input_byte ^ current_pad_byte ^ previous_pad_byte);
			if(output_bytes!=NULL)
				((char*)output_bytes)[loop_count]=output_byte;
			if(output_file!=NULL && !otb_write_byte(output_byte, output_file))
				ret_val=FALSE;
		}
	}
	return ret_val;
}

OtbPadDbCryptResults otb_pad_db_encrypt_file(const OtbPadDb *pad_db, const char *input_file_path, const char *output_file_path)
{
	const guint8 FILE_FORMAT_VERSION='\x00';
	
	OtbPadDbCryptResults encryption_result=OTB_PAD_DB_CRYPT_RESULT_SUCCESS;
	FILE *input_file=NULL;
	FILE *output_file=NULL;
	OtbPadIO *current_pad_io=NULL;
	OtbPadIO *previous_pad_io=NULL;
	OtbPadRec *pad_rec;
	off_t pad_size;
	otb_pad_db_lock(pad_db);
	if(!otb_pad_db_can_encrypt_file(pad_db, input_file_path))
		encryption_result=OTB_PAD_DB_CRYPT_RESULT_NOT_ENOUGH_PADS;
	else if((input_file=otb_open_for_read(input_file_path))==NULL)
		encryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
	else if((output_file=otb_open_for_write(output_file_path))==NULL)
		encryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
	else if(otb_write(&FILE_FORMAT_VERSION, sizeof FILE_FORMAT_VERSION, 1, output_file)!=1)
		encryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
	while(encryption_result==OTB_PAD_DB_CRYPT_RESULT_SUCCESS && otb_file_has_more_bytes(input_file))
	{
		const uuid_t *unique_id=otb_pad_db_fetch_random_rec_id_no_lock(pad_db, OTB_PAD_REC_STATUS_SENT);
		if(unique_id==NULL)
			encryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
		else if(!otb_pad_db_crypt_bytes(sizeof *unique_id, *unique_id, NULL, NULL, output_file, current_pad_io, previous_pad_io))
			encryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
		else if((pad_rec=otb_pad_db_find_pad_rec_by_id(pad_db, unique_id))==NULL)
			encryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
		else if(g_object_get(pad_rec, OTB_PAD_REC_PROP_SIZE, &pad_size, NULL), pad_size<0)
			encryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
		else if((current_pad_io=otb_pad_rec_open_pad_for_read(pad_rec, TRUE))==NULL)
			encryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
		else if(!otb_pad_db_crypt_bytes(pad_size-sizeof(uuid_t), NULL, input_file, NULL, output_file, current_pad_io, previous_pad_io))
			encryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
		else
			g_object_set(pad_rec, OTB_PAD_REC_PROP_STATUS, OTB_PAD_REC_STATUS_BEING_CONSUMED, NULL);
		if(previous_pad_io!=NULL && !otb_pad_io_free(previous_pad_io) && encryption_result==OTB_PAD_DB_CRYPT_RESULT_SUCCESS)
			encryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
		previous_pad_io=current_pad_io;
		current_pad_io=NULL;
	}
	if(input_file!=NULL && !otb_close(input_file) && encryption_result==OTB_PAD_DB_CRYPT_RESULT_SUCCESS)
		encryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
	if(output_file!=NULL && !otb_close(output_file) && encryption_result==OTB_PAD_DB_CRYPT_RESULT_SUCCESS)
		encryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
	if(previous_pad_io!=NULL && !otb_pad_io_free(previous_pad_io) && encryption_result==OTB_PAD_DB_CRYPT_RESULT_SUCCESS)
		encryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
	if(encryption_result==OTB_PAD_DB_CRYPT_RESULT_SUCCESS && !otb_pad_db_transition_status_of_pads(pad_db, OTB_PAD_REC_STATUS_BEING_CONSUMED, OTB_PAD_REC_STATUS_CONSUMED))
	{
		g_warning(_("Failed to update the status of all pads used to encrypt a file, though file itself was fully encrypted. This could cause problems for the recipient of your encrypted files. Recomendation is that the encrypted file not be used."));
		encryption_result=OTB_PAD_DB_CRYPT_RESULT_SUCCESS_PAD_STATUS_UPDATE_FAILED;
	}
	otb_pad_db_transition_status_of_pads(pad_db, OTB_PAD_REC_STATUS_BEING_CONSUMED, OTB_PAD_REC_STATUS_SENT);
	otb_pad_db_unlock(pad_db);
	return encryption_result;
}

OtbPadDbCryptResults otb_pad_db_decrypt_file(const OtbPadDb *pad_db, const char *input_file_path, const char *output_file_path)
{
	OtbPadDbCryptResults decryption_result=OTB_PAD_DB_CRYPT_RESULT_SUCCESS;
	guint8 file_format_version;
	FILE *input_file=NULL;
	FILE *output_file=NULL;
	OtbPadIO *current_pad_io=NULL;
	OtbPadIO *previous_pad_io=NULL;
	OtbPadRec *pad_rec;
	off_t pad_size;
	otb_pad_db_lock(pad_db);
	if((input_file=otb_open_for_read(input_file_path))==NULL)
		decryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
	else if((output_file=otb_open_for_write(output_file_path))==NULL)
		decryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
	else if(otb_read(&file_format_version, sizeof file_format_version, 1, input_file)!=1)
		decryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
	else if(file_format_version!=0)
	{
		g_message(_("Failed to decrypt file due to unsupported file version number."));
		decryption_result=OTB_PAD_DB_CRYPT_RESULT_UNSUPPORTED_FILE_FORMAT;
	}
	while(decryption_result==OTB_PAD_DB_CRYPT_RESULT_SUCCESS && otb_file_has_more_bytes(input_file))
	{
		uuid_t unique_id;
		if(!otb_pad_db_crypt_bytes(sizeof unique_id, NULL, input_file, unique_id, NULL, current_pad_io, previous_pad_io))
			decryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
		else if((pad_rec=otb_pad_db_find_pad_rec_by_id(pad_db, (const uuid_t*)&unique_id))==NULL)
			decryption_result=OTB_PAD_DB_CRYPT_RESULT_MISSING_PAD;
		else if(g_object_get(pad_rec, OTB_PAD_REC_PROP_SIZE, &pad_size, NULL), pad_size<0)
			decryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
		else if((current_pad_io=otb_pad_rec_open_pad_for_read(pad_rec, TRUE))==NULL)
			decryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
		else if(!otb_pad_db_crypt_bytes(pad_size-sizeof(uuid_t), NULL, input_file, NULL, output_file, current_pad_io, previous_pad_io))
			decryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
		else
			g_object_set(pad_rec, OTB_PAD_REC_PROP_STATUS, OTB_PAD_REC_STATUS_DEAD, NULL);
		if(previous_pad_io!=NULL && !otb_pad_io_free(previous_pad_io) && decryption_result==OTB_PAD_DB_CRYPT_RESULT_SUCCESS)
			decryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
		previous_pad_io=current_pad_io;
		current_pad_io=NULL;
	}
	if(input_file!=NULL && !otb_close(input_file) && decryption_result==OTB_PAD_DB_CRYPT_RESULT_SUCCESS)
		decryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
	if(output_file!=NULL && !otb_close(output_file) && decryption_result==OTB_PAD_DB_CRYPT_RESULT_SUCCESS)
		decryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
	if(previous_pad_io!=NULL && !otb_pad_io_free(previous_pad_io) && decryption_result==OTB_PAD_DB_CRYPT_RESULT_SUCCESS)
		decryption_result=OTB_PAD_DB_CRYPT_RESULT_FAILURE;
	if(decryption_result==OTB_PAD_DB_CRYPT_RESULT_SUCCESS && !otb_pad_db_remove_dead_pads(pad_db))
	{
		g_message(_("Failed to delete all pads used to decrypt a file, though file itself was fully decrypted. Recomendation is reset the pad database."));
		decryption_result=OTB_PAD_DB_CRYPT_RESULT_SUCCESS_PAD_STATUS_UPDATE_FAILED;
	}
	otb_pad_db_transition_status_of_pads(pad_db, OTB_PAD_REC_STATUS_DEAD, OTB_PAD_REC_STATUS_RECEIVED);
	otb_pad_db_unlock(pad_db);
	return decryption_result;
}
