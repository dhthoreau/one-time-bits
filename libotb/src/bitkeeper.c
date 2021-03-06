/**
 * Copyright © 2017 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <glib/gi18n.h>

#include "asym-cipher.h"
#include "bitkeeper.h"
#include "io.h"
#include "loopable-thread.h"
#include "protocol.h"
#include "settings.h"

#define CONFIG_GROUP						"bitkeeper"
#define CONFIG_PROXY_PORT					"proxy-port"
#define CONFIG_PAD_SYNCHRONIZATION_INTERVAL	"pad-synchronization-interval"

static GRWLock otb_global_bitkeeper_rw_lock;
static OtbBitkeeper *otb_global_bitkeeper=NULL;

#define otb_global_bitkeeper_lock_read()		(g_rw_lock_reader_lock(&otb_global_bitkeeper_rw_lock))
#define otb_global_bitkeeper_unlock_read()	(g_rw_lock_reader_unlock(&otb_global_bitkeeper_rw_lock))
#define otb_global_bitkeeper_lock_write()	(g_rw_lock_writer_lock(&otb_global_bitkeeper_rw_lock))
#define otb_global_bitkeeper_unlock_write()	(g_rw_lock_writer_unlock(&otb_global_bitkeeper_rw_lock))

enum
{
	PROP_0,
	PROP_USER,
	PROP_PROXY_PORT,
	PROP_PAD_SYNCHRONIZATION_INTERVAL
};

G_DEFINE_TYPE(OtbBitkeeper, otb_bitkeeper, G_TYPE_OBJECT);

static void otb_bitkeeper_dispose(GObject *object);
static void otb_bitkeeper_finalize(GObject *object);
static void otb_bitkeeper_set_property(GObject *object, unsigned int prop_id, const GValue *value, GParamSpec *pspec);
static void otb_bitkeeper_get_property(GObject *object, unsigned int prop_id, GValue *value, GParamSpec *pspec);

struct _OtbBitkeeperPrivate
{
	GRWLock lock;
	OtbUser *user;
	unsigned int proxy_port;
	long long pad_synchronization_interval;
	GSList *friends;
	char *friends_base_path;
	OtbLoopableThread *synchronize_pads_thread;
};

static void otb_bitkeeper_class_init(OtbBitkeeperClass *klass)
{
	GObjectClass *object_class=G_OBJECT_CLASS(klass);
	object_class->dispose=otb_bitkeeper_dispose;
	object_class->finalize=otb_bitkeeper_finalize;
	object_class->set_property=otb_bitkeeper_set_property;
	object_class->get_property=otb_bitkeeper_get_property;
	g_object_class_install_property(object_class, PROP_USER, g_param_spec_object(OTB_BITKEEPER_PROP_USER, _("User"), _("The user who is using the application"), OTB_TYPE_USER, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
	g_object_class_install_property(object_class, PROP_PROXY_PORT, g_param_spec_uint(OTB_BITKEEPER_PROP_PROXY_PORT, _("Proxy port"), _("The port for the local proxy, preferably TOR"), 1, G_MAXUSHORT, OTB_BITKEEPER_DEFAULT_PROXY_PORT, G_PARAM_READWRITE | G_PARAM_CONSTRUCT));
	g_object_class_install_property(object_class, PROP_PAD_SYNCHRONIZATION_INTERVAL, g_param_spec_int64(OTB_BITKEEPER_PROP_PAD_SYNCHRONIZATION_INTERVAL, _("Pad synchronization interval"), _("How often pads should be synchronized, measured in microseconds"), 1, G_MAXINT64, OTB_BITKEEPER_DEFAULT_PAD_SYNCHRONIZATION_INTERVAL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT));
	g_type_class_add_private(klass, sizeof(OtbBitkeeperPrivate));
}

static void otb_bitkeeper_init(OtbBitkeeper *bitkeeper)
{
	bitkeeper->priv=G_TYPE_INSTANCE_GET_PRIVATE(bitkeeper, OTB_TYPE_BITKEEPER, OtbBitkeeperPrivate);
	g_rw_lock_init(&bitkeeper->priv->lock);
	bitkeeper->priv->user=NULL;
	bitkeeper->priv->friends=NULL;
	bitkeeper->priv->friends_base_path=g_build_filename(otb_settings_get_data_directory_path(), "friends", NULL);
	bitkeeper->priv->synchronize_pads_thread=NULL;
}

static void otb_bitkeeper_dispose(GObject *object)
{
	g_return_if_fail(object!=NULL);
	g_return_if_fail(OTB_IS_BITKEEPER(object));
	OtbBitkeeper *bitkeeper=OTB_BITKEEPER(object);
	if(bitkeeper->priv->user!=NULL)
	{
		g_object_unref(bitkeeper->priv->user);
		bitkeeper->priv->user=NULL;
	}
	g_slist_free_full(bitkeeper->priv->friends, g_object_unref);
	bitkeeper->priv->friends=NULL;
	G_OBJECT_CLASS(otb_bitkeeper_parent_class)->dispose(object);
}

static void otb_bitkeeper_finalize(GObject *object)
{
	g_return_if_fail(object!=NULL);
	g_return_if_fail(OTB_IS_BITKEEPER(object));
	OtbBitkeeper *bitkeeper=OTB_BITKEEPER(object);
	g_rw_lock_clear(&bitkeeper->priv->lock);
	g_free(bitkeeper->priv->friends_base_path);
	G_OBJECT_CLASS(otb_bitkeeper_parent_class)->finalize(object);
}

#define otb_bitkeeper_lock_read(bitkeeper)		(g_rw_lock_reader_lock(&bitkeeper->priv->lock))
#define otb_bitkeeper_unlock_read(bitkeeper)	(g_rw_lock_reader_unlock(&bitkeeper->priv->lock))
#define otb_bitkeeper_lock_write(bitkeeper)		(g_rw_lock_writer_lock(&bitkeeper->priv->lock))
#define otb_bitkeeper_unlock_write(bitkeeper)	(g_rw_lock_writer_unlock(&bitkeeper->priv->lock))

static void otb_bitkeeper_set_property(GObject *object, unsigned int prop_id, const GValue *value, GParamSpec *pspec)
{
	OtbBitkeeper *bitkeeper=OTB_BITKEEPER(object);
	switch(prop_id)
	{
		case PROP_USER:
		{
			bitkeeper->priv->user=g_value_dup_object(value);
			break;
		}
		case PROP_PROXY_PORT:
		{
			otb_bitkeeper_lock_write(bitkeeper);
			bitkeeper->priv->proxy_port=g_value_get_uint(value);
			otb_bitkeeper_unlock_write(bitkeeper);
			break;
		}
		case PROP_PAD_SYNCHRONIZATION_INTERVAL:
		{
			otb_bitkeeper_lock_write(bitkeeper);
			bitkeeper->priv->pad_synchronization_interval=g_value_get_int64(value);
			otb_bitkeeper_unlock_write(bitkeeper);
			break;
		}
		default:
		{
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
		}
	}
}

static void otb_bitkeeper_get_property(GObject *object, unsigned int prop_id, GValue *value, GParamSpec *pspec)
{
	OtbBitkeeper *bitkeeper=OTB_BITKEEPER(object);
	switch(prop_id)
	{
		case PROP_USER:
		{
			g_value_set_object(value, bitkeeper->priv->user);
			break;
		}
		case PROP_PROXY_PORT:
		{
			otb_bitkeeper_lock_read(bitkeeper);
			g_value_set_uint(value, bitkeeper->priv->proxy_port);
			otb_bitkeeper_unlock_read(bitkeeper);
			break;
		}
		case PROP_PAD_SYNCHRONIZATION_INTERVAL:
		{
			otb_bitkeeper_lock_read(bitkeeper);
			g_value_set_int64(value, bitkeeper->priv->pad_synchronization_interval);
			otb_bitkeeper_unlock_read(bitkeeper);
			break;
		}
		default:
		{
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
		}
	}
}

gboolean otb_bitkeeper_exists(void)
{
	return otb_settings_config_group_exists(CONFIG_GROUP) && otb_user_exists();
}

static gboolean otb_bitkeeper_load_friends(OtbBitkeeper *bitkeeper)
{
	gboolean ret_val=TRUE;
	GDir *friends_dir;
	if(G_UNLIKELY(!otb_mkdir_with_parents(bitkeeper->priv->friends_base_path)))
		ret_val=FALSE;
	else if(G_UNLIKELY((friends_dir=otb_open_directory(bitkeeper->priv->friends_base_path))==NULL))
		ret_val=FALSE;
	else
	{
		const char *file_name;
		while(G_LIKELY(ret_val && (file_name=g_dir_read_name(friends_dir))!=NULL))
		{
			char *file_path=g_build_filename(bitkeeper->priv->friends_base_path, file_name, NULL);
			if(G_LIKELY(g_file_test(file_path, G_FILE_TEST_IS_DIR)))
			{
				OtbFriend *friend=otb_friend_load_from_directory(file_path);
				if(G_UNLIKELY(friend==NULL))
					ret_val=FALSE;
				else
					bitkeeper->priv->friends=g_slist_prepend(bitkeeper->priv->friends, friend);
			}
			g_free(file_path);
		}
		g_dir_close(friends_dir);
	}
	return ret_val;
}

static void otb_bitkeeper_set_global(OtbBitkeeper *bitkeeper)
{
	otb_global_bitkeeper_lock_write();
	OtbBitkeeper *old_global_bitkeeper=otb_global_bitkeeper;
	otb_global_bitkeeper=(bitkeeper==NULL?NULL:g_object_ref(bitkeeper));
	otb_global_bitkeeper_unlock_write();
	if(old_global_bitkeeper!=NULL)
		g_object_unref(old_global_bitkeeper);
}

gboolean otb_bitkeeper_set(OtbBitkeeper *bitkeeper)
{
	otb_bitkeeper_set_global(bitkeeper);
	return otb_bitkeeper_save();
}

#define otb_bitkeeper_load_proxy_port(bitkeeper)					((bitkeeper->priv->proxy_port=otb_settings_get_config_uint(CONFIG_GROUP, CONFIG_PROXY_PORT, 0))!=0)
#define otb_bitkeeper_load_pad_synchronization_interval(bitkeeper)	((bitkeeper->priv->pad_synchronization_interval=otb_settings_get_config_int64(CONFIG_GROUP, CONFIG_PAD_SYNCHRONIZATION_INTERVAL, -1))!=-1)

gboolean otb_bitkeeper_load(void)
{
	gboolean ret_val=TRUE;
	OtbBitkeeper *bitkeeper=g_object_new(OTB_TYPE_BITKEEPER, NULL);
	if(G_UNLIKELY((bitkeeper->priv->user=otb_user_load())==NULL || !otb_bitkeeper_load_proxy_port(bitkeeper) || !otb_bitkeeper_load_pad_synchronization_interval(bitkeeper) || !otb_bitkeeper_load_friends(bitkeeper)))
		ret_val=FALSE;
	else
		otb_bitkeeper_set_global(bitkeeper);
	g_object_unref(bitkeeper);
	return ret_val;
}

gboolean otb_bitkeeper_save(void)
{
	OtbBitkeeper *bitkeeper=otb_bitkeeper_get_with_ref();
	otb_bitkeeper_lock_read(bitkeeper);
	gboolean ret_val=otb_settings_set_config_uint(CONFIG_GROUP, CONFIG_PROXY_PORT, bitkeeper->priv->proxy_port) && otb_settings_set_config_int64(CONFIG_GROUP, CONFIG_PAD_SYNCHRONIZATION_INTERVAL, bitkeeper->priv->pad_synchronization_interval) && otb_user_save(bitkeeper->priv->user);
	for(GSList *friend_iter=bitkeeper->priv->friends; friend_iter!=NULL; friend_iter=friend_iter->next)
		ret_val=(ret_val && otb_friend_save(friend_iter->data));
	otb_bitkeeper_unlock_read(bitkeeper);
	g_object_unref(bitkeeper);
	return ret_val;
}

void otb_bitkeeper_unload(void)
{
	otb_bitkeeper_set_global(NULL);
}

static GSList *otb_bitkeeper_get_unique_ids_of_friends_no_lock(const OtbBitkeeper *bitkeeper)
{
	GSList *selected_friend_unique_ids=NULL;
	for(const GSList *curr_element=bitkeeper->priv->friends; curr_element!=NULL; curr_element=(const GSList*)g_slist_next(curr_element))
	{
		OtbFriend *friend=OTB_FRIEND(curr_element->data);
		OtbUniqueId *unique_id;
		g_object_get(friend, OTB_FRIEND_PROP_UNIQUE_ID, &unique_id, NULL);
		selected_friend_unique_ids=g_slist_prepend(selected_friend_unique_ids, unique_id);
	}
	return selected_friend_unique_ids;
}

GSList *otb_bitkeeper_get_unique_ids_of_friends(void)
{
	OtbBitkeeper *bitkeeper=otb_bitkeeper_get_with_ref();
	otb_bitkeeper_lock_read(bitkeeper);
	GSList *selected_friend_unique_ids=otb_bitkeeper_get_unique_ids_of_friends_no_lock(bitkeeper);
	otb_bitkeeper_unlock_read(bitkeeper);
	g_object_unref(bitkeeper);
	return selected_friend_unique_ids;
}

static OtbFriend *otb_bitkeeper_get_friend_no_lock_no_ref(const OtbBitkeeper *bitkeeper, const OtbUniqueId *friend_unique_id)
{
	OtbFriend *friend=NULL;
	for(const GSList *curr_element=bitkeeper->priv->friends; curr_element!=NULL && friend==NULL; curr_element=g_slist_next(curr_element))
	{
		OtbFriend *current_friend=OTB_FRIEND(curr_element->data);
		OtbUniqueId *current_friend_unique_id;
		g_object_get(current_friend, OTB_FRIEND_PROP_UNIQUE_ID, &current_friend_unique_id, NULL);
		if(otb_unique_id_compare(friend_unique_id, current_friend_unique_id)==0)
			friend=current_friend;
		otb_unique_id_unref(current_friend_unique_id);
	}
	return friend;
}

OtbFriend *otb_bitkeeper_get_friend(const OtbUniqueId *friend_unique_id)
{
	OtbBitkeeper *bitkeeper=otb_bitkeeper_get_with_ref();
	otb_bitkeeper_lock_read(bitkeeper);
	OtbFriend *friend=otb_bitkeeper_get_friend_no_lock_no_ref(bitkeeper, friend_unique_id);
	if(G_LIKELY(friend!=NULL))
		g_object_ref(friend);
	otb_bitkeeper_unlock_read(bitkeeper);
	g_object_unref(bitkeeper);
	return friend;
}

OtbFriend *otb_bitkeeper_get_friend_who_sent_pad(const OtbUniqueId *pad_unique_id)
{
	OtbBitkeeper *bitkeeper=otb_bitkeeper_get_with_ref();
	OtbFriend *friend=NULL;
	otb_bitkeeper_lock_read(bitkeeper);
	GSList *friend_unique_ids=otb_bitkeeper_get_unique_ids_of_friends_no_lock(bitkeeper);
	for(const GSList *curr_element=friend_unique_ids; friend==NULL && curr_element!=NULL; curr_element=g_slist_next(curr_element))
	{
		OtbFriend *curr_friend=otb_bitkeeper_get_friend_no_lock_no_ref(bitkeeper, (OtbUniqueId*)curr_element->data);
		OtbPadDb *incoming_pad_db;
		g_object_get(curr_friend, OTB_FRIEND_PROP_INCOMING_PAD_DB, &incoming_pad_db, NULL);
		if(G_UNLIKELY(otb_pad_db_get_pad_size(incoming_pad_db, pad_unique_id)>0))
		{
			friend=curr_friend;
			g_object_ref(friend);
		}
		g_object_unref(incoming_pad_db);
	}
	otb_bitkeeper_unlock_read(bitkeeper);
	g_slist_free_full(friend_unique_ids, (GDestroyNotify)otb_unique_id_unref);
	g_object_unref(bitkeeper);
	return friend;
}

static OtbFriend *otb_bitkeeper_import_friend_to_disk(const OtbBitkeeper *bitkeeper, const char *import_string)
{
	char *friend_directory_id_string=otb_unique_id_string_new();
	char *friend_base_path=g_build_filename(bitkeeper->priv->friends_base_path, friend_directory_id_string, NULL);
	OtbFriend *import_friend=otb_friend_import_to_directory(import_string, friend_base_path);
	g_free(friend_base_path);
	g_free(friend_directory_id_string);
	return import_friend;
}

gboolean otb_bitkeeper_import_friend(const char *import_string)
{
	gboolean ret_val=TRUE;
	OtbBitkeeper *bitkeeper=otb_bitkeeper_get_with_ref();
	otb_bitkeeper_lock_write(bitkeeper);
	OtbFriend *import_friend=otb_bitkeeper_import_friend_to_disk(bitkeeper, import_string);
	OtbUniqueId *import_unique_id;
	g_object_get(import_friend, OTB_FRIEND_PROP_UNIQUE_ID, &import_unique_id, NULL);
	OtbFriend *duplicate_friend=otb_bitkeeper_get_friend_no_lock_no_ref(bitkeeper, import_unique_id);
	otb_unique_id_unref(import_unique_id);
	if(G_LIKELY(duplicate_friend==NULL))
		bitkeeper->priv->friends=g_slist_prepend(bitkeeper->priv->friends, import_friend);
	else
	{
		otb_friend_delete(import_friend);
		g_object_unref(duplicate_friend);
		g_object_unref(import_friend);
		ret_val=FALSE;
	}
	otb_bitkeeper_unlock_write(bitkeeper);
	g_object_unref(bitkeeper);
	return ret_val;
}

gboolean otb_bitkeeper_remove_friend(const OtbUniqueId *unique_id)
{
	gboolean ret_val;
	OtbBitkeeper *bitkeeper=otb_bitkeeper_get_with_ref();
	otb_bitkeeper_lock_write(bitkeeper);
	OtbFriend *friend_to_delete=otb_bitkeeper_get_friend_no_lock_no_ref(bitkeeper, unique_id);
	if(G_UNLIKELY(friend_to_delete==NULL))
		ret_val=FALSE;
	else
	{
		ret_val=otb_friend_delete(friend_to_delete);
		bitkeeper->priv->friends=g_slist_remove(bitkeeper->priv->friends, friend_to_delete);
		g_object_unref(friend_to_delete);
	}
	otb_bitkeeper_unlock_write(bitkeeper);
	g_object_unref(bitkeeper);
	return ret_val;
}

static void otb_bitkeeper_friend_message(OtbFriend *friend, GLogLevelFlags log_level, const char *message)
{
	OtbUniqueId *friend_unique_id;
	g_object_get(friend, OTB_FRIEND_IMPORT_UNIQUE_ID, &friend_unique_id, NULL);
	char *friend_unique_id_string=otb_unique_id_to_string(friend_unique_id);
	g_log(G_LOG_DOMAIN, log_level, message, friend_unique_id_string);
	g_free(friend_unique_id_string);
	otb_unique_id_unref(friend_unique_id);
}

static void otb_socket_client_set_proxy_resolver(GSocketClient *socket_client, unsigned int proxy_port)
{
	if(proxy_port>0)
	{
		char proxy_uri[25];
		if(G_UNLIKELY(sprintf(proxy_uri, "socks5://127.0.0.1:%u", proxy_port)<0))
			g_error(_("sprintf() failed in otb_socket_client_set_proxy_resolver() for port %u."), proxy_port);
		GProxyResolver *proxy_resolver=g_simple_proxy_resolver_new(proxy_uri, NULL);
		g_socket_client_set_proxy_resolver(socket_client, proxy_resolver);
		g_object_unref(proxy_resolver);
	}
}

static gboolean otb_friend_synchronize_pads_with_remote(OtbBitkeeper *bitkeeper, OtbFriend *friend, OtbLoopableThread *loopable_thread)
{
	gboolean ret_val=TRUE;
	GSocketClient *socket_client=g_socket_client_new();
	otb_socket_client_set_proxy_resolver(socket_client, bitkeeper->priv->proxy_port);
	char *remote_address;
	unsigned int remote_port;
	g_object_get(friend, OTB_FRIEND_PROP_ADDRESS, &remote_address, OTB_FRIEND_PROP_PORT, &remote_port, NULL);
	GSocketConnection *socket_connect=g_socket_client_connect_to_host(socket_client, remote_address, remote_port, NULL, NULL);
	if(socket_connect!=NULL)
	{
		OtbProtocolContext *protocol_context=otb_protocol_context_create_client(friend, loopable_thread);
		otb_protocol_execute(protocol_context, otb_protocol_client, g_io_stream_get_input_stream(G_IO_STREAM(socket_connect)), g_io_stream_get_output_stream(G_IO_STREAM(socket_connect)), TRUE);
		otb_protocol_context_free(protocol_context);
		g_object_unref(socket_connect);
	}
	else
		ret_val=FALSE;
	g_free(remote_address);
	g_object_unref(socket_client);
}

static void otb_bitkeeper_synchronize_pads_of_friend_from_unique_id(OtbUniqueId *friend_unique_id, OtbLoopableThread *loopable_thread)
{
	if(otb_loopable_thread_continue_looping(loopable_thread))
	{
		OtbBitkeeper *bitkeeper=otb_bitkeeper_get_with_ref();
		OtbFriend *friend=otb_bitkeeper_get_friend_no_lock_no_ref(bitkeeper, friend_unique_id);
		if(friend!=NULL)
		{
			if(!otb_friend_remove_expired_pads(friend))
				otb_bitkeeper_friend_message(friend, G_LOG_LEVEL_WARNING, _("Failed to delete expired pads."));
			if(otb_loopable_thread_continue_looping(loopable_thread) && !otb_friend_synchronize_pads_with_remote(bitkeeper, friend, loopable_thread))
				otb_bitkeeper_friend_message(friend, G_LOG_LEVEL_MESSAGE, _("Failed to synchronize pads with friend."));
		}
		g_object_unref(bitkeeper);
	}
}

static void otb_bitkeeper_synchronize_pads_loopable_thread_func(OtbLoopableThread *loopable_thread)
{
	GSList *unique_ids_of_friends=otb_bitkeeper_get_unique_ids_of_friends();
	g_slist_foreach(unique_ids_of_friends, (GFunc)otb_bitkeeper_synchronize_pads_of_friend_from_unique_id, loopable_thread);
	g_slist_free_full(unique_ids_of_friends, (GDestroyNotify)otb_unique_id_unref);
}

void otb_bitkeeper_launch_tasks(void)
{
	OtbBitkeeper *bitkeeper=otb_bitkeeper_get_with_ref();
	otb_bitkeeper_lock_write(bitkeeper);
	if(bitkeeper->priv->synchronize_pads_thread==NULL)
		bitkeeper->priv->synchronize_pads_thread=otb_loopable_thread_new("SynchoronizePads", otb_bitkeeper_synchronize_pads_loopable_thread_func, NULL, bitkeeper->priv->pad_synchronization_interval);
	otb_bitkeeper_unlock_write(bitkeeper);
	g_object_unref(bitkeeper);
}

void otb_bitkeeper_shutdown_tasks(void)
{
	OtbBitkeeper *bitkeeper=otb_bitkeeper_get_with_ref();
	otb_bitkeeper_lock_write(bitkeeper);
	if(bitkeeper->priv->synchronize_pads_thread!=NULL)
	{
		otb_loopable_thread_stop(bitkeeper->priv->synchronize_pads_thread);
		bitkeeper->priv->synchronize_pads_thread=NULL;
	}
	otb_bitkeeper_unlock_write(bitkeeper);
	g_object_unref(bitkeeper);
}

OtbBitkeeper *otb_bitkeeper_get_with_ref(void)
{
	otb_global_bitkeeper_lock_read();
	OtbBitkeeper *bitkeeper=otb_global_bitkeeper==NULL?NULL:g_object_ref(otb_global_bitkeeper);
	otb_global_bitkeeper_unlock_read();
	return bitkeeper;
}
