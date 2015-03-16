/**
 * Copyright © 2014 the OTB team
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
static void otb_bitkeeper_get_property(GObject *object, unsigned int prop_id, GValue *value, GParamSpec *pspec);

struct _OtbBitkeeperPrivate
{
	GRWLock lock;
	OtbUser *user;
	unsigned short proxy_port;
	long long pad_synchronization_interval;
	GSList *friends;
	char *friends_base_path;
	OtbLoopableThread *synchronize_pads_thread;
};

#define DEFAULT_PROXY_PORT						9050
#define DEFAULT_PAD_SYNCHRONIZATION_INTERVAL	10000000

static void otb_bitkeeper_class_init(OtbBitkeeperClass *klass)
{
	GObjectClass *object_class=G_OBJECT_CLASS(klass);
	object_class->dispose=otb_bitkeeper_dispose;
	object_class->finalize=otb_bitkeeper_finalize;
	object_class->get_property=otb_bitkeeper_get_property;
	g_object_class_install_property(object_class, PROP_USER, g_param_spec_object(OTB_BITKEEPER_PROP_USER, _("User"), _("The user who is using the application"), OTB_TYPE_USER, G_PARAM_READABLE));
	g_object_class_install_property(object_class, PROP_PROXY_PORT, g_param_spec_uint(OTB_BITKEEPER_PROP_PROXY_PORT, _("Proxy port"), _("The port for the local proxy, preferably TOR"), 1, G_MAXUSHORT, DEFAULT_PROXY_PORT, G_PARAM_READABLE));
	g_object_class_install_property(object_class, PROP_PAD_SYNCHRONIZATION_INTERVAL, g_param_spec_int64(OTB_BITKEEPER_PROP_PAD_SYNCHRONIZATION_INTERVAL, _("Pad synchronization interval"), _("How often pads should be synchronized, measured in microseconds"), 1, G_MAXINT64, DEFAULT_PAD_SYNCHRONIZATION_INTERVAL, G_PARAM_READABLE));
	g_type_class_add_private(klass, sizeof(OtbBitkeeperPrivate));
}

static void otb_bitkeeper_init(OtbBitkeeper *bitkeeper)
{
	bitkeeper->priv=G_TYPE_INSTANCE_GET_PRIVATE(bitkeeper, OTB_TYPE_BITKEEPER, OtbBitkeeperPrivate);
	g_rw_lock_init(&bitkeeper->priv->lock);
	bitkeeper->priv->user=NULL;
	bitkeeper->priv->proxy_port=DEFAULT_PROXY_PORT;
	bitkeeper->priv->pad_synchronization_interval=DEFAULT_PAD_SYNCHRONIZATION_INTERVAL;
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
			g_value_set_uint(value, (unsigned int)bitkeeper->priv->proxy_port);
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

static gboolean otb_bitkeeper_load_friends(OtbBitkeeper *bitkeeper)
{
	gboolean ret_val=TRUE;
	GDir *friends_dir=NULL;
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

OtbBitkeeper *otb_bitkeeper_load()
{
	OtbBitkeeper *bitkeeper=g_object_new(OTB_TYPE_BITKEEPER, NULL);
	if(G_UNLIKELY((bitkeeper->priv->user=otb_user_load())==NULL || !otb_bitkeeper_load_friends(bitkeeper)))
	{
		g_object_unref(bitkeeper);
		bitkeeper=NULL;
	}
	else
	{
		bitkeeper->priv->proxy_port=(unsigned short)otb_settings_get_config_uint(CONFIG_GROUP, CONFIG_PROXY_PORT, DEFAULT_PROXY_PORT);
		bitkeeper->priv->pad_synchronization_interval=otb_settings_get_config_int64(CONFIG_GROUP, CONFIG_PAD_SYNCHRONIZATION_INTERVAL, DEFAULT_PAD_SYNCHRONIZATION_INTERVAL);
	}
	return bitkeeper;
}

gboolean otb_bitkeeper_set_proxy_port(const OtbBitkeeper *bitkeeper, unsigned short proxy_port)
{
	otb_bitkeeper_lock_write(bitkeeper);
	bitkeeper->priv->proxy_port=proxy_port;
	gboolean ret_val=otb_settings_set_config_uint(CONFIG_GROUP, CONFIG_PROXY_PORT, (int)bitkeeper->priv->proxy_port);
	otb_bitkeeper_unlock_write(bitkeeper);
	return ret_val;
}

gboolean otb_bitkeeper_set_pad_synchronization_interval(const OtbBitkeeper *bitkeeper, long long pad_synchronization_interval)
{
	otb_bitkeeper_lock_write(bitkeeper);
	bitkeeper->priv->pad_synchronization_interval=pad_synchronization_interval;
	gboolean ret_val=otb_settings_set_config_int64(CONFIG_GROUP, CONFIG_PAD_SYNCHRONIZATION_INTERVAL, bitkeeper->priv->pad_synchronization_interval);
	otb_bitkeeper_unlock_write(bitkeeper);
	return ret_val;
}

static OtbFriend *otb_bitkeeper_get_friend_no_lock_no_ref(const OtbBitkeeper *bitkeeper, const OtbUniqueId *unique_id)
{
	OtbFriend *friend=NULL;
	for(const GSList *curr_element=bitkeeper->priv->friends; curr_element!=NULL && friend==NULL; curr_element=g_slist_next(curr_element))
	{
		OtbFriend *current_friend=OTB_FRIEND(curr_element->data);
		OtbUniqueId *current_unique_id=NULL;
		g_object_get(current_friend, OTB_FRIEND_PROP_UNIQUE_ID, &current_unique_id, NULL);
		if(otb_unique_id_compare(unique_id, current_unique_id)==0)
			friend=current_friend;
		otb_unique_id_unref(current_unique_id);
	}
	return friend;
}

OtbFriend *otb_bitkeeper_get_friend(const OtbBitkeeper *bitkeeper, const OtbUniqueId *unique_id)
{
	otb_bitkeeper_lock_read(bitkeeper);
	OtbFriend *friend=otb_bitkeeper_get_friend_no_lock_no_ref(bitkeeper, unique_id);
	if(G_LIKELY(friend!=NULL))
		g_object_ref(friend);
	otb_bitkeeper_unlock_read(bitkeeper);
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

gboolean otb_bitkeeper_import_friend(OtbBitkeeper *bitkeeper, const char *import_string)
{
	gboolean ret_val=TRUE;
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
	return ret_val;
}

gboolean otb_bitkeeper_remove_friend(OtbBitkeeper *bitkeeper, const OtbUniqueId *unique_id)
{
	gboolean ret_val;
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
	return ret_val;
}

GSList *otb_bitkeeper_get_unique_ids_of_friends(const OtbBitkeeper *bitkeeper)
{
	GSList *selected_friend_unique_ids=NULL;
	otb_bitkeeper_lock_read(bitkeeper);
	for(const GSList *curr_element=bitkeeper->priv->friends; curr_element!=NULL; curr_element=(const GSList*)g_slist_next(curr_element))
	{
		OtbFriend *friend=OTB_FRIEND(curr_element->data);
		OtbUniqueId *unique_id=NULL;
		g_object_get(friend, OTB_FRIEND_PROP_UNIQUE_ID, &unique_id, NULL);
		selected_friend_unique_ids=g_slist_prepend(selected_friend_unique_ids, unique_id);
	}
	otb_bitkeeper_unlock_read(bitkeeper);
	return selected_friend_unique_ids;
}

static void otb_bitkeeper_friend_message(OtbFriend *friend, GLogLevelFlags log_level, const char *message)
{
	OtbUniqueId *friend_unique_id=NULL;
	g_object_get(friend, OTB_FRIEND_IMPORT_UNIQUE_ID, &friend_unique_id, NULL);
	char *friend_unique_id_string=otb_unique_id_to_string(friend_unique_id);
	g_log(G_LOG_DOMAIN, log_level, message, friend_unique_id_string);
	g_free(friend_unique_id_string);
	otb_unique_id_unref(friend_unique_id);
}

static void otb_socket_client_set_proxy_resolver(GSocketClient *socket_client, unsigned short proxy_port)
{
	if(proxy_port>0)
	{
		char proxy_uri[25];
		if(G_UNLIKELY(sprintf(proxy_uri, "socks5://127.0.0.1:%u", (unsigned int)proxy_port)<0))
			g_error(_("sprintf() failed in otb_socket_client_set_proxy_resolver() for port %u."), (unsigned int)proxy_port);
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
	char *remote_address=NULL;
	unsigned int remote_port=0;
	g_object_get(friend, OTB_FRIEND_PROP_ADDRESS, &remote_address, OTB_FRIEND_PROP_PORT, &remote_port, NULL);
	GSocketConnection *socket_connect=g_socket_client_connect_to_host(socket_client, remote_address, (unsigned short)remote_port, NULL, NULL);
	if(socket_connect!=NULL)
	{
		OtbProtocolContext *protocol_context=otb_protocol_context_create_client(bitkeeper, friend, loopable_thread);
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
		OtbBitkeeper *bitkeeper=otb_loopable_thread_data(loopable_thread);
		OtbFriend *friend=otb_bitkeeper_get_friend(bitkeeper, friend_unique_id);
		if(friend!=NULL)
		{
			if(!otb_friend_remove_expired_pads(friend))
				otb_bitkeeper_friend_message(friend, G_LOG_LEVEL_WARNING, _("Failed to delete expired pads."));
			otb_loopable_thread_yield(loopable_thread, 1);
			if(otb_loopable_thread_continue_looping(loopable_thread) && !otb_friend_synchronize_pads_with_remote(bitkeeper, friend, loopable_thread))
				otb_bitkeeper_friend_message(friend, G_LOG_LEVEL_MESSAGE, _("Failed to synchronize pads with friend."));
			otb_loopable_thread_yield(loopable_thread, 1);
			g_object_unref(friend);
		}
		otb_loopable_thread_yield(loopable_thread, 1);
	}
}

static void otb_bitkeeper_synchronize_pads_loopable_thread_func(OtbLoopableThread *loopable_thread)
{
	OtbBitkeeper *bitkeeper=otb_loopable_thread_data(loopable_thread);
	otb_bitkeeper_lock_read(bitkeeper);
	GSList *unique_ids_of_friends=otb_bitkeeper_get_unique_ids_of_friends(bitkeeper);
	otb_bitkeeper_unlock_read(bitkeeper);
	g_slist_foreach(unique_ids_of_friends, (GFunc)otb_bitkeeper_synchronize_pads_of_friend_from_unique_id, loopable_thread);
	g_slist_free_full(unique_ids_of_friends, (GDestroyNotify)otb_unique_id_unref);
}

void otb_bitkeeper_launch_tasks(OtbBitkeeper *bitkeeper)
{
	otb_bitkeeper_lock_write(bitkeeper);
	if(bitkeeper->priv->synchronize_pads_thread==NULL)
		bitkeeper->priv->synchronize_pads_thread=otb_loopable_thread_new("SynchoronizePads", otb_bitkeeper_synchronize_pads_loopable_thread_func, bitkeeper, bitkeeper->priv->pad_synchronization_interval);
	otb_bitkeeper_unlock_write(bitkeeper);
}

void otb_bitkeeper_shutdown_tasks(OtbBitkeeper *bitkeeper)
{
	otb_bitkeeper_lock_write(bitkeeper);
	if(bitkeeper->priv->synchronize_pads_thread!=NULL)
	{
		otb_loopable_thread_stop(bitkeeper->priv->synchronize_pads_thread);
		bitkeeper->priv->synchronize_pads_thread=NULL;
	}
	otb_bitkeeper_unlock_write(bitkeeper);
}
