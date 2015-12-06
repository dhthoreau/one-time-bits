/**
 * Copyright © 2015 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <gtk/gtk.h>

#include "create-user.h"
#include "otb-demo-app.h"

#include "../../libotb/src/libotb.h"

struct _OtbDemoCreateUserContainer
{
	int ref_count;
	GtkEntry *name;
	GtkEntry *address;
	GtkEntry *port;
	GtkEntry *key_size;
	GtkEntry *proxy_port;
	GtkEntry *pad_synchronization_interval;
};

OtbDemoCreateUserContainer *otb_demo_create_user_container_from_builder(GtkBuilder *builder)
{
	OtbDemoCreateUserContainer *create_user_container=g_slice_new(OtbDemoCreateUserContainer);
	create_user_container->ref_count=1;
	create_user_container->name=g_object_ref(GTK_ENTRY(gtk_builder_get_object(builder, "nameValue")));
	create_user_container->address=g_object_ref(GTK_ENTRY(gtk_builder_get_object(builder, "addressValue")));
	create_user_container->port=g_object_ref(GTK_ENTRY(gtk_builder_get_object(builder, "portValue")));
	create_user_container->key_size=g_object_ref(GTK_ENTRY(gtk_builder_get_object(builder, "keySizeValue")));
	create_user_container->proxy_port=g_object_ref(GTK_ENTRY(gtk_builder_get_object(builder, "proxyPortValue")));
	create_user_container->pad_synchronization_interval=g_object_ref(GTK_ENTRY(gtk_builder_get_object(builder, "padSynchronizationIntervalValue")));
	return create_user_container;
}

const char *otb_demo_create_user_container_get_name(const OtbDemoCreateUserContainer *create_user_container)
{
	return gtk_entry_get_text(create_user_container->name);
}

const char *otb_demo_create_user_container_get_address(const OtbDemoCreateUserContainer *create_user_container)
{
	return gtk_entry_get_text(create_user_container->address);
}

unsigned short otb_demo_create_user_container_get_user_port(const OtbDemoCreateUserContainer *create_user_container)
{
	return (unsigned short)strtoul(gtk_entry_get_text(create_user_container->port), NULL, 0);
}

int otb_demo_create_user_container_get_key_size(const OtbDemoCreateUserContainer *create_user_container)
{
	return atoi(gtk_entry_get_text(create_user_container->key_size));
}

unsigned short otb_demo_create_user_container_get_proxy_port(const OtbDemoCreateUserContainer *create_user_container)
{
	return (unsigned short)strtoul(gtk_entry_get_text(create_user_container->proxy_port), NULL, 0);
}

long long otb_demo_create_user_container_get_pad_synchronization_interval(const OtbDemoCreateUserContainer *create_user_container)
{
	return strtoll(gtk_entry_get_text(create_user_container->pad_synchronization_interval), NULL, 0);
}

OtbDemoCreateUserContainer *otb_demo_create_user_container_ref(OtbDemoCreateUserContainer *create_user_container)
{
	g_return_val_if_fail(create_user_container!=NULL, NULL);
	g_atomic_int_inc(&create_user_container->ref_count);
	return create_user_container;
}

void otb_demo_create_user_container_unref(OtbDemoCreateUserContainer *create_user_container)
{
	if(create_user_container!=NULL && g_atomic_int_dec_and_test(&create_user_container->ref_count))
	{
		g_object_unref(create_user_container->name);
		g_object_unref(create_user_container->address);
		g_object_unref(create_user_container->port);
		g_object_unref(create_user_container->key_size);
		g_object_unref(create_user_container->proxy_port);
		g_object_unref(create_user_container->pad_synchronization_interval);
		g_slice_free(OtbDemoCreateUserContainer, create_user_container);
	}
}

static void signal_create_user_create_bitkeeper(GtkWidget *widget, OtbDemoCreateUserContainer *create_user_container)
{
	otb_bitkeeper_create(otb_demo_create_user_container_get_proxy_port(create_user_container), otb_demo_create_user_container_get_pad_synchronization_interval(create_user_container), otb_demo_create_user_container_get_address(create_user_container), otb_demo_create_user_container_get_user_port(create_user_container), otb_demo_create_user_container_get_key_size(create_user_container));
	gtk_main_quit();
}

static void new_create_user_window_setup(GtkBuilder *builder)
{
	char user_port_string[6];
	char user_key_size_string[12];
	char proxy_port_string[6];
	char pad_synchonization_interval_string[21];
	sprintf(user_port_string, "%hu", OTB_BITKEEPER_DEFAULT_USER_PORT);
	sprintf(user_key_size_string, "%hu", OTB_BITKEEPER_DEFAULT_USER_KEY_SIZE);
	sprintf(proxy_port_string, "%hu", OTB_BITKEEPER_DEFAULT_PROXY_PORT);
	sprintf(pad_synchonization_interval_string, "%lli", OTB_BITKEEPER_DEFAULT_PAD_SYNCHRONIZATION_INTERVAL);
	gtk_entry_set_text(GTK_ENTRY(gtk_builder_get_object(builder, "portValue")), user_port_string);
	gtk_entry_set_text(GTK_ENTRY(gtk_builder_get_object(builder, "keySizeValue")), user_key_size_string);
	gtk_entry_set_text(GTK_ENTRY(gtk_builder_get_object(builder, "proxyPortValue")), proxy_port_string);
	gtk_entry_set_text(GTK_ENTRY(gtk_builder_get_object(builder, "padSynchronizationIntervalValue")), pad_synchonization_interval_string);
	g_signal_connect(GTK_WIDGET(gtk_builder_get_object(builder, "saveButton")), "clicked", G_CALLBACK(signal_create_user_create_bitkeeper), otb_demo_create_user_container_from_builder(builder));
}

void otb_demo_create_user_show_new_window(GtkApplication *application)
{
	otb_demo_app_create_window("create-user.ui", new_create_user_window_setup, application);
}
