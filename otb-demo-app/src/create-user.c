/**
 * Copyright © 2015 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <gtk/gtk.h>
#include <glib/gi18n.h>

#include "create-user.h"
#include "otb-demo-app.h"
#include "validation.h"

#include "../../libotb/src/libotb.h"

struct _OtbDemoCreateUserContainer
{
	int ref_count;
	GtkWindow *window;
	GtkWindow *workingWindow;
	GtkEntry *name;
	GtkEntry *address;
	GtkEntry *passphrase;
	GtkEntry *repeatPassphrase;
	GtkAdjustment *port;
	GtkAdjustment *key_size;
	GtkAdjustment *proxy_port;
	GtkAdjustment *pad_synchronization_interval;
};

OtbDemoCreateUserContainer *otb_demo_create_user_container_from_builder(GtkBuilder *builder)
{
	OtbDemoCreateUserContainer *create_user_container=g_slice_new(OtbDemoCreateUserContainer);
	create_user_container->ref_count=1;
	create_user_container->window=g_object_ref(GTK_WINDOW(gtk_builder_get_object(builder, "window")));
	create_user_container->workingWindow=g_object_ref(GTK_WINDOW(gtk_builder_get_object(builder, "workingWindow")));
	create_user_container->name=g_object_ref(GTK_ENTRY(gtk_builder_get_object(builder, "nameValue")));
	create_user_container->address=g_object_ref(GTK_ENTRY(gtk_builder_get_object(builder, "addressValue")));
	create_user_container->passphrase=g_object_ref(GTK_ENTRY(gtk_builder_get_object(builder, "passphraseValue")));
	create_user_container->repeatPassphrase=g_object_ref(GTK_ENTRY(gtk_builder_get_object(builder, "repeatPassphraseValue")));
	create_user_container->port=g_object_ref(GTK_ADJUSTMENT(gtk_builder_get_object(builder, "portRange")));
	create_user_container->key_size=g_object_ref(GTK_ADJUSTMENT(gtk_builder_get_object(builder, "keySizeRange")));
	create_user_container->proxy_port=g_object_ref(GTK_ADJUSTMENT(gtk_builder_get_object(builder, "proxyPortRange")));
	create_user_container->pad_synchronization_interval=g_object_ref(GTK_ADJUSTMENT(gtk_builder_get_object(builder, "padSynchronizationIntervalRange")));
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

const char *otb_demo_create_user_container_get_passphrase(const OtbDemoCreateUserContainer *create_user_container)
{
	return gtk_entry_get_text(create_user_container->passphrase);
}

unsigned short otb_demo_create_user_container_get_user_port(const OtbDemoCreateUserContainer *create_user_container)
{
	return (unsigned short)gtk_adjustment_get_value(create_user_container->port);
}

int otb_demo_create_user_container_get_key_size(const OtbDemoCreateUserContainer *create_user_container)
{
	return (int)gtk_adjustment_get_value(create_user_container->key_size);
}

unsigned short otb_demo_create_user_container_get_proxy_port(const OtbDemoCreateUserContainer *create_user_container)
{
	return (unsigned short)gtk_adjustment_get_value(create_user_container->proxy_port);
}

long long otb_demo_create_user_container_get_pad_synchronization_interval(const OtbDemoCreateUserContainer *create_user_container)
{
	return (long long)gtk_adjustment_get_value(create_user_container->pad_synchronization_interval);
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
		g_object_unref(create_user_container->window);
		g_object_unref(create_user_container->workingWindow);
		g_object_unref(create_user_container->name);
		g_object_unref(create_user_container->address);
		g_object_unref(create_user_container->passphrase);
		g_object_unref(create_user_container->repeatPassphrase);
		g_object_unref(create_user_container->port);
		g_object_unref(create_user_container->key_size);
		g_object_unref(create_user_container->proxy_port);
		g_object_unref(create_user_container->pad_synchronization_interval);
		g_slice_free(OtbDemoCreateUserContainer, create_user_container);
	}
}

static void *create_user(OtbDemoCreateUserContainer *create_user_container)
{
	otb_local_crypto_create_sym_cipher(otb_demo_create_user_container_get_passphrase(create_user_container));
	otb_bitkeeper_create(otb_demo_create_user_container_get_proxy_port(create_user_container), otb_demo_create_user_container_get_pad_synchronization_interval(create_user_container), otb_demo_create_user_container_get_address(create_user_container), otb_demo_create_user_container_get_user_port(create_user_container), otb_demo_create_user_container_get_key_size(create_user_container));
	gtk_widget_destroy(GTK_WIDGET(create_user_container->window));
	g_object_unref(create_user_container);
}

static void signal_create_user_create_button_clicked(GtkWidget *widget, OtbDemoCreateUserContainer *create_user_container)
{
	gboolean success=TRUE;
	success&=otb_validate_not_blank(create_user_container->name);
	success&=otb_validate_not_blank(create_user_container->address);
	success&=otb_validate_equal(create_user_container->passphrase, create_user_container->repeatPassphrase);
	if(success)
	{
		gtk_widget_show(GTK_WIDGET(create_user_container->workingWindow));
		g_thread_new("CreatingNewUser", (GThreadFunc)create_user, create_user_container);
	}
	else
	{
		GtkWidget *error_dialog=gtk_message_dialog_new(create_user_container->window, GTK_DIALOG_MODAL, GTK_MESSAGE_WARNING, GTK_BUTTONS_OK, _("Some inputs are invalid and are highlighted in red. Please correct them and try again."));
		gtk_dialog_run(GTK_DIALOG(error_dialog));
		gtk_widget_destroy(error_dialog);
	}
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
	g_signal_connect(GTK_WIDGET(gtk_builder_get_object(builder, "saveButton")), "clicked", G_CALLBACK(signal_create_user_create_button_clicked), otb_demo_create_user_container_from_builder(builder));
}

void otb_demo_create_user_show_new_window(GtkApplication *application)
{
	otb_demo_app_create_window("create-user.ui", new_create_user_window_setup, application);
}
