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

#include "app.h"
#include "console.h"
#include "demo-user.h"
#include "validation.h"

#include "../../libotb/src/libotb.h"

typedef struct
{
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
} CreateUserContainer;

static CreateUserContainer *create_user_container_from_builder(GtkBuilder *builder)
{
	CreateUserContainer *create_user_container=g_slice_new(CreateUserContainer);
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

#define create_user_container_get_name(create_user_container) 							(gtk_entry_get_text((create_user_container)->name))
#define create_user_container_get_address(create_user_container)						(gtk_entry_get_text((create_user_container)->address))
#define create_user_container_get_passphrase(create_user_container)						(gtk_entry_get_text((create_user_container)->passphrase))
#define create_user_container_get_port(create_user_container)							((unsigned short)gtk_adjustment_get_value((create_user_container)->port))
#define create_user_container_get_key_size(create_user_container)						((int)gtk_adjustment_get_value((create_user_container)->key_size))
#define create_user_container_get_proxy_port(create_user_container)						((unsigned short)gtk_adjustment_get_value((create_user_container)->proxy_port))
#define create_user_container_get_pad_synchronization_interval(create_user_container)	((long long)gtk_adjustment_get_value((create_user_container)->pad_synchronization_interval))

static const gboolean switch_to_console_window(const CreateUserContainer *create_user_container)
{
	otb_demo_console_show_new_window(gtk_window_get_application(create_user_container->window));
	gtk_widget_destroy(GTK_WIDGET(create_user_container->window));
	return FALSE;
}

static const void *create_user_thread(CreateUserContainer *create_user_container)
{
	otb_local_crypto_create_sym_cipher(create_user_container_get_passphrase(create_user_container));
	OtbAsymCipher *asym_cipher=g_object_new(OTB_TYPE_ASYM_CIPHER, OTB_ASYM_CIPHER_PROP_KEY_SIZE, create_user_container_get_key_size(create_user_container), NULL);
	otb_asym_cipher_generate_random_keys(asym_cipher);	// FARE - È ruscito?
	OtbUser *user=g_object_new(otb_user_get_runtime_type(), OTB_USER_PROP_ASYM_CIPHER, asym_cipher, OTB_USER_PROP_ADDRESS, create_user_container_get_address(create_user_container), OTB_USER_PROP_PORT, create_user_container_get_port(create_user_container), NULL);
	otb_demo_user_set_name(OTB_DEMO_USER(user), create_user_container_get_name(create_user_container));
	OtbBitkeeper *bitkeeper=g_object_new(OTB_TYPE_BITKEEPER, OTB_BITKEEPER_PROP_USER, user, OTB_BITKEEPER_PROP_PROXY_PORT, create_user_container_get_proxy_port(create_user_container), OTB_BITKEEPER_PROP_PAD_SYNCHRONIZATION_INTERVAL, create_user_container_get_pad_synchronization_interval(create_user_container), NULL);
	otb_bitkeeper_save(bitkeeper);	// FARE - È ruscito?
	gdk_threads_add_idle((GSourceFunc)switch_to_console_window, create_user_container);
	g_object_unref(bitkeeper);
	g_object_unref(user);
	g_object_unref(asym_cipher);
	return NULL;
}

static void signal_create_user_save_button_clicked(const GtkWidget *widget, CreateUserContainer *create_user_container)
{
	gboolean success=TRUE;
	success&=otb_validation_validate_not_blank(create_user_container->name);
	success&=otb_validation_validate_not_blank(create_user_container->address);
	success&=otb_validation_validate_equal(create_user_container->passphrase, create_user_container->repeatPassphrase);
	if(!success)
	{
		GtkWidget *error_dialog=gtk_message_dialog_new(create_user_container->window, GTK_DIALOG_MODAL, GTK_MESSAGE_WARNING, GTK_BUTTONS_OK, _("Some inputs are invalid and are highlighted in red. Please correct them and try again."));
		gtk_dialog_run(GTK_DIALOG(error_dialog));
		gtk_widget_destroy(error_dialog);
	}
	else
	{
		gtk_widget_show(GTK_WIDGET(create_user_container->workingWindow));
		g_thread_new("CreatingNewUser", (GThreadFunc)create_user_thread, create_user_container);
	}
}

static void signal_create_user_container_free(const GtkWidget *widget, CreateUserContainer *create_user_container)
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
	g_slice_free(CreateUserContainer, create_user_container);
}

static void new_create_user_window_setup(GtkBuilder *builder)
{
	char port_string[6];
	char key_size_string[12];
	char proxy_port_string[6];
	char pad_synchonization_interval_string[21];
	sprintf(port_string, "%hu", OTB_USER_DEFAULT_PORT);
	sprintf(key_size_string, "%hu", OTB_ASYM_CIPHER_DEFAULT_KEY_SIZE);
	sprintf(proxy_port_string, "%hu", OTB_BITKEEPER_DEFAULT_PROXY_PORT);
	sprintf(pad_synchonization_interval_string, "%lli", OTB_BITKEEPER_DEFAULT_PAD_SYNCHRONIZATION_INTERVAL);
	gtk_entry_set_text(GTK_ENTRY(gtk_builder_get_object(builder, "portValue")), port_string);
	gtk_entry_set_text(GTK_ENTRY(gtk_builder_get_object(builder, "keySizeValue")), key_size_string);
	gtk_entry_set_text(GTK_ENTRY(gtk_builder_get_object(builder, "proxyPortValue")), proxy_port_string);
	gtk_entry_set_text(GTK_ENTRY(gtk_builder_get_object(builder, "padSynchronizationIntervalValue")), pad_synchonization_interval_string);
	CreateUserContainer *create_user_container=create_user_container_from_builder(builder);
	g_signal_connect(GTK_WIDGET(gtk_builder_get_object(builder, "saveButton")), "clicked", G_CALLBACK(signal_create_user_save_button_clicked), create_user_container);
	g_signal_connect(GTK_WIDGET(gtk_builder_get_object(builder, "window")), "destroy", G_CALLBACK(signal_create_user_container_free), create_user_container);
}

void otb_demo_create_user_show_new_window(GtkApplication *application)
{
	otb_demo_app_create_window("create-user.ui", new_create_user_window_setup, application);
}
