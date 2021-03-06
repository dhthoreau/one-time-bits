/**
 * Copyright © 2017 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <gtk/gtk.h>
#include <glib/gi18n.h>

#include "app.h"
#include "demo-user.h"
#include "dialog.h"
#include "validation.h"

#include "../../libotb/src/libotb.h"

#define EDIT_USER_WINDOW	"editUserWindow"

typedef struct
{
	GtkWindow *window;
	GtkWindow *workingWindow;
	GtkEntry *name;
	GtkEntry *address;
	GtkAdjustment *port;
	GtkAdjustment *proxy_port;
	GtkAdjustment *pad_synchronization_interval;
} EditUserContainer;

static EditUserContainer *edit_user_container_from_builder(GtkBuilder *builder)
{
	EditUserContainer *edit_user_container=g_slice_new(EditUserContainer);
	edit_user_container->window=g_object_ref(GTK_WINDOW(gtk_builder_get_object(builder, EDIT_USER_WINDOW)));
	edit_user_container->workingWindow=g_object_ref(GTK_WINDOW(gtk_builder_get_object(builder, "workingWindow")));
	edit_user_container->name=g_object_ref(GTK_ENTRY(gtk_builder_get_object(builder, "nameValue")));
	edit_user_container->address=g_object_ref(GTK_ENTRY(gtk_builder_get_object(builder, "addressValue")));
	edit_user_container->port=g_object_ref(GTK_ADJUSTMENT(gtk_builder_get_object(builder, "portRange")));
	edit_user_container->proxy_port=g_object_ref(GTK_ADJUSTMENT(gtk_builder_get_object(builder, "proxyPortRange")));
	edit_user_container->pad_synchronization_interval=g_object_ref(GTK_ADJUSTMENT(gtk_builder_get_object(builder, "padSynchronizationIntervalRange")));
	return edit_user_container;
}

#define edit_user_container_get_name(edit_user_container) 							(gtk_entry_get_text((edit_user_container)->name))
#define edit_user_container_get_address(edit_user_container)						(gtk_entry_get_text((edit_user_container)->address))
#define edit_user_container_get_port(edit_user_container)							((unsigned int)gtk_adjustment_get_value((edit_user_container)->port))
#define edit_user_container_get_proxy_port(edit_user_container)						((unsigned int)gtk_adjustment_get_value((edit_user_container)->proxy_port))
#define edit_user_container_get_pad_synchronization_interval(edit_user_container)	((long long)gtk_adjustment_get_value((edit_user_container)->pad_synchronization_interval))

static gboolean save_edit_user_information(EditUserContainer *edit_user_container)
{
	OtbBitkeeper *bitkeeper=otb_bitkeeper_get_with_ref();
	g_object_set(bitkeeper, OTB_BITKEEPER_PROP_PROXY_PORT, edit_user_container_get_proxy_port(edit_user_container), OTB_BITKEEPER_PROP_PAD_SYNCHRONIZATION_INTERVAL, edit_user_container_get_pad_synchronization_interval(edit_user_container), NULL);
	OtbUser *user;
	g_object_get(bitkeeper, OTB_BITKEEPER_PROP_USER, &user, NULL);
	g_object_set(OTB_DEMO_USER(user), OTB_DEMO_USER_PROP_NAME, edit_user_container_get_name(edit_user_container), OTB_USER_PROP_ADDRESS, edit_user_container_get_address(edit_user_container), OTB_USER_PROP_PORT, edit_user_container_get_port(edit_user_container), NULL);
	gboolean ret_val=otb_bitkeeper_save();
	if(G_UNLIKELY(!ret_val))
		otb_demo_error_dialog(edit_user_container->window, _("There was a failure saving your profile to disk."));
	g_object_unref(user);
	g_object_unref(bitkeeper);
	return ret_val;
}

static const void *edit_user_thread(EditUserContainer *edit_user_container)
{
	if(G_LIKELY(save_edit_user_information(edit_user_container)))
		gdk_threads_add_idle((GSourceFunc)gtk_widget_destroy, edit_user_container->window);
	return NULL;
}

static void signal_edit_user_save_button_clicked(const GtkWidget *widget, EditUserContainer *edit_user_container)
{
	gboolean success=TRUE;
	success&=otb_validation_validate_not_blank(edit_user_container->name);
	success&=otb_validation_validate_not_blank(edit_user_container->address);
	if(!success)
		otb_demo_error_dialog(edit_user_container->window, _("Some inputs are invalid and are highlighted in red. Please correct them and try again."));
	else
	{
		gtk_widget_show(GTK_WIDGET(edit_user_container->workingWindow));
		g_thread_new("EditingNewUser", (GThreadFunc)edit_user_thread, edit_user_container);
	}
}

static void signal_edit_user_container_free(const GtkWidget *widget, EditUserContainer *edit_user_container)
{
	g_object_unref(edit_user_container->window);
	g_object_unref(edit_user_container->workingWindow);
	g_object_unref(edit_user_container->name);
	g_object_unref(edit_user_container->address);
	g_object_unref(edit_user_container->port);
	g_object_unref(edit_user_container->proxy_port);
	g_object_unref(edit_user_container->pad_synchronization_interval);
	g_slice_free(EditUserContainer, edit_user_container);
}

static void new_edit_user_window_setup(GtkBuilder *builder)
{
	OtbBitkeeper *bitkeeper=otb_bitkeeper_get_with_ref();
	OtbUser *user;
	unsigned int proxy_port;
	long long pad_synchronization_interval;
	g_object_get(bitkeeper, OTB_BITKEEPER_PROP_USER, &user, OTB_BITKEEPER_PROP_PROXY_PORT, &proxy_port, OTB_BITKEEPER_PROP_PAD_SYNCHRONIZATION_INTERVAL, &pad_synchronization_interval, NULL);
	char *name;
	char *address;
	unsigned int port;
	g_object_get(OTB_DEMO_USER(user), OTB_DEMO_USER_PROP_NAME, &name, OTB_USER_PROP_ADDRESS, &address, OTB_USER_PROP_PORT, &port, NULL);
	char port_string[6];
	char proxy_port_string[6];
	char pad_synchonization_interval_string[21];
	sprintf(port_string, "%hu", port);
	sprintf(proxy_port_string, "%hu", proxy_port);
	sprintf(pad_synchonization_interval_string, "%lli", pad_synchronization_interval);
	gtk_entry_set_text(GTK_ENTRY(gtk_builder_get_object(builder, "nameValue")), name);
	gtk_entry_set_text(GTK_ENTRY(gtk_builder_get_object(builder, "addressValue")), address);
	gtk_entry_set_text(GTK_ENTRY(gtk_builder_get_object(builder, "portValue")), port_string);
	gtk_entry_set_text(GTK_ENTRY(gtk_builder_get_object(builder, "proxyPortValue")), proxy_port_string);
	gtk_entry_set_text(GTK_ENTRY(gtk_builder_get_object(builder, "padSynchronizationIntervalValue")), pad_synchonization_interval_string);
	EditUserContainer *edit_user_container=edit_user_container_from_builder(builder);
	g_signal_connect(GTK_WIDGET(gtk_builder_get_object(builder, "saveButton")), "clicked", G_CALLBACK(signal_edit_user_save_button_clicked), edit_user_container);
	g_signal_connect(GTK_WIDGET(gtk_builder_get_object(builder, EDIT_USER_WINDOW)), "destroy", G_CALLBACK(signal_edit_user_container_free), edit_user_container);
	g_free(address);
	g_free(name);
	g_object_unref(user);
}

G_MODULE_EXPORT
void otb_demo_app_signal_pop_edit_user(GtkWidget *widget, void *callback_data)
{
	GtkWindow *window=GTK_WINDOW(gtk_widget_get_toplevel(widget));
	otb_demo_app_create_transient_window("edit-user.ui", EDIT_USER_WINDOW, gtk_window_get_application(window), new_edit_user_window_setup, window);
}
