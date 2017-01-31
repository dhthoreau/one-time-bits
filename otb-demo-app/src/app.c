/**
 * Copyright © 2015 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <gtk/gtk.h>

#include "app.h"

GtkWindow *otb_demo_app_create_hidden_transient_window(const char *file_name, const char *window_name, GtkApplication *application, const WindowCreationSetupCallback setup_callback, GtkWindow *parent_for_transient_window)
{
	char *file_path=g_build_filename(DATA_DIRECTORY, file_name, NULL);
	GtkBuilder *builder=gtk_builder_new_from_file(file_path);
	gtk_builder_connect_signals(builder, NULL);
	GtkWindow *window=GTK_WINDOW(g_object_ref(gtk_builder_get_object(builder, window_name)));
	if(setup_callback!=NULL)
		setup_callback(builder);
	g_object_unref(builder);
	if(parent_for_transient_window!=NULL)
		gtk_window_set_transient_for(window, parent_for_transient_window);
	gtk_application_add_window(application, window);
	g_free(file_path);
	return window;
}

void otb_demo_app_create_transient_window(const char *file_name, const char *window_name, GtkApplication *application, const WindowCreationSetupCallback setup_callback, GtkWindow *parent_for_transient_window)
{
	GtkWindow *window=otb_demo_app_create_hidden_transient_window(file_name, window_name, application, setup_callback, parent_for_transient_window);
	gtk_widget_show(GTK_WIDGET(window));
	g_object_unref(window);
}

void otb_demo_app_create_window(const char *file_name, const char *window_name, GtkApplication *application, const WindowCreationSetupCallback setup_callback)
{
	otb_demo_app_create_transient_window(file_name, window_name, application, setup_callback, NULL);
}

G_MODULE_EXPORT
void otb_demo_app_signal_close_window(GtkWidget *widget, void *callback_data)
{
	gtk_window_close(GTK_WINDOW(gtk_widget_get_toplevel(widget)));
}

G_MODULE_EXPORT
void otb_demo_app_signal_decrypt_file(const GtkWidget *widget, GtkWindow *window)
{
}

G_MODULE_EXPORT
void otb_demo_app_signal_encrypt_file(const GtkWidget *widget, GtkWindow *window)
{
}

G_MODULE_EXPORT
void otb_demo_app_signal_edit_profile(const GtkWidget *widget, GtkWindow *window)
{
}

G_MODULE_EXPORT
void otb_demo_app_signal_manage_friends(const GtkWidget *widget, GtkWindow *window)
{
}
