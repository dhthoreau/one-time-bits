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
#include "edit-user.h"

void otb_demo_app_create_window(const char *file_name, const WindowCreationSetupCallback setup_callback, GtkApplication *application)
{
	char *file_path=g_build_filename(DATA_DIRECTORY, file_name, NULL);
	GtkBuilder *builder=gtk_builder_new_from_file(file_path);
	gtk_builder_connect_signals(builder, NULL);
	GtkWindow *window=GTK_WINDOW(gtk_builder_get_object(builder, "window"));
	if(setup_callback!=NULL)
		setup_callback(builder);
	g_object_unref(builder);
	gtk_application_add_window(application, window);
	gtk_widget_show(GTK_WIDGET(window));
	g_free(file_path);
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
