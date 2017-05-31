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

#include "dialog.h"

#include "../../libotb/src/libotb.h"

static void add_filter_to_chooser_dialog(GtkWidget *file_chooser_dialog, const char *name, const char *mask)
{
	GtkFileFilter *filter=gtk_file_filter_new();
	gtk_file_filter_set_name(filter, name);
	gtk_file_filter_add_pattern(filter, mask);
	gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(file_chooser_dialog), filter);
}

static GtkWidget *create_file_chooser_dialog_for_export_user(GtkWidget *widget)
{
	GtkWidget *file_chooser_dialog=gtk_file_chooser_dialog_new("Export profile", GTK_WINDOW(gtk_widget_get_toplevel(widget)), GTK_FILE_CHOOSER_ACTION_SAVE, _("_Cancel"), GTK_RESPONSE_CANCEL, _("_Export"), GTK_RESPONSE_ACCEPT, NULL);
	gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(file_chooser_dialog), TRUE);
	gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(file_chooser_dialog), "Untitled.otbu");
	add_filter_to_chooser_dialog(file_chooser_dialog, "OTB user files", "*.otbu");
	add_filter_to_chooser_dialog(file_chooser_dialog, "All files", "*");
	return file_chooser_dialog;
}

static gboolean export_user_to_dialog_selected_file(OtbUser *user, GtkWidget *file_chooser_dialog)
{
	gboolean success=TRUE;
	char *export_data=otb_user_export(user);
	char *file_name=gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(file_chooser_dialog));
	FILE *file=otb_open_text_for_write(file_name);
	if(otb_write(export_data, sizeof(char), strlen(export_data), file)!=strlen(export_data))
		success=FALSE;
	if(!otb_close(file))
		success=FALSE;
	if(!success)
		otb_demo_error_dialog(GTK_WINDOW(file_chooser_dialog), _("There was an error exporting the data."));
	g_free(file_name);
	g_free(export_data);
	return success;
}

G_MODULE_EXPORT
void otb_demo_app_signal_export_user(GtkWidget *widget, void *callback_data)
{
	GtkWidget *file_chooser_dialog=create_file_chooser_dialog_for_export_user(widget);
	gboolean success;
	do
	{
		if(gtk_dialog_run(GTK_DIALOG(file_chooser_dialog))==GTK_RESPONSE_ACCEPT)
		{
			OtbBitkeeper *bitkeeper=otb_bitkeeper_get_with_ref();
			OtbUser *user;
			g_object_get(bitkeeper, OTB_BITKEEPER_PROP_USER, &user, NULL);
			success=export_user_to_dialog_selected_file(user, file_chooser_dialog);
			g_object_unref(user);
			g_object_unref(bitkeeper);
		}
		else
			success=TRUE;
	}
	while(!success);
	gtk_widget_destroy(file_chooser_dialog);
}

static GtkWidget *create_file_chooser_dialog_for_import_user(GtkWidget *widget)
{
	GtkWidget *file_chooser_dialog=gtk_file_chooser_dialog_new("Import friend", GTK_WINDOW(gtk_widget_get_toplevel(widget)), GTK_FILE_CHOOSER_ACTION_OPEN, _("_Cancel"), GTK_RESPONSE_CANCEL, _("_Import"), GTK_RESPONSE_ACCEPT, NULL);
	add_filter_to_chooser_dialog(file_chooser_dialog, "OTB user files", "*.otbu");
	add_filter_to_chooser_dialog(file_chooser_dialog, "All files", "*");
	return file_chooser_dialog;
}

#define READ_BUFFER_SIZE 1024

static gboolean import_user_from_dialog_selected_file(GtkWidget *file_chooser_dialog)
{
	gboolean success=TRUE;
	char *file_name=gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(file_chooser_dialog));
	FILE *file=otb_open_text_for_read(file_name);
	char *friend_import_data=NULL;
	size_t friend_import_data_size=0;
	do
	{
		char read_buffer[READ_BUFFER_SIZE];
		size_t bytes_read=otb_read(read_buffer, sizeof(char), READ_BUFFER_SIZE, file);
		friend_import_data=g_realloc(friend_import_data, friend_import_data_size+bytes_read);
		memcpy(friend_import_data+friend_import_data_size, read_buffer, bytes_read);
		friend_import_data_size+=bytes_read;
	}
	while(!feof(file));
	if(!otb_close(file))
		success=FALSE;
	if(success && !otb_bitkeeper_import_friend(friend_import_data))
		success=FALSE;
	if(!success)
		otb_demo_error_dialog(GTK_WINDOW(file_chooser_dialog), _("There was an error importing the data."));
	g_free(friend_import_data);
	g_free(file_name);
	return success;
}

G_MODULE_EXPORT
void otb_demo_app_signal_import_user(GtkWidget *widget, void *callback_data)
{
	GtkWidget *file_chooser_dialog=create_file_chooser_dialog_for_import_user(widget);
	gboolean success;
	do
	{
		if(gtk_dialog_run(GTK_DIALOG(file_chooser_dialog))==GTK_RESPONSE_ACCEPT)
			success=import_user_from_dialog_selected_file(file_chooser_dialog);
		else
			success=TRUE;
	}
	while(!success);
	gtk_widget_destroy(file_chooser_dialog);
}
