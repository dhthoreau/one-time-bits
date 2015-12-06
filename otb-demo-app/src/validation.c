/**
 * Copyright © 2015 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <errno.h>
#include <gtk/gtk.h>
#include <glib/gi18n.h>
#include <stdlib.h>

#include "main.h"

static GtkCssProvider *provider=NULL;

static void *initialize_css_provider(void *garbage)
{
	char *css_file_path=g_build_filename(DATA_DIRECTORY, "entry-invalid.css", NULL);
	provider=gtk_css_provider_new();
	if(!gtk_css_provider_load_from_path(provider, css_file_path, NULL))
		g_error(_("Failed to load ENTRY_ERROR_STYLE."));
	g_free(css_file_path);
}

static GOnce initialize_css_provider_once=G_ONCE_INIT;

G_MODULE_EXPORT
gboolean otb_validate_unsigned_short_int(GtkWidget *widget, GdkEvent *event, void *user_data)
{
	g_once(&initialize_css_provider_once, initialize_css_provider, NULL);
	errno=0;
	char *last_char=NULL;
	unsigned int entry_value=strtoul(gtk_entry_get_text(GTK_ENTRY(widget)), &last_char, 0);
	if(errno!=0 || entry_value>USHRT_MAX || last_char!=gtk_entry_get_text(GTK_ENTRY(widget))+strlen(gtk_entry_get_text(GTK_ENTRY(widget))))
		gtk_style_context_add_provider(gtk_widget_get_style_context(widget), GTK_STYLE_PROVIDER(provider), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
	else
		gtk_style_context_remove_provider(gtk_widget_get_style_context(widget), GTK_STYLE_PROVIDER(provider));
	return FALSE;
}

G_MODULE_EXPORT
gboolean otb_validate_unsigned_positive_int(GtkWidget *widget, GdkEvent *event, void *user_data)
{
	g_once(&initialize_css_provider_once, initialize_css_provider, NULL);
	errno=0;
	char *last_char=NULL;
	int entry_value=strtol(gtk_entry_get_text(GTK_ENTRY(widget)), &last_char, 0);
	if(errno!=0 || entry_value<0 || last_char!=gtk_entry_get_text(GTK_ENTRY(widget))+strlen(gtk_entry_get_text(GTK_ENTRY(widget))))
		gtk_style_context_add_provider(gtk_widget_get_style_context(widget), GTK_STYLE_PROVIDER(provider), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
	else
		gtk_style_context_remove_provider(gtk_widget_get_style_context(widget), GTK_STYLE_PROVIDER(provider));
	return FALSE;
}

G_MODULE_EXPORT
gboolean otb_validate_not_blank(GtkWidget *widget, GdkEvent *event, void *user_data)
{
	g_once(&initialize_css_provider_once, initialize_css_provider, NULL);
	if(strlen(gtk_entry_get_text(GTK_ENTRY(widget)))==0)
		gtk_style_context_add_provider(gtk_widget_get_style_context(widget), GTK_STYLE_PROVIDER(provider), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
	else
		gtk_style_context_remove_provider(gtk_widget_get_style_context(widget), GTK_STYLE_PROVIDER(provider));
	return FALSE;
}

G_MODULE_EXPORT
gboolean otb_validate_equal(GtkWidget *widget, GdkEvent *event, void *user_data)
{
	g_once(&initialize_css_provider_once, initialize_css_provider, NULL);
	if(strcmp(gtk_entry_get_text(GTK_ENTRY(widget)), gtk_entry_get_text(GTK_ENTRY(user_data)))!=0)
		gtk_style_context_add_provider(gtk_widget_get_style_context(widget), GTK_STYLE_PROVIDER(provider), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
	else
		gtk_style_context_remove_provider(gtk_widget_get_style_context(widget), GTK_STYLE_PROVIDER(provider));
	return FALSE;
}
