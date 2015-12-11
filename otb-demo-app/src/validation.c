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

gboolean otb_validate_not_blank(GtkEntry *entry)
{
	g_once(&initialize_css_provider_once, initialize_css_provider, NULL);
	if(strlen(gtk_entry_get_text(entry))==0)
	{
		gtk_style_context_add_provider(gtk_widget_get_style_context(GTK_WIDGET(entry)), GTK_STYLE_PROVIDER(provider), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
		return FALSE;
	}
	gtk_style_context_remove_provider(gtk_widget_get_style_context(GTK_WIDGET(entry)), GTK_STYLE_PROVIDER(provider));
	return TRUE;
}

gboolean otb_validate_equal(GtkEntry *entry1, GtkEntry *entry2)
{
	g_once(&initialize_css_provider_once, initialize_css_provider, NULL);
	if(strcmp(gtk_entry_get_text(entry1), gtk_entry_get_text(entry2))!=0)
	{
		gtk_style_context_add_provider(gtk_widget_get_style_context(GTK_WIDGET(entry1)), GTK_STYLE_PROVIDER(provider), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
		gtk_style_context_add_provider(gtk_widget_get_style_context(GTK_WIDGET(entry2)), GTK_STYLE_PROVIDER(provider), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
		return FALSE;
	}
	gtk_style_context_remove_provider(gtk_widget_get_style_context(GTK_WIDGET(entry1)), GTK_STYLE_PROVIDER(provider));
	gtk_style_context_remove_provider(gtk_widget_get_style_context(GTK_WIDGET(entry2)), GTK_STYLE_PROVIDER(provider));
	return TRUE;
}
