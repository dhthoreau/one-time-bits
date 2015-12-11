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

#include "../../libotb/src/libotb.h"

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

static void invalidate_entry(const GtkEntry *entry)
{
	g_once(&initialize_css_provider_once, initialize_css_provider, NULL);
	gtk_style_context_add_provider(gtk_widget_get_style_context(GTK_WIDGET(entry)), GTK_STYLE_PROVIDER(provider), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
}

gboolean otb_validation_validate_not_blank(GtkEntry *entry)
{
	if(strlen(gtk_entry_get_text(entry))==0)
	{
		invalidate_entry(entry);
		return FALSE;
	}
	return TRUE;
}

gboolean otb_validation_validate_equal(GtkEntry *entry1, GtkEntry *entry2)
{
	if(strcmp(gtk_entry_get_text(entry1), gtk_entry_get_text(entry2))!=0)
	{
		invalidate_entry(entry1);
		invalidate_entry(entry2);
		return FALSE;
	}
	return TRUE;
}

gboolean otb_validation_validate_local_crypto_unlock(GtkEntry *entry)
{
	if(!otb_local_crypto_unlock_sym_cipher(gtk_entry_get_text(entry)))
	{
		invalidate_entry(entry);
		return FALSE;
	}
	return TRUE;
}

G_MODULE_EXPORT
void otb_demo_validation_signal_clear_error_style(GtkWidget *widget1, GtkWidget *widget2)
{
	if(provider!=NULL)
	{
		gtk_style_context_remove_provider(gtk_widget_get_style_context(widget1), GTK_STYLE_PROVIDER(provider));
		if(widget2!=NULL)
			gtk_style_context_remove_provider(gtk_widget_get_style_context(widget2), GTK_STYLE_PROVIDER(provider));
	}
}
