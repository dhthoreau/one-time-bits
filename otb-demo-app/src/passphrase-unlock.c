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
#include "dialog.h"
#include "main.h"
#include "validation.h"

#include "../../libotb/src/libotb.h"

#define PASSPHRASE_UNLOCK_WINDOW	"passphraseUnlockWindow"

typedef struct
{
	GtkWindow *window;
	GtkEntry *passphrase;
} PassphraseUnlockContainer;

static PassphraseUnlockContainer *passphrase_unlock_container_from_builder(GtkBuilder *builder)
{
	PassphraseUnlockContainer *passphrase_unlock_container=g_slice_new(PassphraseUnlockContainer);
	passphrase_unlock_container->window=g_object_ref(GTK_WINDOW(gtk_builder_get_object(builder, PASSPHRASE_UNLOCK_WINDOW)));
	passphrase_unlock_container->passphrase=g_object_ref(GTK_ENTRY(gtk_builder_get_object(builder, "passphraseValue")));
	return passphrase_unlock_container;
}

#define passphrase_unlock_container_get_passphrase(passphrase_container)	(gtk_entry_get_text((passphrase_container)->passphrase))

static void signal_passphrase_unlock_button_clicked(const GtkWidget *widget, PassphraseUnlockContainer *passphrase_unlock_container)
{
	if(!otb_validation_validate_not_blank(passphrase_unlock_container->passphrase))
		otb_demo_error_dialog(passphrase_unlock_container->window, _("Please enter a passphrase."));
	else if(!otb_validation_validate_local_crypto_unlock(passphrase_unlock_container->passphrase))
		otb_demo_error_dialog(passphrase_unlock_container->window, _("Incorrect passphrase. Please try again."));
	else if(otb_demo_load_bitkeeper_with_error_handling(passphrase_unlock_container->window))
	{
		otb_demo_console_show_new_window(gtk_window_get_application(passphrase_unlock_container->window));
		gtk_widget_destroy(GTK_WIDGET(passphrase_unlock_container->window));
	}
}

static void signal_passphrase_unlock_container_free(const GtkWidget *widget, PassphraseUnlockContainer *passphrase_unlock_container)
{
	g_object_unref(passphrase_unlock_container->window);
	g_object_unref(passphrase_unlock_container->passphrase);
	g_slice_free(PassphraseUnlockContainer, passphrase_unlock_container);
}

static void new_passphrase_unlock_window_setup(GtkBuilder *builder)
{
	PassphraseUnlockContainer *passphrase_unlock_container=passphrase_unlock_container_from_builder(builder);
	g_signal_connect(GTK_WIDGET(gtk_builder_get_object(builder, "unlockButton")), "clicked", G_CALLBACK(signal_passphrase_unlock_button_clicked), passphrase_unlock_container);
	g_signal_connect(GTK_WIDGET(gtk_builder_get_object(builder, PASSPHRASE_UNLOCK_WINDOW)), "destroy", G_CALLBACK(signal_passphrase_unlock_container_free), passphrase_unlock_container);
}

void otb_demo_passphrase_unlock_show_new_window(GtkApplication *application)
{
	otb_demo_app_create_window("passphrase-unlock.ui", PASSPHRASE_UNLOCK_WINDOW, application, new_passphrase_unlock_window_setup);
}
