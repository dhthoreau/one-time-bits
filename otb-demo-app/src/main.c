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
#include "create-user.h"
#include "passphrase-unlock.h"

#include "../../libotb/src/libotb.h"

#include "main.h"

static void destroy_bitkeeper(OtbBitkeeper *bitkeeper)
{
	otb_bitkeeper_shutdown_tasks(bitkeeper);
	g_object_unref(bitkeeper);
}

static void run_otb_demo_app_window(OtbBitkeeper *bitkeeper)
{
	otb_bitkeeper_launch_tasks(bitkeeper);
	const GtkWindow *window=NULL;
	otb_demo_app_create_window("main.ui", NULL, NULL);
	g_signal_connect_after(GTK_WIDGET(window), "delete_event", G_CALLBACK(destroy_bitkeeper), bitkeeper);
	gtk_widget_show(GTK_WIDGET(window));
	gtk_main();
	gtk_widget_destroy(GTK_WIDGET(window));
}

#define otb_data_is_corrupted_or_missing()	(!otb_local_crypto_can_be_unlocked() || !otb_bitkeeper_exists() || !otb_user_exists())

static void activate(GtkApplication *application, const void *user_data)
{
	otb_settings_initialize(OTB_DEMO_APP_NAME, "otb");
	const OtbBitkeeper *bitkeeper=NULL;
	if(otb_data_is_corrupted_or_missing())
		otb_demo_create_user_show_new_window(application);
	else if(otb_local_crypto_unlock_sym_cipher(""))
		otb_demo_console_show_new_window(application);
	else
		otb_demo_passphrase_unlock_show_new_window(application);
/*
{
		bitkeeper=otb_bitkeeper_load();
		if(bitkeeper==NULL)
			g_error(_("Failed to load bitkeeper."));
		run_otb_demo_app_window(bitkeeper);
}
*/
}

int main(int argc, char *argv[])
{
	GtkApplication *application=gtk_application_new("otb.DemoApp", G_APPLICATION_FLAGS_NONE);
	g_signal_connect(application, "activate", G_CALLBACK(activate), NULL);
	int status=g_application_run(G_APPLICATION(application), argc, argv);
	g_object_unref(application);
	return status;
}
