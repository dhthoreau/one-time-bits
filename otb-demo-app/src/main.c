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

#include "create-user-container.h"
#include "../../libotb/src/libotb.h"

G_MODULE_EXPORT
void signal_main_quit(GtkWidget *widget)
{
	gtk_main_quit();
}

G_MODULE_EXPORT
void signal_main_close_window(GtkWidget *widget, GtkWindow *window)
{
	gtk_window_close(window);
}

G_MODULE_EXPORT
void signal_main_create_bitkeeper(GtkWidget *widget, OTBDemoCreateUserContainer *create_user_container)
{
	unsigned short proxy_port=(unsigned short)strtoul(gtk_entry_get_text(create_user_container->proxy_port), NULL, 0);
	long long pad_synchronization_interval=strtoll(gtk_entry_get_text(create_user_container->pad_synchronization_interval), NULL, 0);
	unsigned short user_port=(unsigned short)strtoul(gtk_entry_get_text(create_user_container->port), NULL, 0);
	int key_size=atoi(gtk_entry_get_text(create_user_container->key_size));
	otb_bitkeeper_create(proxy_port, pad_synchronization_interval, gtk_entry_get_text(create_user_container->address), user_port, key_size);
	gtk_main_quit();
}

static gboolean setup_local_crypto()
{
	if(otb_local_crypto_can_be_unlocked())
		otb_local_crypto_unlock_sym_cipher("");
	else
		otb_local_crypto_create_sym_cipher("");
}

typedef void (*WindowCreationSetupCallback)(GtkBuilder *builder);

static GtkWindow *create_window(const char *fileName, const WindowCreationSetupCallback setup_callback)
{
	GtkBuilder *builder=gtk_builder_new_from_file(fileName);
	gtk_builder_connect_signals(builder, NULL);
	if(setup_callback!=NULL)
		setup_callback(builder);
	GtkWindow *window=GTK_WINDOW(gtk_builder_get_object(builder, "window"));
	g_object_unref(builder);
	return window;
}

static void new_bitkeeper_prompt_window_setup(GtkBuilder *builder)
{
	char user_port_string[6];
	char user_key_size_string[12];
	char proxy_port_string[6];
	char pad_synchonization_interval_string[21];
	sprintf(user_port_string, "%hu", OTB_BITKEEPER_DEFAULT_USER_PORT);
	sprintf(user_key_size_string, "%hu", OTB_BITKEEPER_DEFAULT_USER_KEY_SIZE);
	sprintf(proxy_port_string, "%hu", OTB_BITKEEPER_DEFAULT_PROXY_PORT);
	sprintf(pad_synchonization_interval_string, "%lli", OTB_BITKEEPER_DEFAULT_PAD_SYNCHRONIZATION_INTERVAL);
	gtk_entry_set_text(GTK_ENTRY(gtk_builder_get_object(builder, "portValue")), user_port_string);
	gtk_entry_set_text(GTK_ENTRY(gtk_builder_get_object(builder, "keySizeValue")), user_key_size_string);
	gtk_entry_set_text(GTK_ENTRY(gtk_builder_get_object(builder, "proxyPortValue")), proxy_port_string);
	gtk_entry_set_text(GTK_ENTRY(gtk_builder_get_object(builder, "padSynchronizationIntervalValue")), pad_synchonization_interval_string);
	g_signal_connect(GTK_WIDGET(gtk_builder_get_object(builder, "saveButton")), "clicked", G_CALLBACK(signal_main_create_bitkeeper), otb_demo_create_user_container_from_builder(builder));
}

static void run_otb_new_bitkeeper_prompt()
{
	GtkWindow *window=create_window("create-user.ui", new_bitkeeper_prompt_window_setup);
	gtk_widget_show(GTK_WIDGET(window));
	gtk_main();
}

static void destroy_bitkeeper(OtbBitkeeper *bitkeeper)
{
	otb_bitkeeper_shutdown_tasks(bitkeeper);
	g_object_unref(bitkeeper);
}

static void run_otb_demo_app_window(OtbBitkeeper *bitkeeper)
{
	otb_bitkeeper_launch_tasks(bitkeeper);
	GtkWindow *window=create_window("main.ui", NULL);
	g_signal_connect_after(GTK_WIDGET(window), "delete_event", G_CALLBACK(destroy_bitkeeper), bitkeeper);
	gtk_widget_show(GTK_WIDGET(window));
	gtk_main();
	gtk_widget_destroy(GTK_WIDGET(window));
}

static void run_otb_demo_app()
{
	OtbBitkeeper *bitkeeper=NULL;
	if(!otb_bitkeeper_exists())
		run_otb_new_bitkeeper_prompt();
	else
	{
		bitkeeper=otb_bitkeeper_load();
		if(bitkeeper==NULL)
			g_error(_("Failed to load bitkeeper."));
		run_otb_demo_app_window(bitkeeper);
	}
}

int main(int argc, char *argv[])
{
	gtk_init(&argc, &argv);
	otb_settings_initialize("otb-demo-app", "otb");
	setup_local_crypto();
	run_otb_demo_app();
	return 0;
}
