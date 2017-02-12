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
#include "dialog.h"
#include "passphrase-unlock.h"
#include "demo-user.h"

#include "../../libotb/src/libotb.h"

#include "main.h"

#define otb_data_is_corrupted_or_missing()	(!otb_local_crypto_can_be_unlocked() || !otb_bitkeeper_exists() || !otb_user_exists())

gboolean otb_demo_load_bitkeeper_with_error_handling(GtkWindow *window)
{
	gboolean ret_val=otb_bitkeeper_load();
	if(G_UNLIKELY(!ret_val))
		otb_demo_error_dialog(window, _("There was a problem loading the data."));
	return ret_val;
}

static void activate(GtkApplication *application, const void *user_data)
{
	otb_settings_initialize(OTB_DEMO_APP_NAME, "otb");
	if(G_UNLIKELY(otb_data_is_corrupted_or_missing()))
		otb_demo_create_user_show_new_window(application);
	else if(otb_local_crypto_unlock(""))
	{
		if(otb_demo_load_bitkeeper_with_error_handling(NULL))
			otb_demo_console_show_new_window(application);
	}
	else
		otb_demo_passphrase_unlock_show_new_window(application);
}

int main(int argc, char *argv[])
{
	otb_user_set_runtime_type(OTB_DEMO_TYPE_USER);
	GtkApplication *application=gtk_application_new("otb.DemoApp", G_APPLICATION_FLAGS_NONE);
	g_signal_connect(application, "activate", G_CALLBACK(activate), NULL);
	int status=g_application_run(G_APPLICATION(application), argc, argv);
	g_object_unref(application);
	return status;
}
