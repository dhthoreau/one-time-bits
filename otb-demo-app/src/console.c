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
#include "create-user.h"
#include "validation.h"

#include "../../libotb/src/libotb.h"

#define CONSOLE_WINDOW	"consoleWindow"

void otb_demo_console_show_new_window(GtkApplication *application)
{
	otb_demo_app_create_window("console.ui", CONSOLE_WINDOW, application, NULL);
}

G_MODULE_EXPORT
void otb_demo_app_signal_switch_to_console(GtkWidget *widget, void *callback_data)
{
	GtkWindow *window=GTK_WINDOW(gtk_widget_get_toplevel(widget));
	otb_demo_console_show_new_window(gtk_window_get_application(window));
	gtk_widget_destroy(GTK_WIDGET(window));
}
