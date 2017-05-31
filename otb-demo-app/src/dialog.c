/**
 * Copyright © 2017 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <gtk/gtk.h>

void otb_demo_dialog(GtkWindow *window, GtkMessageType type, const char *message)
{
	GtkWidget *error_dialog=gtk_message_dialog_new(window, GTK_DIALOG_MODAL, type, GTK_BUTTONS_OK, message, NULL);
	gtk_dialog_run(GTK_DIALOG(error_dialog));
	gtk_widget_destroy(error_dialog);
}
