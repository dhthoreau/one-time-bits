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

void otb_demo_console_show_new_window(GtkApplication *application)
{
	otb_demo_app_create_window("console.ui", NULL, application);
}
