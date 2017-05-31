/**
 * Copyright © 2017 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_WORKING_H
#define OTB_WORKING_H

#include <gtk/gtk.h>

#include "app.h"

#define otb_demo_app_create_hidden_working_transient(parent_window)	otb_demo_app_create_hidden_transient_window("working.ui", "workingWindow", gtk_window_get_application(parent_window), NULL, (parent_window))

#endif
