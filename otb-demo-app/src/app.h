/**
 * Copyright © 2015 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_DEMO_OTB_DEMO_APP_H
#define OTB_DEMO_OTB_DEMO_APP_H

typedef void (*WindowCreationSetupCallback)(GtkBuilder *builder);

void otb_demo_app_create_window(const char *file_name, const WindowCreationSetupCallback setup_callback, GtkApplication *application);

#endif
