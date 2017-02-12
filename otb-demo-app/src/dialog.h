/**
 * Copyright © 2015 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_DEMO_DIALOG_H
#define OTB_DEMO_DIALOG_H

#define otb_demo_error_dialog(window, message)		otb_demo_dialog((window), GTK_MESSAGE_ERROR, (message))
#define otb_demo_warning_dialog(window, message)	otb_demo_dialog((window), GTK_MESSAGE_WARNING, (message))

void otb_demo_dialog(GtkWindow *window, GtkMessageType type, const char *message);

#endif
