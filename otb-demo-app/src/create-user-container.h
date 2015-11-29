/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_DEMO_CREATE_USER_H
#define OTB_DEMO_CREATE_USER_H

#include <gtk/gtk.h>

typedef struct _OTBDemoCreateUserContainer OTBDemoCreateUserContainer;

struct _OTBDemoCreateUserContainer
{
	GtkEntry *name;
	GtkEntry *address;
	GtkEntry *port;
	GtkEntry *key_size;
	GtkEntry *proxy_port;
	GtkEntry *pad_synchronization_interval;
};

OTBDemoCreateUserContainer *otb_demo_create_user_container_from_builder(GtkBuilder *builder);

#endif
