/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <gtk/gtk.h>

#include "create-user-container.h"

OTBDemoCreateUserContainer *otb_demo_create_user_container_from_builder(GtkBuilder *builder)
{
	OTBDemoCreateUserContainer *create_user_container=g_slice_new(OTBDemoCreateUserContainer);
	create_user_container->name=GTK_ENTRY(gtk_builder_get_object(builder, "nameValue"));
	create_user_container->address=GTK_ENTRY(gtk_builder_get_object(builder, "addressValue"));
	create_user_container->port=GTK_ENTRY(gtk_builder_get_object(builder, "portValue"));
	create_user_container->key_size=GTK_ENTRY(gtk_builder_get_object(builder, "keySizeValue"));
	create_user_container->proxy_port=GTK_ENTRY(gtk_builder_get_object(builder, "proxyPortValue"));
	create_user_container->pad_synchronization_interval=GTK_ENTRY(gtk_builder_get_object(builder, "padSynchronizationIntervalValue"));
	return create_user_container;
}
