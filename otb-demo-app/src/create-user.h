/**
 * Copyright © 2015 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_DEMO_CREATE_USER_H
#define OTB_DEMO_CREATE_USER_H

#include <gtk/gtk.h>

typedef struct _OtbDemoCreateUserContainer OtbDemoCreateUserContainer;

OtbDemoCreateUserContainer *otb_demo_create_user_container_from_builder(GtkBuilder *builder);
const char *otb_demo_create_user_container_get_name(const OtbDemoCreateUserContainer *create_user_container);
const char *otb_demo_create_user_container_get_address(const OtbDemoCreateUserContainer *create_user_container);
const char *otb_demo_create_user_container_get_passphrase(const OtbDemoCreateUserContainer *create_user_container);
unsigned short otb_demo_create_user_container_get_user_port(const OtbDemoCreateUserContainer *create_user_container);
int otb_demo_create_user_container_get_key_size(const OtbDemoCreateUserContainer *create_user_container);
unsigned short otb_demo_create_user_container_get_proxy_port(const OtbDemoCreateUserContainer *create_user_container);
long long otb_demo_create_user_container_get_pad_synchronization_interval(const OtbDemoCreateUserContainer *create_user_container);
OtbDemoCreateUserContainer *otb_demo_create_user_container_ref(OtbDemoCreateUserContainer *create_user_container);
void otb_demo_create_user_container_unref(OtbDemoCreateUserContainer *create_user_container);
void otb_demo_create_user_show_new_window(GtkApplication *application);

#endif
