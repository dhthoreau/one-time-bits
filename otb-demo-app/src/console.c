/**
 * Copyright © 2017 the OTB team
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
#include "demo-friend.h"
#include "validation.h"

#include "../../libotb/src/libotb.h"

#define CONSOLE_WINDOW	"consoleWindow"

static void add_friend_to_console_list(const OtbUniqueId *friend_unique_id, GtkListBox *friends_list)
{
	OtbFriend *friend=otb_bitkeeper_get_friend(friend_unique_id);
	char *friend_name;
	g_object_get(friend, OTB_DEMO_FRIEND_PROP_NAME, &friend_name, NULL);
	GtkWidget *friend_label=gtk_label_new(friend_name);
	gtk_container_add(GTK_CONTAINER(friends_list), friend_label);
	g_object_unref(friend_label);
	g_free(friend_name);
	g_object_unref(friend);
}

static void console_window_setup(GtkBuilder *builder)
{
	GtkListBox *friends_list=g_object_ref(GTK_LIST_BOX(gtk_builder_get_object(builder, "friendsList")));
	GSList *friend_unique_ids=otb_bitkeeper_get_unique_ids_of_friends();
	g_slist_foreach(friend_unique_ids, (GFunc)add_friend_to_console_list, friends_list);
	g_slist_free_full(friend_unique_ids, (GDestroyNotify)otb_unique_id_unref);
	g_object_unref(friends_list);
}

void otb_demo_console_show_new_window(GtkApplication *application)
{
	otb_demo_app_create_window("console.ui", CONSOLE_WINDOW, application, console_window_setup);
}

G_MODULE_EXPORT
void otb_demo_app_signal_switch_to_console(GtkWidget *widget, void *callback_data)
{
	GtkWindow *window=GTK_WINDOW(gtk_widget_get_toplevel(widget));
	otb_demo_console_show_new_window(gtk_window_get_application(window));
	gtk_widget_destroy(GTK_WIDGET(window));
}
