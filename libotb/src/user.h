/**
 * Copyright © 2015 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_USER_H
#define OTB_USER_H

#include "asym-cipher.h"

#define OTB_USER_PROP_UNIQUE_ID		"unique-id"
#define OTB_USER_PROP_ASYM_CIPHER	"asym-cipher"
#define OTB_USER_PROP_ADDRESS		"address"
#define OTB_USER_PROP_PORT			"port"

#define OTB_TYPE_USER				(otb_user_get_type())
#define OTB_USER(obj)				(G_TYPE_CHECK_INSTANCE_CAST((obj), OTB_TYPE_USER, OtbUser))
#define OTB_IS_USER(obj)			(G_TYPE_CHECK_INSTANCE_TYPE((obj), OTB_TYPE_USER))
#define OTB_USER_CLASS(klass)		(G_TYPE_CHECK_CLASS_CAST((klass), OTB_TYPE_USER, OtbUserClass))
#define OTB_IS_USER_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE((klass), OTB_TYPE_USER))
#define OTB_USER_GET_CLASS(obj)		(G_TYPE_INSTANCE_GET_CLASS((obj), OTB_TYPE_USER, OtbUserClass))

typedef struct _OtbUser OtbUser;
typedef struct _OtbUserClass OtbUserClass;
typedef struct _OtbUserPrivate OtbUserPrivate;

struct _OtbUser
{
	GObject parent_instance;
	OtbUserPrivate *priv;
};

struct _OtbUserClass
{
	GObjectClass parent_class;
	void (*otb_user_export_key_file_private)(const OtbUser *user, GKeyFile *);
};

GType otb_user_get_type();

void otb_user_set_runtime_type(GType user_runtime_type);
void otb_user_lock_read(const OtbUser *user);
void otb_user_unlock_read(const OtbUser *user);
void otb_user_lock_write(const OtbUser *user);
void otb_user_unlock_write(const OtbUser *user);
gboolean otb_user_exists();
OtbUser *otb_user_create(const unsigned char *address, unsigned short port, unsigned int key_size);	// FARE - Non cancellare dati sul disc. Invece, abbi un otb_user_delete().
OtbUser *otb_user_load();
gboolean otb_user_set_address(const OtbUser *user, const char *address);
gboolean otb_user_set_port(const OtbUser *user, unsigned short port);
char *otb_user_export(const OtbUser *user);

#endif
