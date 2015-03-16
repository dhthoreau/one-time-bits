/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_DUMMY_USER_H
#define OTB_DUMMY_USER_H

#include "../src/user.h"

#define OTB_DUMMY_USER_EXPORT_VALUE	"dummy-export-dumb-dumb"

#define OTB_TYPE_DUMMY_USER				(otb_dummy_user_get_type())
#define OTB_DUMMY_USER(obj)				(G_TYPE_CHECK_INSTANCE_CAST((obj), OTB_TYPE_DUMMY_USER, OtbDummyUser))
#define OTB_IS_DUMMY_USER(obj)			(G_TYPE_CHECK_INSTANCE_TYPE((obj), OTB_TYPE_DUMMY_USER))
#define OTB_DUMMY_USER_CLASS(klass)		(G_TYPE_CHECK_CLASS_CAST((klass), OTB_TYPE_DUMMY_USER, OtbDummyUserClass))
#define OTB_IS_DUMMY_USER_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE((klass), OTB_TYPE_DUMMY_USER))
#define OTB_DUMMY_USER_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS((obj), OTB_TYPE_DUMMY_USER, OtbDummyUserClass))

typedef struct _OtbDummyUser OtbDummyUser;
typedef struct _OtbDummyUserClass OtbDummyUserClass;

struct _OtbDummyUser
{
	OtbUser parent_instance;
};

struct _OtbDummyUserClass
{
	OtbUserClass parent_class;
};

GType otb_dummy_user_get_type();

#endif

