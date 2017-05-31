/**
 * Copyright © 2017 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_DEMO_USER_H
#define OTB_DEMO_USER_H

#include "../../libotb/src/libotb.h"

#define OTB_DEMO_USER_PROP_NAME	"name"

#define OTB_DEMO_TYPE_USER				(otb_demo_user_get_type())
#define OTB_DEMO_USER(obj)				(G_TYPE_CHECK_INSTANCE_CAST((obj), OTB_DEMO_TYPE_USER, OtbDemoUser))
#define OTB_DEMO_IS_USER(obj)			(G_TYPE_CHECK_INSTANCE_TYPE((obj), OTB_DEMO_TYPE_USER))
#define OTB_DEMO_USER_CLASS(klass)		(G_TYPE_CHECK_CLASS_CAST((klass), OTB_DEMO_TYPE_USER, OtbDemoUserClass))
#define OTB_DEMO_IS_USER_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE((klass), OTB_DEMO_TYPE_USER))
#define OTB_DEMO_USER_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS((obj), OTB_DEMO_TYPE_USER, OtbDemoUserClass))

typedef struct _OtbDemoUser OtbDemoUser;
typedef struct _OtbDemoUserClass OtbDemoUserClass;
typedef struct _OtbDemoUserPrivate OtbDemoUserPrivate;

struct _OtbDemoUser
{
	OtbUser parent_instance;
	OtbDemoUserPrivate *priv;
};

struct _OtbDemoUserClass
{
	OtbUserClass parent_class;
};

GType otb_demo_user_get_type(void);

#endif
