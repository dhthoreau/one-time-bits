/**
 * Copyright © 2015 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <glib-object.h>
#include <string.h>

#include "unique-id.h"

#define UNIQUE_ID_STRING_SIZE	37

struct _OtbUniqueId
{
	int ref_count;
	uuid_t uuid;
};

GType otb_unique_id_get_type()
{
	static GType unique_id_type;
	static long otb_unique_id_type_initialized=FALSE;
	if(G_UNLIKELY(g_once_init_enter(&otb_unique_id_type_initialized)))
	{
		unique_id_type=g_boxed_type_register_static("OtbUniqueId", (GBoxedCopyFunc)otb_unique_id_ref, (GDestroyNotify)otb_unique_id_unref);
		g_once_init_leave(&otb_unique_id_type_initialized, TRUE);
	}
	return unique_id_type;
}

static OtbUniqueId *otb_unique_id_instantiate()
{
	OtbUniqueId *unique_id=g_slice_new(OtbUniqueId);
	unique_id->ref_count=1;
	return unique_id;
}

OtbUniqueId *otb_unique_id_new()
{
	OtbUniqueId *unique_id=otb_unique_id_instantiate();
	uuid_generate(unique_id->uuid);
	return unique_id;
}

const unsigned char *otb_unique_id_get_bytes(const OtbUniqueId *unique_id)
{
	return unique_id->uuid;
}

OtbUniqueId *otb_unique_id_from_bytes(const unsigned char *unique_id_bytes)
{
	OtbUniqueId *unique_id=otb_unique_id_instantiate();
	memcpy(unique_id->uuid, unique_id_bytes, sizeof unique_id->uuid);
	return unique_id;
}

char *otb_unique_id_to_string(const OtbUniqueId *unique_id)
{
	char *unique_id_string=g_new(char, UNIQUE_ID_STRING_SIZE);
	uuid_unparse_lower(unique_id->uuid, unique_id_string);
	return unique_id_string;
}

OtbUniqueId *otb_unique_id_from_string(const char *unique_id_string)
{
	OtbUniqueId *unique_id=otb_unique_id_instantiate();
	uuid_parse(unique_id_string, unique_id->uuid);
	return unique_id;
}

char *otb_unique_id_string_new()
{
	OtbUniqueId *unique_id=otb_unique_id_new();
	char *unique_id_string=otb_unique_id_to_string(unique_id);
	g_slice_free(OtbUniqueId, unique_id);
	return unique_id_string;
}

OtbUniqueId *otb_unique_id_ref(OtbUniqueId *unique_id)
{
	g_return_val_if_fail(unique_id!=NULL, NULL);
	g_atomic_int_inc(&unique_id->ref_count);
	return unique_id;
}

int otb_unique_id_compare(const OtbUniqueId *unique_id1, const OtbUniqueId *unique_id2)
{
	return uuid_compare(unique_id1->uuid, unique_id2->uuid);
}

void otb_unique_id_unref(OtbUniqueId *unique_id)
{
	if(unique_id!=NULL && g_atomic_int_dec_and_test(&unique_id->ref_count))
		g_slice_free(OtbUniqueId, unique_id);
}
