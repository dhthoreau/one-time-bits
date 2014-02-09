/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <glib/gi18n.h>

#include "openssl-util.h"

int _RAND_bytes(unsigned char *buf, int num);

gboolean otb_random_bytes(void *bytes, size_t num_bytes)
{
	gboolean ret_val=TRUE;
	int rand_results=_RAND_bytes(bytes, num_bytes);
	if(rand_results<=0)
	{
		char *error=otb_openssl_errors_as_string();
		g_warning(_("%s: Failed to generate random data. Error == %s"), "otb_secure_random_bytes", error, NULL);
		g_free(error);
		ret_val=FALSE;
	}
	return ret_val;
}

void *otb_create_random_bytes(size_t size)
{
	void *byte_array=g_malloc(size);
	if(!otb_random_bytes(byte_array, size))
	{
		g_free(byte_array);
		byte_array=NULL;
	}
	return byte_array;
}
