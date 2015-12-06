/**
 * Copyright © 2015 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <glib/gi18n.h>

#include "export.h"
#include "openssl-util.h"

gboolean otb_random_bytes(void *bytes, size_t num_bytes)
{
	gboolean ret_val=TRUE;
	int rand_results=_RAND_bytes(bytes, num_bytes);
	if(G_UNLIKELY(rand_results<=0))
	{
		char *error=otb_openssl_errors_as_string();
		g_warning(_("Failed to generate random data. Error == %s"), error);
		g_free(error);
		ret_val=FALSE;
	}
	return ret_val;
}

unsigned char *otb_create_random_bytes(size_t size)
{
	unsigned char *byte_array=g_new(unsigned char, size);
	if(G_UNLIKELY(!otb_random_bytes(byte_array, size)))
	{
		g_free(byte_array);
		byte_array=NULL;
	}
	return byte_array;
}
