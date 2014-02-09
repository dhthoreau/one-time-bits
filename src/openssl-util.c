/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <glib.h>
#include <openssl/err.h>
#include <string.h>

char *otb_openssl_errors_as_string()
{
	BIO *bio=BIO_new(BIO_s_mem());
	ERR_print_errors(bio);
	char *buffer=NULL;
	size_t size=BIO_get_mem_data(bio, &buffer);
	char *error_string=g_strnfill(size+1, 0);
	if(error_string)
		memcpy(error_string, buffer, size);
	BIO_free(bio);
	return error_string;
}
