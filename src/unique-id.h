/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_UNIQUE_ID_H
#define OTB_UNIQUE_ID_H

#include <glib-object.h>
#include <uuid/uuid.h>

#define OTB_TYPE_UNIQUE_ID	(otb_unique_id_get_type())

#define OTB_UNIQUE_ID_BYTES_LENGTH	(sizeof(uuid_t))

typedef struct _OtbUniqueId OtbUniqueId;

GType otb_unique_id_get_type();
OtbUniqueId *otb_unique_id_create();
const unsigned char *otb_unique_id_get_bytes(const OtbUniqueId *unique_id);
OtbUniqueId *otb_unique_id_from_bytes(const unsigned char *unique_id_bytes);
char *otb_unique_id_to_string(const OtbUniqueId *unique_id);
OtbUniqueId *otb_unique_id_from_string(const char *unique_id_string);
char *otb_unique_id_string_create();
OtbUniqueId *otb_unique_id_duplicate(const OtbUniqueId *unique_id);
int otb_unique_id_compare(const OtbUniqueId *unique_id1, const OtbUniqueId *unique_id2);
void otb_unique_id_free(OtbUniqueId *unique_id);

#endif
