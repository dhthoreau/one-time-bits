/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_UNIQUE_ID_H
#define OTB_UNIQUE_ID_H

#include <uuid/uuid.h>

#define otb_unique_id_compare(unique_id1, unique_id2)	(uuid_compare((unique_id1)->value, (unique_id2)->value))

#define OTB_TYPE_UNIQUE_ID	(otb_unique_id_get_type())

typedef struct
{
	uuid_t value;
} OtbUniqueId;

GType otb_unique_id_get_type();
OtbUniqueId *otb_unique_id_create();
char *otb_unique_id_to_string(OtbUniqueId *unique_id);
OtbUniqueId *otb_unique_id_from_string(char *unique_id_string);
char *otb_unique_id_string_create();
OtbUniqueId *otb_unique_id_duplicate(const OtbUniqueId *unique_id);

#endif
