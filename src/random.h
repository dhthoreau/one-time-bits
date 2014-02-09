/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_RANDOM_H
#define OTB_RANDOM_H

#define otb_modulo(x, y)						(((x)%(y)+(y))%(y))

gboolean otb_random_bytes(void *bytes, size_t num_bytes);
void *otb_create_random_bytes(size_t size);

#endif
