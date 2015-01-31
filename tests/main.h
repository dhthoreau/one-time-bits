/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_MAIN_H
#define OTB_MAIN_H

#include <glib-object.h>

#include "test-utils.h"

#define otb_add_test_func(name, func)	if(!g_test_perf()) g_test_add((name), void, NULL, otb_recreate_test_dir, (func), otb_delete_test_dir); otb_test_funcs=g_slist_prepend(otb_test_funcs, (func))

extern GSList *otb_test_funcs;

#endif
