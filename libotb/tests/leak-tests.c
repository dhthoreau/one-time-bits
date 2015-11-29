/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <stdio.h>

#include "main.h"
#include "test-utils.h"

static void otb_call_test(const void *test, const void *user_data)
{
	otb_recreate_test_dir();
	((GTestFunc)test)();
	otb_test_clean_up();
}

static void test_memory_leaks()
{
	/// This test will never exit nor fail. It is intended to be run while you monitor memory consumption for possible leaks,
	/// then terminate the process (CNTRL-C) when you are finished monitoring.
	while(TRUE)
		g_slist_foreach(otb_test_funcs, (GFunc)otb_call_test, NULL);
}

void otb_add_leak_tests()
{
	if(g_test_perf())
		g_test_add_func("/leak/test_memory_leaks", test_memory_leaks);
}
