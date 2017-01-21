/**
 * Copyright © 2015 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include "main.h"
#include "../src/loopable-thread.h"
#include "../src/random.h"

static int otb_test_loopable_thread_data;
static int otb_test_loopable_thread_call_count;
static int otb_test_loopable_thread_loop_count;

static void otb_test_loopable_thread(OtbLoopableThread *loopable_thread)
{
	if(!otb_test_loopable_thread_call_count)
		g_assert(otb_loopable_thread_continue_looping(loopable_thread));
	otb_test_loopable_thread_call_count++;
	g_assert_cmpint(otb_test_loopable_thread_data, ==, *((int*)otb_loopable_thread_data(loopable_thread)));
}

static void test_loopable_thread()
{
	otb_test_loopable_thread_call_count=0;
	otb_random_bytes(&otb_test_loopable_thread_data, sizeof otb_test_loopable_thread_data);
	OtbLoopableThread *loopable_thread=otb_loopable_thread_new("TestThread", otb_test_loopable_thread, &otb_test_loopable_thread_data, 100);
	otb_loopable_thread_ref(loopable_thread);
	while(otb_test_loopable_thread_call_count<3 && otb_test_loopable_thread_loop_count<2)
		;
	otb_loopable_thread_stop(loopable_thread);
	g_assert(!otb_loopable_thread_continue_looping(loopable_thread));
	otb_loopable_thread_unref(loopable_thread);
}

void otb_add_loopable_thread_tests()
{
	otb_add_test_func("/loopable-thread/test_loopable_thread", test_loopable_thread);
}
