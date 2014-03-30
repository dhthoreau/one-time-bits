/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include <string.h>

#include "main.h"
#include "../src/unique-id.h"

static void test_unique_id_create_compare()
{
	OtbUniqueId *unique_id1=otb_unique_id_create();
	OtbUniqueId *unique_id2=otb_unique_id_create();
	g_assert_cmpint(0, ==, otb_unique_id_compare(unique_id1, unique_id1));
	g_assert_cmpint(0, !=, otb_unique_id_compare(unique_id1, unique_id2));
	g_free(unique_id1);
	g_free(unique_id2);
}

static void test_unique_id_duplicate()
{
	OtbUniqueId *unique_id1=otb_unique_id_create();
	OtbUniqueId *unique_id2=otb_unique_id_duplicate(unique_id1);
	g_assert(unique_id1!=unique_id2);
	g_assert_cmpint(0, ==, otb_unique_id_compare(unique_id1, unique_id2));
	g_free(unique_id1);
	g_free(unique_id2);
}

static void test_unique_id_duplicate_null()
{
	g_assert(otb_unique_id_duplicate(NULL)==NULL);
}

static void test_unique_id_strings()
{
	char *expected_unique_id_string=otb_unique_id_string_create();
	OtbUniqueId *unique_id=otb_unique_id_from_string(expected_unique_id_string);
	char *actual_unique_id_string=otb_unique_id_to_string(unique_id);
	g_assert_cmpstr(expected_unique_id_string, ==, actual_unique_id_string);
	g_free(actual_unique_id_string);
	g_free(unique_id);
	g_free(expected_unique_id_string);
}

void otb_add_unique_id_tests()
{
	otb_add_test_func("/unique-id/test_unique_id_create_compare", test_unique_id_create_compare);
	otb_add_test_func("/unique-id/test_unique_id_duplicate", test_unique_id_duplicate);
	otb_add_test_func("/unique-id/test_unique_id_duplicate_null", test_unique_id_duplicate_null);
	otb_add_test_func("/unique-id/test_unique_id_strings", test_unique_id_strings);
}
