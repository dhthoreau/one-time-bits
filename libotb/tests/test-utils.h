/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_TEST_UTILS
#define OTB_TEST_UTILS

#define MICROSECONDS_PER_MONTH	2629822965840

void otb_recreate_test_dir();
void otb_test_clean_up();
const char *otb_get_test_dir_path();
char *otb_generate_unique_test_subdir_path();
void otb_create_local_crypto_test_config_with_few_has_iteration_so_that_unit_test_does_not_take_too_long();
void otb_test_setup_local_crypto();
void otb_assert_file_does_not_exist(const char *file_path);
long long otb_few_months_from_now();
void otb_initialize_settings_for_tests();

#endif
