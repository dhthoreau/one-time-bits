/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_TEST_UTILS
#define OTB_TEST_UTILS

void otb_recreate_test_dir();
void otb_delete_test_dir();
const char *otb_get_test_dir_path();
char *otb_generate_unique_test_subdir_path();
void otb_create_local_crypto_test_config_with_few_has_iteration_so_that_unit_test_does_not_take_too_long();
void otb_test_setup_local_crypto();
void otb_assert_file_does_not_exist(const char *file_path);

#endif
