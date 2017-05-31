/**
 * Copyright © 2017 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_TEST_UTILS
#define OTB_TEST_UTILS

#define SHORT_KEY_SIZE_THAT_DOES_NOT_MAKE_UNIT_TESTS_RUN_SLOWLY	256
#define MICROSECONDS_PER_MONTH	2629822965840

void otb_recreate_test_dir(void);
void otb_test_clean_up(void);
const char *otb_get_test_dir_path(void);
char *otb_generate_unique_test_subdir_path(void);
void otb_test_setup_local_crypto(void);
void otb_assert_file_does_not_exist(const char *file_path);
long long otb_few_months_from_now(void);
void otb_initialize_settings_for_tests(void);

#endif
