/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_IO_H
#define OTB_IO_H

#include <glib-object.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#define otb_file_has_more_bytes(file)	(ungetc(fgetc((file)), (file))!=EOF)

gboolean __otb_dummy_false();
FILE *otb_open_for_write(const char *file_path, const char *function_name);
FILE *otb_open_for_read(const char *file_path, const char *function_name);
size_t otb_write(const void *buffer, size_t size, size_t num_items, FILE *file, const char *function_name);
size_t otb_read(void *buffer, size_t size, size_t num_items, FILE *file, const char *function_name);
gboolean otb_write_byte(unsigned char byte, FILE *file, const char *function_name);
gboolean otb_read_byte(unsigned char *byte, FILE *file, const char *function_name);
gboolean otb_close(FILE *file, const char *function_name);
gboolean otb_unlink_if_exists(const char *file_path, const char *function_name);
off_t otb_get_file_size(const char *file_path, const char *function_name);
gboolean otb_mkdir_with_parents(const char *file_path, const char *function_name);
GDir *otb_open_directory(const char *directory_path, const char *function_name);

#endif
