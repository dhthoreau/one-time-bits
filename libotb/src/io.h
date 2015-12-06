/**
 * Copyright © 2015 the OTB team
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

FILE *otb_open_binary_for_write(const char *file_path);
FILE *otb_open_binary_for_read(const char *file_path);
FILE *otb_open_text_for_write(const char *file_path);
size_t otb_write(const void *buffer, size_t size, size_t num_items, FILE *file);
size_t otb_read(void *buffer, size_t size, size_t num_items, FILE *file);
gboolean otb_close(FILE *file);
gboolean otb_unlink_if_exists(const char *file_path);
gboolean otb_mkdir_with_parents(const char *file_path);
GDir *otb_open_directory(const char *directory_path);
gboolean otb_delete_dir(const char *dir_path);

#endif
