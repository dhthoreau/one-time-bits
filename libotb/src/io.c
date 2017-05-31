/**
 * Copyright © 2017 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <errno.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <glib/gi18n.h>

static FILE *otb_open_file_with_logging(const char *file_path, const char *mode)
{
	FILE *file=g_fopen(file_path, mode);
	if(G_UNLIKELY(file==NULL))
	{
		int orig_errno=errno;
		g_warning(_("Failed to open file %s. Error == %s"), file_path, strerror(orig_errno));
	}
	return file;
}

FILE *otb_open_binary_for_write(const char *file_path)
{
	return otb_open_file_with_logging(file_path, "wb");
}

FILE *otb_open_binary_for_read(const char *file_path)
{
	return otb_open_file_with_logging(file_path, "rb");
}

FILE *otb_open_text_for_write(const char *file_path)
{
	return otb_open_file_with_logging(file_path, "w");
}

FILE *otb_open_text_for_read(const char *file_path)
{
	return otb_open_file_with_logging(file_path, "r");
}

size_t otb_write(const void *buffer, size_t size, size_t num_items, FILE *file)
{
	size_t ret_val=fwrite(buffer, size, num_items, file);
	if(G_UNLIKELY(ret_val!=num_items))
	{
		int orig_errno=errno;
		g_warning(_("Failed to write file. Error == %s"), strerror(orig_errno));
	}
	return ret_val;
}

size_t otb_read(void *buffer, size_t size, size_t num_items, FILE *file)
{
	size_t ret_val=fread(buffer, size, num_items, file);
	if(G_UNLIKELY(ret_val!=num_items && ferror(file)))
	{
		int orig_errno=errno;
		g_warning(_("Failed to read file. Error == %s"), strerror(orig_errno));
	}
	return ret_val;
}

gboolean otb_close(FILE *file)
{
	gboolean ret_val=TRUE;
	if(G_UNLIKELY(file!=NULL && fclose(file)))
	{
		int orig_errno=errno;
		g_warning(_("Failed close file. Error == %s"), strerror(orig_errno));
		ret_val=FALSE;
	}
	return ret_val;
}

gboolean otb_unlink_if_exists(const char *file_path)
{
	gboolean ret_val=TRUE;
	if(G_UNLIKELY(g_unlink(file_path)!=0 && errno!=ENOENT))
	{
		int orig_errno=errno;
		g_warning(_("Failed delete file %s. Error == %s"), file_path, strerror(orig_errno));
		ret_val=FALSE;
	}
	return ret_val;
}

gboolean otb_mkdir_with_parents(const char *file_path)
{
	gboolean ret_val=TRUE;
	if(G_UNLIKELY(g_mkdir_with_parents(file_path, S_IRUSR | S_IWUSR | S_IRWXU)!=0))
	{
		int orig_errno=errno;
		g_warning(_("Failed create directory %s. Error == %s"), file_path, strerror(orig_errno));
		ret_val=FALSE;
	}
	return ret_val;
}

GDir *otb_open_directory(const char *directory_path)
{
	GError *error=NULL;
	GDir *directory=g_dir_open(directory_path, 0, &error);
	if(G_UNLIKELY(!directory))
	{
		g_warning(_("Failed open directory %s. Error == %s"), directory_path, error->message);
		g_error_free(error);
	}
	return directory;
}

gboolean otb_delete_dir(const char *dir_path)
{
	gboolean ret_val=TRUE;
	GDir *test_dir=g_dir_open(dir_path, 0, NULL);
	if(test_dir!=NULL)
	{
		const char *file_name;
		while((file_name=g_dir_read_name(test_dir))!=NULL)
		{
			char *file_path=g_build_filename(dir_path, file_name, NULL);
			if(g_file_test(file_path, G_FILE_TEST_IS_DIR))
				ret_val=(otb_delete_dir(file_path) && ret_val);
			else
				ret_val=(g_unlink(file_path)==0 && ret_val);
			g_free(file_path);
		}
		g_dir_close(test_dir);
	}
	g_rmdir(dir_path);
	return ret_val;
}
