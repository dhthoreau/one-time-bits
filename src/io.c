/**
 * Copyright © 2014 the OTB team
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

static FILE *otb_open_file_with_logging(const char *file_path, const char *function_name, const char *mode)
{
	FILE *file=g_fopen(file_path, mode);
	if(file==NULL)
	{
		int orig_errno=errno;
		g_warning(_("%s: Failed to open file %s. Error == %s"), function_name, file_path, strerror(orig_errno));
	}
	return file;
}

FILE *otb_open_for_write(const char *file_path, const char *function_name)
{
	return otb_open_file_with_logging(file_path, function_name, "wb");
}

FILE *otb_open_for_read(const char *file_path, const char *function_name)
{
	return otb_open_file_with_logging(file_path, function_name, "rb");
}

size_t otb_write(const void *buffer, size_t size, size_t num_items, FILE *file, const char *function_name)
{
	size_t ret_val=fwrite(buffer, size, num_items, file);
	if(ret_val!=num_items)
	{
		int orig_errno=errno;
		g_warning(_("%s: Failed to write file. Error == %s"), function_name, strerror(orig_errno));
	}
	return ret_val;
}

gboolean otb_write_byte(unsigned char byte, FILE *file, const char *function_name)
{
	gboolean ret_val=TRUE;
	int put_result=fputc(byte, file);
	if(put_result==EOF)
	{
		int orig_errno=errno;
		g_warning(_("%s: Failed to write byte to file. Error == %s"), function_name, strerror(orig_errno));
		ret_val=FALSE;
	}
	return ret_val;
}

size_t otb_read(void *buffer, size_t size, size_t num_items, FILE *file, const char *function_name)
{
	size_t ret_val=fread(buffer, size, num_items, file);
	if(ret_val!=num_items && ferror(file))
	{
		int orig_errno=errno;
		g_warning(_("%s: Failed to read file. Error == %s"), function_name, strerror(orig_errno));
	}
	return ret_val;
}

gboolean otb_read_byte(unsigned char *byte, FILE *file, const char *function_name)
{
	gboolean ret_val=TRUE;
	int get_result=fgetc(file);
	if(get_result==EOF)
	{
		int orig_errno=errno;
		g_warning(_("%s: Failed read byte from file, or tried to read past the end of the file. Error == %s"), function_name, strerror(orig_errno));
		ret_val=FALSE;
	}
	else
		*byte=get_result;
	return ret_val;
}

gboolean otb_close(FILE *file, const char *function_name)
{
	gboolean ret_val=TRUE;
	if(file!=NULL && fclose(file))
	{
		int orig_errno=errno;
		g_warning(_("%s: Failed close file. Error == %s"), function_name, strerror(orig_errno));
		ret_val=FALSE;
	}
	return ret_val;
}

gboolean otb_unlink_if_exists(const char *file_path, const char *function_name)
{
	gboolean ret_val=TRUE;
	if(g_unlink(file_path)!=0 && errno!=ENOENT)
	{
		int orig_errno=errno;
		g_warning(_("%s: Failed delete file %s. Error == %s"), function_name, file_path, strerror(orig_errno));
		ret_val=FALSE;
	}
	return ret_val;
}

off_t otb_get_file_size(const char *file_path, const char *function_name)
{
	off_t file_size;
	struct stat file_stat;
	if(stat(file_path, &file_stat)==0)
		file_size=file_stat.st_size;
	else
	{
		int orig_errno=errno;
		g_warning(_("%s: Failed to read status of file %s. Error == %s"), function_name, file_path, strerror(orig_errno));
		file_size=-1;
	}
	return file_size;
}

gboolean otb_mkdir_with_parents(const char *file_path, const char *function_name)
{
	gboolean ret_val=TRUE;
	if(g_mkdir_with_parents(file_path, S_IRUSR | S_IWUSR | S_IRWXU)!=0)
	{
		int orig_errno=errno;
		g_warning(_("%s: Failed create directory %s. Error == %s"), file_path, file_path, strerror(orig_errno));
		ret_val=FALSE;
	}
	return ret_val;
}

GDir *otb_open_directory(const char *directory_path, const char *function_name)
{
	GError *error=NULL;
	GDir *directory=g_dir_open(directory_path, 0, &error);
	if(!directory)
	{
		g_warning(_("%s: Failed open directory %s. Error == %s"), function_name, directory_path, error->message);
		g_error_free(error);
	}
	return directory;
}
