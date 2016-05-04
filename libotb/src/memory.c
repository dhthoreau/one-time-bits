/**
 * Copyright © 2015 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <glib.h>
#include <glib/gi18n.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

int otb_smemcmp(const void *buffer1, const void *buffer2, size_t size)
/// This to ensure that the memcmp executes every byte, no short circuiting, no optimizations. Slow compares prevent timing attacks on short circuited comparisons, where longer times indicate better matches then shorter times. So far it's only used to compare password hashes, which probably doesn't improve security, but what the heck: it can't hurt!
{
	int retVal=0;
	const unsigned char *buffPtr1;
	const unsigned char *buffPtr2;
	for(buffPtr1=buffer1, buffPtr2=buffer2; buffPtr1-(const unsigned char *)buffer1<size; buffPtr1++, buffPtr2++)
	{
		int compare=*buffPtr1-*buffPtr2;
		retVal=(retVal?retVal:compare);
	}
	return retVal;
}

static unsigned int otb_mlock_hash(const void *key)
{
	return (unsigned int)key;
}

static gboolean otb_mlock_equality(const void *value1, const void *value2)
{
	return value1==value2;
}

static GHashTable *otb_allocation_sizes=NULL;
#ifdef HAVE_UNISTD_H
static GHashTable *otb_locked_pages=NULL;
#endif

static void otb_mlock_initialize_hash_tables()
{
	static long otb_mlock_hash_tables_initialized=FALSE;
	if(G_UNLIKELY(g_once_init_enter(&otb_mlock_hash_tables_initialized)))
	{
		otb_allocation_sizes=g_hash_table_new_full(otb_mlock_hash, otb_mlock_equality, NULL, g_free);
#ifdef HAVE_UNISTD_H
		otb_locked_pages=g_hash_table_new_full(otb_mlock_hash, otb_mlock_equality, NULL, g_free);
#endif
		g_once_init_leave(&otb_mlock_hash_tables_initialized, TRUE);
	}
}

static GMutex otb_mlock_hash_tables_mutex;

#define otb_mlock_hash_tables_lock()	g_mutex_lock(&otb_mlock_hash_tables_mutex)
#define otb_mlock_hash_tables_unlock()	g_mutex_unlock(&otb_mlock_hash_tables_mutex)

#ifdef HAVE_UNISTD_H
void otb_mlock_page(void *page)
{
	size_t *lock_count=NULL;
	if(g_hash_table_contains(otb_locked_pages, page))
	{
		lock_count=g_hash_table_lookup(otb_locked_pages, page);
		(*lock_count)++;
	}
	else if(mlock(page, sysconf(_SC_PAGESIZE))==0)
	{
		lock_count=g_new(size_t, 1);
		*lock_count=1;
		if(G_UNLIKELY(!g_hash_table_insert(otb_locked_pages, page, lock_count)))
			g_error(_("Failed to add locked page to hash table."));
	}
}

void otb_mlock(void *memory, size_t size)
{
	uintptr_t page_size=sysconf(_SC_PAGESIZE);
	if(page_size>0)
	{
		const void *page_max=(const unsigned char*)memory+size;
		void *page=(void*)((uintptr_t)memory-(uintptr_t)memory%page_size);
		do
		{
			otb_mlock_page(page);
			page=(unsigned char*)page+page_size;
		}
		while(page<page_max);
	}
}

void otb_munlock_page(const void *page)
{
	if(g_hash_table_contains(otb_locked_pages, page))
	{
		size_t *lock_count=g_hash_table_lookup(otb_locked_pages, page);
		(*lock_count)--;
		if(*lock_count==0)
		{
			if(G_UNLIKELY(!g_hash_table_remove(otb_locked_pages, page)))
				g_error(_("Locked page already exists in hash table. Likely cause is calling free() instead of otb_free_locked()."));
			if(munlock(page, sysconf(_SC_PAGESIZE))!=0)
				g_error(_("otb_munlock_page() failed."));
		}
	}
}

void otb_munlock(const void *memory, size_t size)
{
	uintptr_t page_size=sysconf(_SC_PAGESIZE);
	if(page_size>0)
	{
		void *page_max=(unsigned char*)memory+size;
		void *page=(void *)((uintptr_t)memory-(uintptr_t)memory%page_size);
		do
		{
			otb_munlock_page(page);
			page=(unsigned char*)page+page_size;
		}
		while(page<page_max);
	}
}
#endif

static void otb_mlock_record_allocation_size(void *memory, size_t size)
{
	size_t *size_for_hash_table=g_new(size_t, 1);
	*size_for_hash_table=size;
	if(G_UNLIKELY(!g_hash_table_insert(otb_allocation_sizes, memory, size_for_hash_table)))
		g_error(_("Memory already exists in hash table. Likely cause is calling free() instead of otb_free_locked()."));
}

void *otb_malloc_locked(size_t size)
{
	otb_mlock_hash_tables_lock();
	otb_mlock_initialize_hash_tables();
	void *memory=g_malloc(size);
	if(memory!=NULL)
	{
		otb_mlock_record_allocation_size(memory, size);
#ifdef HAVE_UNISTD_H
		otb_mlock(memory, size);
#endif
	}
	otb_mlock_hash_tables_unlock();
	return memory;
}

static size_t otb_mlock_release_allocation_size(const void *memory)
{
	size_t size=*(size_t*)g_hash_table_lookup(otb_allocation_sizes, memory);
	if(G_UNLIKELY(!g_hash_table_remove(otb_allocation_sizes, memory)))
		g_error(_("Failed to remove memory from hash table."));
	return size;
}

void *otb_smemset(void *buffer, int value, size_t size)
/// This is a hack to bypass compiler optimizations that remove memset() calls entirely. Not good when you wanted to call memset() to zero out sensitive information in memory!
{
	for(unsigned char *buffPtr=buffer; buffPtr-(unsigned char *)buffer<size; *buffPtr++=value);
	return buffer;
}

void otb_free_locked(void *memory)
{
	if(memory!=NULL)
	{
		otb_mlock_hash_tables_lock();
		size_t size=otb_mlock_release_allocation_size(memory);
		otb_smemset(memory, 0, size);
		g_free(memory);
#ifdef HAVE_UNISTD_H
		otb_munlock(memory, size);
#endif
		otb_mlock_hash_tables_unlock();
	}
}
