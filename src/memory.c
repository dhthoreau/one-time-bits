/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <glib.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

volatile void *otb_smemset(volatile void *buffer, int value, size_t size)
/// This is a hack to bypass compiler optimizations that remove memset() calls entirely. Not good when you wanted to call memset() to zero out sensitive information in memory!
{
	for(volatile unsigned char *buffPtr=buffer; buffPtr-(volatile unsigned char *)buffer<size; *buffPtr++=value);
	return buffer;
}

int otb_smemcmp(const void *buffer1, const void *buffer2, size_t size)
/// This to ensure that the memcmp executes every byte, no short circuiting, no optimizations. Slow compares prevent timing attacks on short circuited comparisons, where longer times indicate better matches then shorter times. So far it's only used to compare password hashes, which probably doesn't improve security, but what the heck: it can't hurt!
{
	volatile int retVal=0;
	const unsigned char *buffPtr1;
	const unsigned char *buffPtr2;
	for(buffPtr1=buffer1, buffPtr2=buffer2; buffPtr1-(const unsigned char *)buffer1<size; buffPtr1++, buffPtr2++)
	{
		volatile int compare=*buffPtr1-*buffPtr2;
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

static GHashTable *otb_locked_pages=NULL;

static void otb_mlock_initialize_hash_table()
{
	static gboolean otb_mlock_hash_table_initialized=FALSE;
	if(g_once_init_enter(&otb_mlock_hash_table_initialized))
	{
		otb_locked_pages=g_hash_table_new_full(otb_mlock_hash, otb_mlock_equality, NULL, g_free);
		g_once_init_leave(&otb_mlock_hash_table_initialized, TRUE);
	}
}

static GMutex otb_mlock_hash_table_mutex;

void otb_mlock_page(void *page)
{
	size_t *lock_count=NULL;
	if(g_hash_table_contains(otb_locked_pages, page))
	{
		lock_count=g_hash_table_lookup(otb_locked_pages, page);
		*lock_count++;
	}
	else if(mlock(page, 1)==0)
	{
		lock_count=g_malloc(sizeof *lock_count);
		*lock_count=1;
		g_hash_table_insert(otb_locked_pages, page, lock_count);
	}
}

#define otb_mlock_hash_table_lock()		g_mutex_lock(&otb_mlock_hash_table_mutex)
#define otb_mlock_hash_table_unlock()	g_mutex_unlock(&otb_mlock_hash_table_mutex)

void otb_mlock(const void *memory, size_t size)
{
#ifdef HAVE_UNISTD_H
	uintptr_t page_size=sysconf(_SC_PAGESIZE);
	if(page_size>0)
	{
		otb_mlock_initialize_hash_table();
		const void *page_max=(const unsigned char*)memory+size;
		void *page=(void*)((uintptr_t)memory-(uintptr_t)memory % page_size);
		otb_mlock_hash_table_lock();
		do
		{
			otb_mlock_page(page);
			page=(unsigned char*)page+page_size;
		}
		while(page<page_max);
		otb_mlock_hash_table_unlock();
	}
#endif
}

void otb_munlock_page(const void *page)
{
	size_t *lock_count=NULL;
	if(g_hash_table_contains(otb_locked_pages, page))
	{
		lock_count=g_hash_table_lookup(otb_locked_pages, page);
		*lock_count--;
		if(*lock_count==0)
		{
			g_hash_table_remove(otb_locked_pages, page);
			munlock(page, 1);
		}
	}
}

void otb_munlock(const void *memory, size_t size)
{
#ifdef HAVE_UNISTD_H
	uintptr_t page_size=sysconf(_SC_PAGESIZE);
	if(page_size>0)
	{
		otb_mlock_initialize_hash_table();
		void *page_max=(unsigned char*)memory+size;
		void *page=(void *)((uintptr_t)memory-(uintptr_t)memory % page_size);
		otb_mlock_hash_table_lock();
		do
		{
			otb_munlock_page(page);
			page=(unsigned char*)page+page_size;
		}
		while(page<page_max);
		otb_mlock_hash_table_unlock();
	}
#endif
}

void *otb_malloc_locked(size_t size)
{
	void *memory=g_malloc(size);
	otb_mlock(memory, size);
	return memory;
}

void otb_free_locked(void *memory, size_t size)
{
	otb_smemset(memory, 0, size);
	g_free(memory);
	otb_munlock(memory, size);
}
