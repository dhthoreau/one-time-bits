/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <string.h>

volatile void *smemset(volatile void *buffer, int value, int size)
/// This is a hack to bypass compiler optimizations that remove memset() calls entirely. Not good when you wanted to call memset() to zero out sensitive information in memory!
{
	for(volatile unsigned char *buffPtr=buffer; (void*)buffPtr-buffer<size; *buffPtr++=value);
	return buffer;
}

int smemcmp(const void *buffer1, const void *buffer2, size_t size)
/// This to ensure that the memcmp executes every byte, no short circuiting, no optimizations. Slow compares prevent timing attacks on short circuited comparisons, where longer times indicate better matches then shorter times. So far it's only used to compare password hashes, which probably doesn't improve security, but what the heck: it can't hurt!
{
	volatile int retVal=0;
	const unsigned char *buffPtr1;
	const unsigned char *buffPtr2;
	for(buffPtr1=buffer1, buffPtr2=buffer2; (void*)buffPtr1-buffer1<size; buffPtr1++, buffPtr2++)
	{
		volatile int compare=*buffPtr1-*buffPtr2;
		retVal=(retVal?retVal:compare);
	}
	return retVal;
}
