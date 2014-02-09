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
// This is a hack to bypass compiler optimizations that remove memset() calls entirely. Not good when you wanted to call memset() to zero out sensitive information in memory!
{
	while(size--)
		((char*)buffer)[size]=value;
	return buffer;
}
