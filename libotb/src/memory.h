/**
 * Copyright © 2015 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

int otb_smemcmp(const void *buffer1, const void *buffer2, size_t size);
void otb_mlock(const void* address, size_t size);
void otb_munlock(const void* address, size_t size);
void *otb_malloc_locked(size_t size);
void otb_free_locked(void *memory);
