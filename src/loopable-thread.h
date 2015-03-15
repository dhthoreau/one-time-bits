/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#ifndef OTB_LOOPABLE_THREAD_H
#define OTB_LOOPABLE_THREAD_H

typedef struct _OtbLoopableThread OtbLoopableThread;
typedef struct _OtbLoopableThreadPriv OtbLoopableThreadPriv;

struct _OtbLoopableThread
{
	gboolean continue_looping;
	void *data;
	OtbLoopableThreadPriv *priv;
};

typedef void (*OtbLoopableThreadFunc) (OtbLoopableThread *loopable_thread);

OtbLoopableThread *otb_loopable_thread_new(const unsigned char *name, OtbLoopableThreadFunc loopable_thread_func, void *data, long long looping_interval_microseconds);
OtbLoopableThread *otb_loopable_thread_ref(OtbLoopableThread *loopable_thread);
void otb_loopable_thread_yield(OtbLoopableThread *loopable_thread, long long interval_microseconds);
void otb_loopable_thread_stop(OtbLoopableThread *loopable_thread);
void otb_loopable_thread_unref(OtbLoopableThread *loopable_thread);

#endif
