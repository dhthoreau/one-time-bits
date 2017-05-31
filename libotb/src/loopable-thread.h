/**
 * Copyright © 2017 the OTB team
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
	OtbLoopableThreadPriv *priv;
};

typedef void (*OtbLoopableThreadFunc) (OtbLoopableThread *loopable_thread);

OtbLoopableThread *otb_loopable_thread_new(const unsigned char *name, OtbLoopableThreadFunc loopable_thread_func, void *data, long long looping_interval_microseconds);
OtbLoopableThread *otb_loopable_thread_ref(OtbLoopableThread *loopable_thread);
void *otb_loopable_thread_data(OtbLoopableThread *loopable_thread);
gboolean otb_loopable_thread_continue_looping(OtbLoopableThread *loopable_thread);
void otb_loopable_thread_stop(OtbLoopableThread *loopable_thread);
void otb_loopable_thread_unref(OtbLoopableThread *loopable_thread);

#endif
