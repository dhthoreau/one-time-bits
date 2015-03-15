/**
 * Copyright © 2014 the OTB team
 * 
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the COPYING file for more details.
 **/

#include "../config.h"

#include <glib.h>

#include "loopable-thread.h"

struct _OtbLoopableThreadPriv
{
	int ref_count;
	OtbLoopableThreadFunc loopable_thread_func;
	long long looping_interval;
	GMutex mutex;
	GCond cond;
	GThread *thread;
};

void *otb_loopable_thread_loop(OtbLoopableThread *loopable_thread)
{
	g_mutex_lock(&loopable_thread->priv->mutex);
	while(loopable_thread->continue_looping)
	{
		loopable_thread->priv->loopable_thread_func(loopable_thread);
		otb_loopable_thread_yield(loopable_thread, loopable_thread->priv->looping_interval);
	}
	g_mutex_unlock(&loopable_thread->priv->mutex);
	return NULL;
}

OtbLoopableThread *otb_loopable_thread_new(const unsigned char *name, OtbLoopableThreadFunc loopable_thread_func, void *data, long long looping_interval)
{
	OtbLoopableThread *loopable_thread=g_slice_new(OtbLoopableThread);
	loopable_thread->priv=g_slice_new(OtbLoopableThreadPriv);
	loopable_thread->priv->ref_count=1;
	loopable_thread->priv->loopable_thread_func=loopable_thread_func;
	loopable_thread->priv->looping_interval=looping_interval;
	g_mutex_init(&loopable_thread->priv->mutex);
	g_cond_init(&loopable_thread->priv->cond);
	loopable_thread->continue_looping=TRUE;
	loopable_thread->data=data;
	loopable_thread->priv->thread=g_thread_new(name, (GThreadFunc)otb_loopable_thread_loop, loopable_thread);
	return loopable_thread;
}

OtbLoopableThread *otb_loopable_thread_ref(OtbLoopableThread *loopable_thread)
{
	g_return_val_if_fail(loopable_thread!=NULL, NULL);
	g_atomic_int_inc(&loopable_thread->priv->ref_count);
	return loopable_thread;
}

void otb_loopable_thread_yield(OtbLoopableThread *loopable_thread, long long interval)
{
	long long end_time=g_get_monotonic_time()+loopable_thread->priv->looping_interval;
	while(g_get_monotonic_time()<end_time && loopable_thread->continue_looping)
		g_cond_wait_until(&loopable_thread->priv->cond, &loopable_thread->priv->mutex, end_time);
}

void otb_loopable_thread_stop(OtbLoopableThread *loopable_thread)
{
	g_mutex_lock(&loopable_thread->priv->mutex);
	loopable_thread->continue_looping=FALSE;
	g_cond_signal(&loopable_thread->priv->cond);
	g_mutex_unlock(&loopable_thread->priv->mutex);
	g_thread_join(loopable_thread->priv->thread);
	otb_loopable_thread_unref(loopable_thread);
}

void otb_loopable_thread_unref(OtbLoopableThread *loopable_thread)
{
	if(loopable_thread!=NULL && g_atomic_int_dec_and_test(&loopable_thread->priv->ref_count))
	{
		g_cond_clear(&loopable_thread->priv->cond);
		g_mutex_clear(&loopable_thread->priv->mutex);
		g_slice_free(OtbLoopableThreadPriv, loopable_thread->priv);
		g_slice_free(OtbLoopableThread, loopable_thread);
	}
}
