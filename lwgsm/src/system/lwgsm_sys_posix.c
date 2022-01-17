/**
 * \file            lwgsm_sys_template.c
 * \brief           System dependant functions
 */

/*
 * Copyright (c) 2020 Tilen MAJERLE
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE
 * AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Author:          Tilen MAJERLE <tilen@majerle.eu>
 * Version:         v0.1.0
 */
#include "system/lwgsm_sys.h"
//#include "cmsis_os.h"
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>

typedef void* (*lwesp_sys_posix_thread_fn) (void*);

/* Mutex ID for main protection */
static pthread_mutex_t sys_mutex;
static pthread_mutexattr_t sys_mutex_attr;

/**
 * \brief           Custom message queue implementation for WIN32
 */
typedef struct {
    lwgsm_sys_sem_t sem_not_empty;              /*!< Semaphore indicates not empty */
    lwgsm_sys_sem_t sem_not_full;               /*!< Semaphore indicates not full */
    lwgsm_sys_sem_t sem;                        /*!< Semaphore to lock access */
    size_t in, out, size;
    void* entries[1];
} posix_mbox_t;

/**
 * \brief           Check if message box is full
 * \param[in]       m: Message box handle
 * \return          1 if full, 0 otherwise
 */
static uint8_t
mbox_is_full(posix_mbox_t* m) {
    size_t size = 0;
    if (m->in > m->out) {
        size = (m->in - m->out);
    } else if (m->out > m->in) {
        size = m->size - m->out + m->in;
    }
    return size == m->size - 1;
}

/**
 * \brief           Check if message box is empty
 * \param[in]       m: Message box handle
 * \return          1 if empty, 0 otherwise
 */
static uint8_t
mbox_is_empty(posix_mbox_t* m) {
    return m->in == m->out;
}

/**
 * \brief           Init system dependant parameters
 *
 * After this function is called,
 * all other system functions must be fully ready.
 *
 * \return          `1` on success, `0` otherwise
 */
uint8_t
lwgsm_sys_init(void) {
	if (pthread_mutexattr_init(&sys_mutex_attr) != 0) {
	        return 0;
	    }

	    if (pthread_mutexattr_settype(&sys_mutex_attr, PTHREAD_MUTEX_RECURSIVE) != 0) {
	        return 0;
	    }

	    /* pthread_mutex_init return 0 on success */
	    if (pthread_mutex_init(&sys_mutex, &sys_mutex_attr) != 0) {
	        return 0;
	    }

	    return 1;
}

/**
 * \brief           Get current time in units of milliseconds
 * \return          Current time in units of milliseconds
 */
uint32_t
lwgsm_sys_now(void) {
	struct timespec tp;
	    if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0) {
	        return 0;
	    }
	    uint32_t msec = (tp.tv_sec * 1000 + tp.tv_nsec / 1000000) \
	                    & 0xFFFFFFFFU;

	    return msec;
}

/**
 * \brief           Protect middleware core
 *
 * Stack protection must support recursive mode.
 * This function may be called multiple times,
 * even if access has been granted before.
 *
 * \note            Most operating systems support recursive mutexes.
 * \return          `1` on success, `0` otherwise
 */
uint8_t
lwgsm_sys_protect(void) {
	pthread_mutex_lock(&sys_mutex);
	    return 1;
}

/**
 * \brief           Unprotect middleware core
 *
 * This function must follow number of calls of \ref lwgsm_sys_protect
 * and unlock access only when counter reached back zero.
 *
 * \note            Most operating systems support recursive mutexes.
 * \return          `1` on success, `0` otherwise
 */
uint8_t
lwgsm_sys_unprotect(void) {
	pthread_mutex_unlock(&sys_mutex);
	    return 1;
}

/**
 * \brief           Create new recursive mutex
 * \note            Recursive mutex has to be created as it may be locked multiple times before unlocked
 * \param[out]      p: Pointer to mutex structure to allocate
 * \return          `1` on success, `0` otherwise
 */
uint8_t
lwgsm_sys_mutex_create(lwgsm_sys_mutex_t* p) {
	*p = malloc(sizeof(pthread_mutex_t));
	    if (*p == NULL) {
	        return 0;
	    }

	    if (pthread_mutex_init(*p, NULL) != 0) {
	        free(*p);
	        return 0;
	    }
	    return 1;
}

/**
 * \brief           Delete recursive mutex from system
 * \param[in]       p: Pointer to mutex structure
 * \return          `1` on success, `0` otherwise
 */
uint8_t
lwgsm_sys_mutex_delete(lwgsm_sys_mutex_t* p) {
	if (pthread_mutex_destroy(*p) != 0) {
	        return 0;
	    }

	    free(*p);

	    return 1;
}

/**
 * \brief           Lock recursive mutex, wait forever to lock
 * \param[in]       p: Pointer to mutex structure
 * \return          `1` on success, `0` otherwise
 */
uint8_t
lwgsm_sys_mutex_lock(lwgsm_sys_mutex_t* p) {
	if (pthread_mutex_lock(*p) != 0) {
	        return 0;
	    }
	    return 1;
}

/**
 * \brief           Unlock recursive mutex
 * \param[in]       p: Pointer to mutex structure
 * \return          `1` on success, `0` otherwise
 */
uint8_t
lwgsm_sys_mutex_unlock(lwgsm_sys_mutex_t* p) {
	if (pthread_mutex_unlock(*p) != 0) {
	        return 0;
	    }
	    return 1;
}

/**
 * \brief           Check if mutex structure is valid system
 * \param[in]       p: Pointer to mutex structure
 * \return          `1` on success, `0` otherwise
 */
uint8_t
lwgsm_sys_mutex_isvalid(lwgsm_sys_mutex_t* p) {
	if (p == NULL || *p == NULL) {
	        return 0;
	    }
	    return 1;
}

/**
 * \brief           Set recursive mutex structure as invalid
 * \param[in]       p: Pointer to mutex structure
 * \return          `1` on success, `0` otherwise
 */
uint8_t
lwgsm_sys_mutex_invalid(lwgsm_sys_mutex_t* p) {
	*p = NULL;
	    return 1;
}

/**
 * \brief           Create a new binary semaphore and set initial state
 * \note            Semaphore may only have `1` token available
 * \param[out]      p: Pointer to semaphore structure to fill with result
 * \param[in]       cnt: Count indicating default semaphore state:
 *                     `0`: Take semaphore token immediately
 *                     `1`: Keep token available
 * \return          `1` on success, `0` otherwise
 */
uint8_t
lwgsm_sys_sem_create(lwgsm_sys_sem_t* p, uint8_t cnt) {
	*p = malloc(sizeof(sem_t));
	    if (*p == NULL) {
	        return 0;
	    }

	    /* sem_init returns 0 on success
	    * This function assumes a binary semaphore
	    * should be created in some ports.
	    */
	    if (sem_init(*p, 0, !!cnt) != 0) {
	        free(*p);
	        return 0;
	    }
	    return 1;
}

/**
 * \brief           Delete binary semaphore
 * \param[in]       p: Pointer to semaphore structure
 * \return          `1` on success, `0` otherwise
 */
uint8_t
lwgsm_sys_sem_delete(lwgsm_sys_sem_t* p) {
	if (sem_destroy(*p) != 0) {
	        return 0;
	    }

	    free(*p);

	    return 1;
}

/**
 * \brief           Wait for semaphore to be available
 * \param[in]       p: Pointer to semaphore structure
 * \param[in]       timeout: Timeout to wait in milliseconds. When `0` is applied, wait forever
 * \return          Number of milliseconds waited for semaphore to become available or
 *                      \ref LWGSM_SYS_TIMEOUT if not available within given time
 */
uint32_t
lwgsm_sys_sem_wait(lwgsm_sys_sem_t* p, uint32_t timeout) {
	struct timespec ts;
	    int ret;

	    uint32_t t_start = lwgsm_sys_now();

	    /* Note that timedwait requires CLOCK_REALTIME, not CLOCK_MONOTONIC. */
	    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
	        return 0;
	    }

	    if (timeout == 0) {
	        ret = sem_wait(*p);
	    } else {
	        /* Calculate new timespec values based on timeout. */
	        time_t timeout_sec = timeout / 1000;
	        time_t timeout_nsec = (timeout % 1000) * 1000000; /* 1E6 */
	        ts.tv_sec += timeout_sec;
	        ts.tv_nsec += timeout_nsec;
	        if (ts.tv_nsec > 1000000000) { /* 1E9 */
	            ts.tv_sec += 1;
	            ts.tv_nsec -= 1000000000;
	        }

	        ret = sem_timedwait(*p, &ts);
	    }

	    if (ret != 0) {
	        return LWGSM_SYS_TIMEOUT;
	    }
	    return lwgsm_sys_now() - t_start;
}

/**
 * \brief           Release semaphore
 * \param[in]       p: Pointer to semaphore structure
 * \return          `1` on success, `0` otherwise
 */
uint8_t
lwgsm_sys_sem_release(lwgsm_sys_sem_t* p) {
	if (sem_post(*p) != 0) {
	        return 0;
	    }
	    return 1;
}

/**
 * \brief           Check if semaphore is valid
 * \param[in]       p: Pointer to semaphore structure
 * \return          `1` on success, `0` otherwise
 */
uint8_t
lwgsm_sys_sem_isvalid(lwgsm_sys_sem_t* p) {
	if (p == NULL || *p == NULL) {
	        return 0;
	    }
	    return 1;
}

/**
 * \brief           Invalid semaphore
 * \param[in]       p: Pointer to semaphore structure
 * \return          `1` on success, `0` otherwise
 */
uint8_t
lwgsm_sys_sem_invalid(lwgsm_sys_sem_t* p) {
	*p = NULL;

	    return 1;
}

/**
 * \brief           Create a new message queue with entry type of `void *`
 * \param[out]      b: Pointer to message queue structure
 * \param[in]       size: Number of entries for message queue to hold
 * \return          `1` on success, `0` otherwise
 */
uint8_t
lwgsm_sys_mbox_create(lwgsm_sys_mbox_t* b, size_t size) {
	posix_mbox_t* mbox;

	    *b = 0;

	    mbox = malloc(sizeof(*mbox) + size * sizeof(void*));
	    if (mbox != NULL) {
	        memset(mbox, 0x00, sizeof(*mbox));
	        mbox->size = size + 1;                  /* Set it to 1 more as cyclic buffer has only one less than size */
	        lwgsm_sys_sem_create(&mbox->sem, 1);
	        lwgsm_sys_sem_create(&mbox->sem_not_empty, 0);
	        lwgsm_sys_sem_create(&mbox->sem_not_full, 0);
	        *b = mbox;
	    }
	    return *b != NULL;
}

/**
 * \brief           Delete message queue
 * \param[in]       b: Pointer to message queue structure
 * \return          `1` on success, `0` otherwise
 */
uint8_t
lwgsm_sys_mbox_delete(lwgsm_sys_mbox_t* b) {
	posix_mbox_t* mbox = *b;
	    lwgsm_sys_sem_delete(&mbox->sem);
	    lwgsm_sys_sem_delete(&mbox->sem_not_full);
	    lwgsm_sys_sem_delete(&mbox->sem_not_empty);
	    free(mbox);
	    return 1;
}

/**
 * \brief           Put a new entry to message queue and wait until memory available
 * \param[in]       b: Pointer to message queue structure
 * \param[in]       m: Pointer to entry to insert to message queue
 * \return          Time in units of milliseconds needed to put a message to queue
 */
uint32_t
lwgsm_sys_mbox_put(lwgsm_sys_mbox_t* b, void* m) {
	posix_mbox_t* mbox = *b;
	    uint32_t time = lwgsm_sys_now();            /* Get start time */

	    lwgsm_sys_sem_wait(&mbox->sem, 0);          /* Wait for access */

	    /*
	     * Since function is blocking until ready to write something to queue,
	     * wait and release the semaphores to allow other threads
	     * to process the queue before we can write new value.
	     */
	    while (mbox_is_full(mbox)) {
	        lwgsm_sys_sem_release(&mbox->sem);      /* Release semaphore */
	        lwgsm_sys_sem_wait(&mbox->sem_not_full, 0); /* Wait for semaphore indicating not full */
	        lwgsm_sys_sem_wait(&mbox->sem, 0);      /* Wait availability again */
	    }
	    mbox->entries[mbox->in] = m;
	    if (++mbox->in >= mbox->size) {
	        mbox->in = 0;
	    }
	    lwgsm_sys_sem_release(&mbox->sem_not_empty);/* Signal non-empty state */
	    lwgsm_sys_sem_release(&mbox->sem);          /* Release access for other threads */
	    return lwgsm_sys_now() - time;
}

/**
 * \brief           Get a new entry from message queue with timeout
 * \param[in]       b: Pointer to message queue structure
 * \param[in]       m: Pointer to pointer to result to save value from message queue to
 * \param[in]       timeout: Maximal timeout to wait for new message. When `0` is applied, wait for unlimited time
 * \return          Time in units of milliseconds needed to put a message to queue
 *                      or \ref LWGSM_SYS_TIMEOUT if it was not successful
 */
uint32_t
lwgsm_sys_mbox_get(lwgsm_sys_mbox_t* b, void** m, uint32_t timeout) {
	posix_mbox_t* mbox = *b;
	    uint32_t time;

	    time = lwgsm_sys_now();

	    /* Get exclusive access to message queue */
	    if (lwgsm_sys_sem_wait(&mbox->sem, timeout) == LWGSM_SYS_TIMEOUT) {
	        return LWGSM_SYS_TIMEOUT;
	    }
	    while (mbox_is_empty(mbox)) {
	        lwgsm_sys_sem_release(&mbox->sem);
	        if (lwgsm_sys_sem_wait(&mbox->sem_not_empty, timeout) == LWGSM_SYS_TIMEOUT) {
	            return LWGSM_SYS_TIMEOUT;
	        }
	        lwgsm_sys_sem_wait(&mbox->sem, timeout);
	    }
	    *m = mbox->entries[mbox->out];
	    if (++mbox->out >= mbox->size) {
	        mbox->out = 0;
	    }
	    lwgsm_sys_sem_release(&mbox->sem_not_full);
	    lwgsm_sys_sem_release(&mbox->sem);

	    return lwgsm_sys_now() - time;
}

/**
 * \brief           Put a new entry to message queue without timeout (now or fail)
 * \param[in]       b: Pointer to message queue structure
 * \param[in]       m: Pointer to message to save to queue
 * \return          `1` on success, `0` otherwise
 */
uint8_t
lwgsm_sys_mbox_putnow(lwgsm_sys_mbox_t* b, void* m) {
	posix_mbox_t* mbox = *b;

	    lwgsm_sys_sem_wait(&mbox->sem, 0);
	    if (mbox_is_full(mbox)) {
	        lwgsm_sys_sem_release(&mbox->sem);
	        return 0;
	    }
	    mbox->entries[mbox->in] = m;
	    if (mbox->in == mbox->out) {
	        lwgsm_sys_sem_release(&mbox->sem_not_empty);
	    }
	    if (++mbox->in >= mbox->size) {
	        mbox->in = 0;
	    }
	    lwgsm_sys_sem_release(&mbox->sem);
	    return 1;
}

/**
 * \brief           Get an entry from message queue immediately
 * \param[in]       b: Pointer to message queue structure
 * \param[in]       m: Pointer to pointer to result to save value from message queue to
 * \return          `1` on success, `0` otherwise
 */
uint8_t
lwgsm_sys_mbox_getnow(lwgsm_sys_mbox_t* b, void** m) {
	posix_mbox_t* mbox = *b;

	    lwgsm_sys_sem_wait(&mbox->sem, 0);          /* Wait exclusive access */
	    if (mbox->in == mbox->out) {
	        lwgsm_sys_sem_release(&mbox->sem);      /* Release access */
	        return 0;
	    }

	    *m = mbox->entries[mbox->out];
	    if (++mbox->out >= mbox->size) {
	        mbox->out = 0;
	    }
	    lwgsm_sys_sem_release(&mbox->sem_not_full); /* Queue not full anymore */
	    lwgsm_sys_sem_release(&mbox->sem);          /* Release semaphore */
	    return 1;
}

/**
 * \brief           Check if message queue is valid
 * \param[in]       b: Pointer to message queue structure
 * \return          `1` on success, `0` otherwise
 */
uint8_t
lwgsm_sys_mbox_isvalid(lwgsm_sys_mbox_t* b) {
	return b != NULL && *b != NULL;
}

/**
 * \brief           Invalid message queue
 * \param[in]       b: Pointer to message queue structure
 * \return          `1` on success, `0` otherwise
 */
uint8_t
lwgsm_sys_mbox_invalid(lwgsm_sys_mbox_t* b) {
	*b = LWGSM_SYS_MBOX_NULL;
	    return 1;
}

/**
 * \brief           Create a new thread
 * \param[out]      t: Pointer to thread identifier if create was successful.
 *                     It may be set to `NULL`
 * \param[in]       name: Name of a new thread
 * \param[in]       thread_func: Thread function to use as thread body
 * \param[in]       arg: Thread function argument
 * \param[in]       stack_size: Size of thread stack in uints of bytes. If set to 0, reserve default stack size
 * \param[in]       prio: Thread priority
 * \return          `1` on success, `0` otherwise
 */
uint8_t
lwgsm_sys_thread_create(lwgsm_sys_thread_t* t, const char* name, lwgsm_sys_thread_fn thread_func,
                      void* const arg, size_t stack_size, lwgsm_sys_thread_prio_t prio) {
	pthread_t *thread;
	thread = malloc(sizeof(pthread_t));
	pthread_create(thread, NULL, (lwesp_sys_posix_thread_fn)thread_func, arg);
	if(t != NULL) {
		*t = thread;
	}
	return thread != NULL;

}

/**
 * \brief           Terminate thread (shut it down and remove)
 * \param[in]       t: Pointer to thread handle to terminate.
 *                      If set to `NULL`, terminate current thread (thread from where function is called)
 * \return          `1` on success, `0` otherwise
 */
uint8_t
lwgsm_sys_thread_terminate(lwgsm_sys_thread_t* t) {
	if (pthread_cancel(**t) != 0) {
	        return 0;
	    }

	    free(*t);
	    return 1;
}

/**
 * \brief           Yield current thread
 * \return          `1` on success, `0` otherwise
 */
uint8_t
lwgsm_sys_thread_yield(void) {
	/* Not implemented. */
	    return 1;
}
