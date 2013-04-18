#ifndef __TSLIB_SPINLOCK_H__
#define __TSLIB_SPINLOCK_H__


#ifdef __WIN32__

/*
 * VC does not support empty struct.
 */
typedef struct spinlock
{
	int a;
} spinlock_t;

#else

typedef struct spinlock
{
} spinlock_t;

#endif

/*
 * According to the code, wo do not need a spin_lock at all.
 * There is only one user for each known spin_lock.
 */
#define spin_lock( lock)
#define spin_unlock( lock)
#define spin_lock_init( lock)

#endif
