#ifndef __TSLIB_SEMA_H__
#define __TSLIB_SEMA_H__
struct kerenl_sem;
struct semaphore
{
	struct kerenl_sem *sem;
};

int sema_init( struct semaphore *sem, int value);
int down_trylock(struct semaphore *sem);
int down(struct semaphore *sem);
int up(struct semaphore *sem);
#endif
