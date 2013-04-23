#ifndef __TSLIB_SEMA_H__
#define __TSLIB_SEMA_H__
#ifdef WIN32
#else
struct semaphore
{
	kerenl_sem_t *sem;
};

int down_trylock(struct semaphore *sem);
int down(struct semaphore *sem);
int up(struct semaphore *sem);
#endif
#endif
