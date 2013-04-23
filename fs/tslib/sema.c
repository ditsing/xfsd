
#ifdef WIN32
#else
#include <pthread.h>
#include <semaphore.h>
#define kerenl_sem_t sem_t
#include "sema.h"
#include "syscall.h"

static pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;

int sema_init( struct semaphore *sem, int value)
{
	pthread_mutex_lock( &init_mutex);
	sem->sem = ( sem_t*)mem_alloc( sizeof( sem_t));
	pthread_mutex_unlock( &init_mutex);
	return sem_init( sem->sem, 0, value);
}

inline int down( struct semaphore *sem)
{
	return sem_wait( sem->sem);
}

inline int up( struct semaphore *sem)
{
	return sem_post( sem->sem);
}

inline int down_trywait( struct semaphore *sem)
{
	return sem_trywait( sem->sem);
}

#endif
