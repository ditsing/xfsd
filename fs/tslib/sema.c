#ifdef WIN32
#include <ntddk.h>
#include "sema.h"
#include "syscall.h"

struct kerenl_sem
{
	sem_t _;
};

int sema_init( struct semaphore *sem, int value)
{
	sem->sem = ( struct kerenl_sem*)mem_alloc( sizeof( sem_t));
	return sem_init( ( sem_t*)sem->sem, 0, value);
}

int down( struct semaphore *sem)
{
	return sem_wait( ( sem_t*)sem->sem);
}

int up( struct semaphore *sem)
{
	return sem_post( ( sem_t*)sem->sem);
}

int down_trylock( struct semaphore *sem)
{
	return sem_trywait( ( sem_t*)sem->sem);
}


#else
#include <pthread.h>
#include <semaphore.h>
#include "sema.h"
#include "syscall.h"

static pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;

struct kerenl_sem
{
	sem_t _;
};

int sema_init( struct semaphore *sem, int value)
{
	pthread_mutex_lock( &init_mutex);
	sem->sem = ( struct kerenl_sem*)mem_alloc( sizeof( sem_t));
	pthread_mutex_unlock( &init_mutex);
	return sem_init( ( sem_t*)sem->sem, 0, value);
}

inline int down( struct semaphore *sem)
{
	return sem_wait( ( sem_t*)sem->sem);
}

inline int up( struct semaphore *sem)
{
	return sem_post( ( sem_t*)sem->sem);
}

inline int down_trylock( struct semaphore *sem)
{
	return sem_trywait( ( sem_t*)sem->sem);
}

#endif
