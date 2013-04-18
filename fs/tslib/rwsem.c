#ifdef WIN32
#error "what's the fuck!"
#else
#include <pthread.h>
#include "rwsem.h"
#include "syscall.h"

void init_rwsem( struct rw_semaphore *sem)
{
	sem->mutex = ( pthread_mutex_t *) mem_alloc( sizeof( pthread_mutex_t));
	pthread_mutex_init( (pthread_mutex_t *)&sem->mutex, NULL);
	sem->reader_count = 0;
}

void down_write( struct rw_semaphore *sem)
{
	pthread_mutex_lock( (pthread_mutex_t *)&sem->mutex);
}

void up_write( struct rw_semaphore *sem)
{
	pthread_mutex_unlock( (pthread_mutex_t *)&sem->mutex);
}

int down_write_trylock( struct rw_semaphore *sem)
{
	return !pthread_mutex_trylock( (pthread_mutex_t *)&sem->mutex);
}

void down_read( struct rw_semaphore *sem)
{
	pthread_mutex_lock( (pthread_mutex_t *)&sem->mutex);
	sem->reader_count++;
	pthread_mutex_unlock( (pthread_mutex_t *)&sem->mutex);
}

void up_read( struct rw_semaphore *sem)
{
	pthread_mutex_lock( (pthread_mutex_t *)&sem->mutex);
	sem->reader_count--;
	pthread_mutex_unlock( (pthread_mutex_t *)&sem->mutex);
}

int down_read_trylock( struct rw_semaphore *sem)
{
	int ret = !pthread_mutex_trylock( (pthread_mutex_t *)&sem->mutex);
	if ( ret)
	{
		sem->reader_count++;
	}
	return ret;
}

void downgrade_write( struct rw_semaphore *sem)
{
	sem->reader_count++;
	pthread_mutex_unlock( (pthread_mutex_t *)&sem->mutex);
}

#endif
