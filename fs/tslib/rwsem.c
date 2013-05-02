#ifdef WIN32
#include <ntddk.h>
#include "rwsem.h"
#include "syscall.h"

struct kernel_mutex
{
	KMUTEX _;
};

void init_rwsem( struct rw_semaphore *sem)
{
	sem->mutex = ( struct kernel_mutex *) ddk_mem_alloc( sizeof( KMUTEX), 0);
	KeInitializeMutex( ( KMUTEX *)&sem->mutex, 0);
	sem->reader_count = 0;
}

void down_write( struct rw_semaphore *sem)
{
	KeWaitForMutexObject( ( KMUTEX *)&sem->mutex, Executive, KernelMode, FALSE, NULL);
}

void up_write( struct rw_semaphore *sem)
{
	KeReleaseMutex( ( KMUTEX *)&sem->mutex, FALSE);
}

int down_write_trylock( struct rw_semaphore *sem)
{
	NTSTATUS nts = KeWaitForMutexObject( ( KMUTEX *)&sem->mutex, Executive, KernelMode, FALSE, 0);
	return nts != STATUS_SUCCESS;
}

void down_read( struct rw_semaphore *sem)
{
	KeWaitForMutexObject( ( KMUTEX *)&sem->mutex, Executive, KernelMode, FALSE, NULL);
	sem->reader_count++;
	KeReleaseMutex( ( KMUTEX *)&sem->mutex, FALSE);
}

void up_read( struct rw_semaphore *sem)
{
	KeWaitForMutexObject( ( KMUTEX *)&sem->mutex, Executive, KernelMode, FALSE, NULL);
	sem->reader_count--;
	KeReleaseMutex( ( KMUTEX *)&sem->mutex, FALSE);
}

int down_read_trylock( struct rw_semaphore *sem)
{
	NTSTATUS nts = KeWaitForMutexObject( ( KMUTEX *)&sem->mutex, Executive, KernelMode, FALSE, 0);
	if ( nts == STATUS_SUCCESS)
	{
		sem->reader_count++;
	}
	return nts != STATUS_SUCCESS;
}

void downgrade_write( struct rw_semaphore *sem)
{
	sem->reader_count++;
	KeReleaseMutex( ( KMUTEX *)&sem->mutex, FALSE);
}

#else
#include <pthread.h>
#include "rwsem.h"
#include "syscall.h"

struct kernel_mutex
{
	pthread_mutex_t _;
};

static pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;

void init_rwsem( struct rw_semaphore *sem)
{
	pthread_mutex_lock( &init_mutex);

	sem->mutex = ( struct kernel_mutex *) mem_alloc( sizeof( pthread_mutex_t));
	pthread_mutex_init( ( pthread_mutex_t *)&sem->mutex, NULL);
	sem->reader_count = 0;

	pthread_mutex_unlock( &init_mutex);
}

void down_write( struct rw_semaphore *sem)
{
	pthread_mutex_lock( ( pthread_mutex_t *)&sem->mutex);
}

void up_write( struct rw_semaphore *sem)
{
	pthread_mutex_unlock( ( pthread_mutex_t *)&sem->mutex);
}

int down_write_trylock( struct rw_semaphore *sem)
{
	return !pthread_mutex_trylock( ( pthread_mutex_t *)&sem->mutex);
}

void down_read( struct rw_semaphore *sem)
{
	pthread_mutex_lock( ( pthread_mutex_t *)&sem->mutex);
	sem->reader_count++;
	pthread_mutex_unlock( ( pthread_mutex_t *)&sem->mutex);
}

void up_read( struct rw_semaphore *sem)
{
	pthread_mutex_lock( ( pthread_mutex_t *)&sem->mutex);
	sem->reader_count--;
	pthread_mutex_unlock( ( pthread_mutex_t *)&sem->mutex);
}

int down_read_trylock( struct rw_semaphore *sem)
{
	int ret = !pthread_mutex_trylock( ( pthread_mutex_t *)&sem->mutex);
	if ( ret)
	{
		sem->reader_count++;
	}
	return ret;
}

void downgrade_write( struct rw_semaphore *sem)
{
	sem->reader_count++;
	pthread_mutex_unlock( ( pthread_mutex_t *)&sem->mutex);
}

#endif
