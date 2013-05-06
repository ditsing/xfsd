#ifdef WIN32
#include <ntddk.h>
#include "syscall.h"
#include "mutex.h"

struct kernel_mutex
{
	KMUTEX _;
};

struct kernel_mutex inline_kmutex;
void mutex_init( struct mutex *m)
{
	m->kmutex = ( struct kernel_mutex *) ddk_mem_alloc( sizeof( KMUTEX), 0);
	KeInitializeMutex( ( KMUTEX *)m->kmutex, 0);
}

void mutex_lock( struct mutex *m)
{
	KeWaitForMutexObject( ( KMUTEX *)m->kmutex, Executive, KernelMode, FALSE, NULL);
}

void mutex_unlock( struct mutex *m)
{
	KeReleaseMutex( ( KMUTEX *)m->kmutex, FALSE);
}

int mutex_trylock( struct mutex *m)
{
	NTSTATUS nts = KeWaitForMutexObject( ( KMUTEX *)m->kmutex, Executive, KernelMode, FALSE, 0);
	return nts != STATUS_SUCCESS;
}

#else
#include <pthread.h>
#include "mutex.h"
#include "syscall.h"

struct kernel_mutex
{
	pthread_mutex_t _;
};

struct kernel_mutex inline_kmutex;
static pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;

void mutex_init( struct mutex *m)
{
	pthread_mutex_lock( &init_mutex);

	m->kmutex = ( struct kernel_mutex *) mem_alloc( sizeof( pthread_mutex_t));
	pthread_mutex_init( ( pthread_mutex_t *)m->kmutex, NULL);

	pthread_mutex_unlock( &init_mutex);
}

void mutex_lock( struct mutex *m)
{
	pthread_mutex_lock( ( pthread_mutex_t *)m->kmutex);
}

void mutex_unlock( struct mutex *m)
{
	pthread_mutex_unlock( ( pthread_mutex_t *)m->kmutex);
}

int mutex_trylock( struct mutex *m)
{
	return !pthread_mutex_trylock( ( pthread_mutex_t *)m->kmutex);
}

#endif
