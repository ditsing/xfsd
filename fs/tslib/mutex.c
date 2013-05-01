#ifdef WIN32
#error "what's the fuck!"
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
	pthread_mutex_init( ( pthread_mutex_t *)&m->kmutex, NULL);

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
