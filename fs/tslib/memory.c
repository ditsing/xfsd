#include "memory.h"

#ifdef WIN32

#include <ntddk.h>

void *kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flag)
{
	return ExAllocateFromNPagedLookasideList( (PNPAGED_LOOKASIDE_LIST)cachep->head);
}

void kmem_cache_free(struct kmem_cache *cachep, void *objp)
{
	ExFreeToNPagedLookasideList( (PNPAGED_LOOKASIDE_LIST)cachep->head, objp);
}

struct kmem_cache *
kmem_cache_create(const char *name, size_t size, size_t align,
		  unsigned long flags, void (*ctor)(void *))
{
	struct kmem_cache *cachep = (struct kmem_cache *)ddk_mem_alloc( sizeof( struct kmem_cache), 0);
	cachep->head = ( PNPAGED_LOOKASIDE_LIST)( sizeof( NPAGED_LOOKASIDE_LIST), 0);
	ExInitializeNPagedLookasideList( (PNPAGED_LOOKASIDE_LIST)&cachep->head, NULL, NULL, 0, size, 0, 0);

	size_t l = str_len( name) + 1;
	cachep->name = ( const char *)mem_cpy( ddk_mem_alloc( l, 1), name, l);
	cachep->object_size = size;
	return cachep;
}

void kmem_cache_destroy(struct kmem_cache *s)
{
	ExDeleteNPagedLookasideList( (PNPAGED_LOOKASIDE_LIST)s->head);
	mem_free( s->name);
	ddk_mem_free( s);
}

unsigned int kmem_cache_size(struct kmem_cache *s)
{
	return s->object_size;
}

#endif
