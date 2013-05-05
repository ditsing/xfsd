
#ifdef WIN32

#include <ntddk.h>
#include "linux/defs.h"
#include "memory.h"

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
	struct kmem_cache *cachep = (struct kmem_cache *)ddk_mem_zalloc( sizeof( struct kmem_cache), 0);
	size_t l = str_len( name) + 1;
	char *n_name = ( char *)ddk_mem_alloc( l, 1);

	cachep->head = ddk_mem_alloc( sizeof( NPAGED_LOOKASIDE_LIST), 0);
	ExInitializeNPagedLookasideList( (PNPAGED_LOOKASIDE_LIST)cachep->head, NULL, NULL, 0, size, 0, 0);

	mem_cpy( n_name, name, l);
	
	cachep->name = n_name;
	KdPrint(("size is %d\n", (int)sizeof( NPAGED_LOOKASIDE_LIST)));
	KdPrint(("name is %s\n", cachep->name));
	KdPrint(("l is %d\n", l));
	KdPrint(("addr is %p %p %p\n", cachep, cachep->name, cachep->head));
	cachep->object_size = size;
	return cachep;
}

void kmem_cache_destroy(struct kmem_cache *s)
{
	KdPrint(("addr is %p %p %p", s, s->name, s->head));
	ExDeleteNPagedLookasideList( (PNPAGED_LOOKASIDE_LIST)s->head);
	KdPrint(("To destory name is %s\n", s->name));
	ddk_mem_free( s->head);
	ddk_mem_free( s->name);
	ddk_mem_free( s);
}

unsigned int kmem_cache_size(struct kmem_cache *s)
{
	return s->object_size;
}

#endif
