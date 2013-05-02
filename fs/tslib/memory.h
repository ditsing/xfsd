#ifndef __TSLIB_MEMORY_H__
#define __TSLIB_MEMORY_H__
#ifdef WIN32
/*
 * Built under Win32
 */
#include "syscall.h"

#define SLAB_HWCACHE_ALIGN	0x00002000UL	/* Align objs on cache lines */
#define SLAB_RECLAIM_ACCOUNT	0x00020000UL		/* Objects are reclaimable */
#define SLAB_MEM_SPREAD		0x00100000UL	/* Spread some memory over cpuset */

#define GFP_KERNEL	1
#define GFP_ATOMIC	0
#define GFP_NOFS	0
#define __GFP_FS	0
#define __GFP_NOWARN    0

typedef unsigned gfp_t;
struct kmem_cache
{
	void *head;
	size_t object_size;
	const char *name;
};

static inline void *kmalloc( size_t size, gfp_t flags)
{
	return ddk_mem_alloc( size, flags);
}

static inline void kfree( const void *p)
{
	ddk_mem_free( p);
}

static inline void *vzalloc( unsigned long size)
{
	return ddk_mem_zalloc( size, 1);
}

static inline void vfree( const void *p)
{
	ddk_mem_free( p);
}

static inline int is_vmalloc_addr( const void *p)
{
	return 1;
}

inline void *kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flag);
inline void kmem_cache_free(struct kmem_cache *cachep, void *objp);

inline struct kmem_cache *
kmem_cache_create(const char *name, size_t size, size_t align,
		  unsigned long flags, void (*ctor)(void *));
inline void kmem_cache_destroy(struct kmem_cache *s);
inline unsigned int kmem_cache_size(struct kmem_cache *s);


#else
/*
 * We are in the userspace.
 */
#include "syscall.h"

#define SLAB_HWCACHE_ALIGN	0x00002000UL	/* Align objs on cache lines */
#define SLAB_RECLAIM_ACCOUNT	0x00020000UL		/* Objects are reclaimable */
#define SLAB_MEM_SPREAD		0x00100000UL	/* Spread some memory over cpuset */

#define ___GFP_WAIT		0x10u
#define ___GFP_HIGH		0x20u
#define ___GFP_IO		0x40u
#define ___GFP_FS		0x80u
#define ___GFP_NOWARN		0x200u
#define ___GFP_NORETRY		0x1000u
#define __GFP_WAIT	((__force gfp_t)___GFP_WAIT)	/* Can wait and reschedule? */
#define __GFP_HIGH	((__force gfp_t)___GFP_HIGH)	/* Should access emergency pools? */
#define __GFP_IO	((__force gfp_t)___GFP_IO)	/* Can start physical IO? */
#define __GFP_FS	((__force gfp_t)___GFP_FS)	/* Can call down to low-level FS? */
#define __GFP_NOWARN	((__force gfp_t)___GFP_NOWARN)	/* Suppress page allocation failure warning */
#define __GFP_NORETRY	((__force gfp_t)___GFP_NORETRY)

#define GFP_KERNEL	(__GFP_WAIT | __GFP_IO | __GFP_FS)
#define GFP_ATOMIC	(__GFP_HIGH)
#define GFP_NOFS	(__GFP_WAIT | __GFP_IO)

typedef unsigned gfp_t;

struct kmem_cache {
	unsigned int object_size;/* The original size of the object */
	unsigned int size;	/* The aligned/padded/added on size  */
	unsigned int align;	/* Alignment as calculated */
	unsigned long flags;	/* Active flags on the slab */
	const char *name;	/* Slab name for sysfs */
	int refcount;		/* Use counter */
	void (*ctor)(void *);	/* Called on object slot creation */
	struct list_head list;	/* List of all slab caches on the system */
};

static inline void *kmalloc( size_t size, gfp_t flags)
{
	return mem_alloc( size);
}

static inline void kfree( const void *p)
{
	mem_free( p);
}

static inline void *vzalloc( unsigned long size)
{
	return mem_zalloc( size);
}

static inline void vfree( const void *p)
{
	mem_free( p);
}

static inline int is_vmalloc_addr( const void *p)
{
	return 1;
}

static inline void *kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flag)
{
	return mem_alloc( cachep->object_size);
}

static inline void kmem_cache_free(struct kmem_cache *cachep, void *objp)
{
	mem_free( objp);
}

static inline struct kmem_cache *
kmem_cache_create(const char *name, size_t size, size_t align,
		  unsigned long flags, void (*ctor)(void *))
{
	struct kmem_cache *cachep = mem_alloc( sizeof( struct kmem_cache));
	cachep->object_size = size;
	cachep->align = align;
	cachep->size = 0;
	cachep->ctor = ctor;
	cachep->flags = flags;
	cachep->refcount = 0;
	/*
	cachep->list
	*/
	size_t l = str_len( name) + 1;
	cachep->name = mem_cpy( mem_alloc( l), name, l);
	return cachep;
}

static inline void kmem_cache_destroy(struct kmem_cache *s)
{
	mem_free( s->name);
	mem_free( s);
}

static inline unsigned int kmem_cache_size(struct kmem_cache *s)
{
	return s->object_size;
}

#endif
#endif
