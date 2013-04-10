#ifndef __XFSD_H__
#define __XFSD_H__

#ifdef CONfiG_XFS_DEBUG
#endif

#define __KERNEL__

/*
 * Copied from include/linux/stat.h
 */
#define S_IFLNK	 0120000
#define S_IFREG  0100000
#define S_IFDIR  0040000
#define S_IFMT  00170000

#include "xfsd_errno.h"

/*
 * Copied from xfs/xfs_linux.h
 */
#define ENOATTR		ENODATA		/* Attribute not found */
#define EWRONGFS	EINVAL		/* Mount with wrong filesystem type */
#define EFSCORRUPTED	EUCLEAN		/* Filesystem is corrupted */

/*
 * Copied from xfs/kmem.h
 */
#define KM_SLEEP	0x0001u
#define KM_NOSLEEP	0x0002u
#define KM_NOFS		0x0004u
#define KM_MAYFAIL	0x0008u

/*
 * Copied from linux/fs.h
 * File types
 *
 * NOTE! These match bits 12..15 of stat.st_mode
 * (ie "(i_mode >> 12) & 15").
 */
#define DT_UNKNOWN	0
#define DT_FIFO		1
#define DT_CHR		2
#define DT_DIR		4
#define DT_BLK		6
#define DT_REG		8
#define DT_LNK		10
#define DT_SOCK		12
#define DT_WHT		14

#define ASSERT(x)

#define XFS_BIT_BLKNOS 	1
#define XFS_BIT_INUMS  	1
#define STATIC static

#include "xfsd_asm.h"

#include "tslib/syscall.h"

#include "linux/defs.h"
#include "linux/rbtree.h"
#include "linux/bytes.h"

#include "xfsd_buf.h"
#include "xfsd_globals.h"
#include "xfsd_stats.h"
#include "xfsd_message.h"

#define __return_address (0)

#define min_t(type, x, y) ({			\
	type __min1 = (x);			\
	type __min2 = (y);			\
	__min1 < __min2 ? __min1: __min2; })

#define max_t(type, x, y) ({			\
	type __max1 = (x);			\
	type __max2 = (y);			\
	__max1 > __max2 ? __max1: __max2; })

#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })

#define max(x, y) ({				\
	typeof(x) _max1 = (x);			\
	typeof(y) _max2 = (y);			\
	(void) (&_max1 == &_max2);		\
	_max1 > _max2 ? _max1 : _max2; })

#define likely(x) (x)
#define unlikely(x) (x)

#define MIN(a,b)	(min(a,b))
#define MAX(a,b)	(max(a,b))
#define howmany(x, y)	(((x)+((y)-1))/(y))

void sort(void *base, size_t num, size_t size,
	  int (*cmp_func)(const void *, const void *),
	  void (*swap_func)(void *, void *, int size));
#define xfs_sort(a,n,s,fn)	sort(a,n,s,fn,NULL)
#define xfs_stack_trace()

/*
 * Need to be updated
 */
#define kmem_alloc(x, y) ( ( void *)0)
#define kmem_zalloc(x, y) ( ( void *)0)
#define kmem_free(x) ( 0)
#define kmem_zone_zalloc(x, y) ( ( void *)0)
#define kmem_zone_free(x, y) ( 0)
#endif

