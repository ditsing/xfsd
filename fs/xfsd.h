#ifndef __XFSD_H__
#define __XFSD_H__

#define __KERNEL__

/*
 * Copied from include/linux/stat.h
 */
#include "linux/stat.h"
#include "xfsd_errno.h"

/*
 * Copied from xfs/xfs_linux.h
 */
#define ENOATTR		ENODATA		/* Attribute not found */
#define EWRONGFS	EINVAL		/* Mount with wrong filesystem type */
#define EFSCORRUPTED	EUCLEAN		/* Filesystem is corrupted */

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

#define __bitwise
#define __force
#define __releases(x)
#define __init
#define ASSERT(x)
#define BUG_ON(x)
#define WARN_ON(x)

#define i_size_read(x) ((x)->i_size)

#define XFS_BIT_BLKNOS 	1
#define XFS_BIT_INUMS  	1
#define STATIC static

#include "xfsd_asm.h"

#include "tslib/syscall.h"
#include "tslib/spinlock.h"
#include "tslib/sema.h"
#include "tslib/mutex.h"

#include "linux/defs.h"
#include "linux/rbtree.h"
#include "linux/bytes.h"
#include "linux/inode.h"
#include "linux/list.h"

#include "xfsd_mem.h"
#include "xfsd_buf.h"
#include "xfsd_globals.h"
#include "xfsd_stats.h"
#include "xfsd_message.h"
#include "xfsd_mrlock.h"

#include "radix-tree.h"
#include "xfs/uuid.h"

#define __return_address (0)

#ifdef WIN32
#define inline
#define min(x, y) ((x) < (y) ? (x) : (y))
#define max(x, y) ((x) < (y) ? (x) : (y))
#define min_t(type, x, y) ((type)min(((type)x), ((type)y)))
#define max_t(type, x, y) ((type)max(((type)x), ((type)y)))
#else
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
#endif

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
 * For xfs_mount.h
 * All those locks are not needed.
 */
#define rcu_read_lock()
#define rcu_read_unlock()
#define call_rcu( para, func) func( para)

/*
 * From compiler
 */
#define uninitialized_var(x) x = x

/*
 * From kernel.h
 */
#define UINT_MAX (~0U)
#define ULONG_MAX (~0UL)
#define LONG_MAX ((long)(~0UL>>1))


/*
 * Copied from linux/pagemap.h, used in xfs_mount.h.
 * This won't be used.
 */
#define PAGE_CACHE_SHIFT 12
#define PAGE_SHIFT 12
#define PAGE_SIZE	(1UL << PAGE_SHIFT)
#define PAGE_CACHE_SIZE	(1UL << PAGE_CACHE_SHIFT)

#define radix_tree_preload(mask) 		0
#define radix_tree_preload_end(mask)
#define smp_mb()
#define wake_up_bit(x,y)

/*
 * Copied from xfs_fs.h
 */
/*
 * Block I/O parameterization.	A basic block (BB) is the lowest size of
 * filesystem allocation, and must equal 512.  Length units given to bio
 * routines are in BB's.
 */
#define BBSHIFT		9
#define BBSIZE		(1<<BBSHIFT)
#define BBMASK		(BBSIZE-1)
#define BTOBB(bytes)	(((__u64)(bytes) + BBSIZE - 1) >> BBSHIFT)
#define BTOBBT(bytes)	((__u64)(bytes) >> BBSHIFT)
#define BBTOB(bbs)	((bbs) << BBSHIFT)

#include "tslib/disk.h"
#define block_size(x) BLK_SIZE
#define bdev_logical_block_size(x) BLK_SIZE

/*
 * Functions not in xfs
 */
struct xfs_mount;
int xfs_fs_init();
int xfs_fs_exit();
int xfs_mount( struct xfs_mount **mpp);
int xfs_unmount( struct xfs_mount **mpp);

#ifdef WIN32
#define __func__ "This is a tag."
#define __builtin_constant_p(n) 0
#endif
#endif
