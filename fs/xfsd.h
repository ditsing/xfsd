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
 * Copide from xfs/xfs_linux.h
 */
#define ENOATTR		ENODATA		/* Attribute not found */
#define EWRONGFS	EINVAL		/* Mount with wrong filesystem type */
#define EFSCORRUPTED	EUCLEAN		/* Filesystem is corrupted */

/*
 * Copide from xfs/kmem.h
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


#include "syscall.h"
#define memcpy mem_cpy
#define memmove mem_move

#include "linux/defs.h"
#include "linux/rbtree.h"
#include "xfsd_buf.h"

#define __return_address (0)

#endif

