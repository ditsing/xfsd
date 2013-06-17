// All the else branch in ifdef WIN32 is of NO USE when compiling!!
// xfsd.h and xfsd_types.h must be included BEFORE xfs.h and xfs_types.h!
#ifndef __XFSD_TYPES_H__
#define __XFSD_TYPES_H__

#ifdef __TSLIB_TYPES_H__
// tslib needs to be used with windows headers, so it
// can't contain types like __int64_t.
# define __TSLIB_(x) __TSLIB_##x
#else
# define __TSLIB_(x) x
#endif

#define FAKE_STRUCT( name) struct __TSLIB_(name) { int a;}
#define FAKE_STRUCT_TYPE( name) typedef struct __TSLIB_(name) { int a;} __TSLIB_(name##_t)

/* This lib is only used under win32. */
#ifdef WIN32
# define BITS_PER_LONG 32
// VC needs __inline in C
# define inline __inline
#else
// I use linux 64bits, so...
# define BITS_PER_LONG 64
#endif

// Types for short
// The length of these types are FIXED under WINDOWS and LINUX.
typedef signed long long int __s64;
typedef unsigned long long int __u64;
typedef signed int __s32;
typedef unsigned int __u32;
typedef signed short __s16;
typedef unsigned short __u16;
typedef signed char __s8;
typedef unsigned char __u8;

typedef signed char s8;
typedef unsigned char u8;
typedef signed short s16;
typedef unsigned short u16;
typedef signed int s32;
typedef unsigned int u32;
typedef signed long long s64;
typedef unsigned long long u64;


// That means big/little endian 64
typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __le32;
typedef __u32 __be32;
typedef __u64 __le64;
typedef __u64 __be64;

// Basic types.
/*
 * Additional type declarations for XFS
 */
typedef __s8	__TSLIB_(__int8_t);
typedef __u8	__TSLIB_(__uint8_t);
typedef __s16	__TSLIB_(__int16_t);
typedef __u16	__TSLIB_(__uint16_t);
typedef __s32 	__TSLIB_(__int32_t);
typedef __u32	__TSLIB_(__uint32_t);
typedef __s64 	__TSLIB_(__int64_t);
typedef __u64	__TSLIB_(__uint64_t);

typedef __s8	__TSLIB_(int8_t);
typedef __u8	__TSLIB_(uint8_t);
typedef __s16	__TSLIB_(int16_t);
typedef __u16	__TSLIB_(uint16_t);
typedef __s32 	__TSLIB_(int32_t);
typedef __u32	__TSLIB_(uint32_t);
typedef __s64 	__TSLIB_(int64_t);
typedef __u64	__TSLIB_(uint64_t);

typedef __TSLIB_(__uint32_t)		__TSLIB_(prid_t);		/* project ID */
typedef __TSLIB_(__uint32_t)		__TSLIB_(inst_t);		/* an instruction */

typedef __s64			__TSLIB_(xfs_off_t);	/* <file offset> type */
typedef unsigned long long	__TSLIB_(xfs_ino_t);	/* <inode> type */
typedef __s64			__TSLIB_(xfs_daddr_t);	/* <disk address> type */
typedef char *			__TSLIB_(xfs_caddr_t);	/* <core address> type */
typedef __u32			__TSLIB_(xfs_dev_t);
typedef __u32			__TSLIB_(xfs_nlink_t);

/* __psint_t is the same size as a pointer */
#if (BITS_PER_LONG == 32)
typedef __TSLIB_(__int32_t) __TSLIB_(__psint_t);
typedef __TSLIB_(__uint32_t) __TSLIB_(__psunsigned_t);
#elif (BITS_PER_LONG == 64)
typedef __TSLIB_(__int64_t) __TSLIB_(__psint_t);
typedef __TSLIB_(__uint64_t) __TSLIB_(__psunsigned_t);
#else
#error BITS_PER_LONG must be 32 or 64
#endif

// Copied from uapi/linux/swab.h
#define REVERSE_BITS16( x)((__u16)( 					\
		(((__u16)(x) & ( __u16)0x00ffU) << 8) | 		\
		(((__u16)(x) & ( __u16)0xff00U) >> 8)))
#define REVERSE_BITS32( x)((__u32)(					\
		(((__u32)(x) & ( __u32)0x000000ffUL) << 24) | 		\
		(((__u32)(x) & ( __u32)0x0000ff00UL) <<  8) | 		\
		(((__u32)(x) & ( __u32)0x00ff0000UL) >>  8) | 		\
		(((__u32)(x) & ( __u32)0xff000000UL) >> 24)))
#define REVERSE_BITS64( x)((__u64)( 					\
		(((__u64)(x) & ( __u64)0x00000000000000ffUL) << 56) | 	\
		(((__u64)(x) & ( __u64)0x000000000000ff00UL) << 40) | 	\
		(((__u64)(x) & ( __u64)0x0000000000ff0000UL) << 24) | 	\
		(((__u64)(x) & ( __u64)0x00000000ff000000UL) <<  8) | 	\
		(((__u64)(x) & ( __u64)0x000000ff00000000UL) >>  8) | 	\
		(((__u64)(x) & ( __u64)0x0000ff0000000000UL) >> 24) | 	\
		(((__u64)(x) & ( __u64)0x00ff000000000000UL) >> 40) | 	\
		(((__u64)(x) & ( __u64)0xff00000000000000UL) >> 56)))

#define be16_to_cpu( x) REVERSE_BITS16( x)
#define be32_to_cpu( x) REVERSE_BITS32( x)
#define be64_to_cpu( x) REVERSE_BITS64( x)
#define cpu_to_be16( x) REVERSE_BITS16( x)
#define cpu_to_be32( x) REVERSE_BITS32( x)
#define cpu_to_be64( x) REVERSE_BITS64( x)
#define le16_to_cpu( x) x
#define le32_to_cpu( x) x
#define le64_to_cpu( x) x
#define cpu_to_le16( x) x
#define cpu_to_le32( x) x
#define cpu_to_le64( x) x

// For atomic_t, copied from linux/types.h
typedef struct
{
	__s32 counter;
} __TSLIB_(atomic_t);

// For list_head, copied from linux/types.h
struct __TSLIB_(list_head)
{
	struct __TSLIB_(list_head) *prev, *next;
};

// Fake rcu_head
struct __TSLIB_(rcu_head)
{
	struct rcu_head *next;
	void (*func)( struct rcu_head *head);
};

// Copied from xfs/xfs_linux.h
// What are they talking about.
/*
 * XFS_BIG_BLKNOS needs block layer disk addresses to be 64 bits.
 * XFS_BIG_INUMS requires XFS_BIG_BLKNOS to be set.
 */
#if defined(CONFIG_LBDAF) || (BITS_PER_LONG == 64)
# define XFS_BIG_BLKNOS	1
# define XFS_BIG_INUMS	1
#else
# define XFS_BIG_BLKNOS	0
# define XFS_BIG_INUMS	0
#endif

// Copied from xfs/xfs_linux.h
#define NBBY		8		/* number of bits per byte */

#ifdef WIN32
typedef long __TSLIB_(size_t);
typedef long __TSLIB_(ssize_t);
#else
typedef long long __TSLIB_(size_t);
typedef long long __TSLIB_(ssize_t);
#endif


// Copied from linux/types.h
/* bsd */
typedef unsigned char           __TSLIB_(u_char);
typedef unsigned short          __TSLIB_(u_short);
typedef unsigned int            __TSLIB_(u_int);
typedef unsigned long           __TSLIB_(u_long);

/* sysv */
typedef unsigned char           __TSLIB_(uchar);
typedef unsigned short          __TSLIB_(ushort);
typedef unsigned int            __TSLIB_(uint);
typedef unsigned long           __TSLIB_(ulong);

/* GNUC */
typedef __u64 			__TSLIB_(uint64_t);
typedef __u64 			__TSLIB_(u_int64_t);
typedef __s64 			__TSLIB_(int64_t);

/*
 * Fake container_of, used in xfs_inode.h
 */
#ifndef WIN32
#define container_of(ptr, type, member) ({		      \
	const typeof(((type *)0)->member)*__mptr = (ptr);    \
	(type *)((char *)__mptr - offsetof(type, member)); })
#else
#define container_of(ptr, type, member) ((type *)( \
			(char *)(ptr) - \
			(unsigned long)(&((type *)0)->member)))
#endif


/*
 * Copied from linux/types.h, used in xfs_inode.h
 */
typedef unsigned short 		__TSLIB_(umode_t);

/*
 * Copied from xfs/xfs_linux.h
 */
#define __arch_pack __attribute__((packed))

/*
 * Copied from linux/stddef.h
 */
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

/*
 * Copied from linux/workqueue.h, used in xfs_mount.h.
 */
FAKE_STRUCT( delayed_work);
FAKE_STRUCT( work_struct);

/*
 * Copied from linux/shrinker.h, used in xfs_mount.h.
 */
FAKE_STRUCT( shrinker);

/*
 * Copied from linux/fs.h, used in xfs_dir2_priv.h
 */
typedef long 				__TSLIB_(__kernel_off_t);
typedef long long 			__TSLIB_(__kernel_loff_t);
typedef __TSLIB_(__kernel_loff_t)	__TSLIB_(loff_t);
typedef int (*filldir_t)(void *, const char *, int, __TSLIB_(loff_t), __u64, unsigned);

/*
 * Copied from linux/types.h
 */
typedef long 				__TSLIB_(time_t);

/*
 * Copied from ioctl.h
 */
#ifndef __user
#define __user
#endif

#ifndef __cplusplus
typedef int bool;
#define false 0
#define true  1
#endif

/*
 * Copied from linux/uapi/asm-generic/posix_types.h, used in xfs_mount.h
 */
typedef unsigned int 			__TSLIB_(__kernel_gid_t);
typedef unsigned int 			__TSLIB_(__kernel_uid_t);

/*
 * Copied from linux/types.h, used in xfs_mount.h
 */
typedef __TSLIB_(__kernel_gid_t)	__TSLIB_(gid_t);
typedef __TSLIB_(__kernel_uid_t) 	__TSLIB_(uid_t);

#define DEFINE_SINGLE_BUF_MAP(map, blkno, numblk) \
	struct xfs_buf_map (map) = { .bm_bn = (blkno), .bm_len = (numblk) };

/*
 * Copied from fs/xfs/kmem.h
 */
typedef unsigned __TSLIB_(xfs_km_flags_t);

/*
 * Used in xfs/xfs_buf.h
 */
FAKE_STRUCT_TYPE(dev);
FAKE_STRUCT_TYPE(wait_queue_head);
FAKE_STRUCT(completion);

/*
 * Copied from linux/kernel.h, used by xfs/xfs_attr.h
 */
typedef long __kernel_size_t;
typedef __kernel_size_t ssize_t;

/*
 * Copied from linux/types.h used by xfs_vnodeops.h
 */

typedef		__u8		u_int8_t;
typedef		__s8		int8_t;
typedef		__u16		u_int16_t;
typedef		__s16		int16_t;
typedef		__u32		u_int32_t;
typedef		__s32		int32_t;

typedef struct __TSLIB_(timespec) {
	long	tv_sec;			/* seconds */
	long	tv_nsec;		/* nanoseconds */
} __TSLIB_(timespec_t);

/*
 * For inode.h
 */
FAKE_STRUCT(address_space);
struct __TSLIB_(hlist_head) {
	struct __TSLIB_(hlist_node) *first;
};

struct __TSLIB_(hlist_node) {
	struct __TSLIB_(hlist_node) *next, **pprev;
};

typedef __TSLIB_(gid_t) __TSLIB_(kgid_t);
typedef __TSLIB_(uid_t) __TSLIB_(kuid_t);
// From linxu/types.h
typedef u64 __TSLIB_(blkcnt_t);
typedef u64 __TSLIB_(sector_t);
#endif
