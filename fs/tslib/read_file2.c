#include "xfsd.h"
#include "read_file2.h"
#include "xfs/xfs_types.h"
#include "xfs/xfs_fs.h"
#include "xfs/xfs_dir2.h"
#include "xfs/xfs_sb.h"
#include "xfs/xfs_ag.h"
#include "xfs/xfs_dir2.h"
#include "xfs/xfs_mount.h"
#include "xfs/xfs_da_btree.h"
#include "xfs/xfs_bmap_btree.h"
#include "xfs/xfs_ialloc_btree.h"
#include "xfs/xfs_dinode.h"
#include "xfs/xfs_inode.h"
#include "xfs/xfs_ialloc.h"
#include "xfs/xfs_alloc.h"
#include "xfs/xfs_bmap.h"
#include "xfs/xfs_ialloc_btree.h"
#include "xfs/xfs_inode.h"
#include "xfs/xfs_icache.h"

#include "xfs/xfs_error.h"

#include "xfsd_mem.h"
#include "xfsd_asm.h"
#include "syscall.h"

struct tslib_file
{
	struct list_head node;
	xfs_inode_t *i_root;
	xfs_fileoff_t offset;
};

struct list_head *head = NULL;
extern xfs_mount_t *mount;

kmem_zone_t *tslib_file_zone;

int tslib_file_init()
{
	tslib_file_zone = kmem_zone_init(sizeof(tslib_file_t), "tslib_file_zone");
	if ( !tslib_file_zone)
	{
		return 1;
	}
	return 0;
}

tslib_file_p assemble_file_pointer( xfs_inode_t *ip)
{
	tslib_file_p 		fp = kmem_zone_alloc( tslib_file_zone, KM_NOFS);
	if ( !fp)
	{
		goto out;
	}

	fp->offset = 0;
	fp->i_root = ip;

	if ( head == NULL)
	{
		head = &fp->node;
	}
	else
	{
		list_add_tail( &fp->node, head);
	}

	return fp;

out:
	return NULL;
}

tslib_file_p open_file2( const char *name)
{
	xfs_ino_t		inum;
	int			error;
	uint			lock_mode;
	struct xfs_name		xfs_name;
	xfs_inode_t 		*ip;

	xfs_inode_t 		*dp = mount->m_rootip;

	xfs_name.len = str_len( name);
	xfs_name.name = ( const unsigned char *) name;

	lock_mode = xfs_ilock_map_shared(dp);
	error = xfs_dir_lookup(NULL, dp, &xfs_name, &inum, NULL);
	xfs_iunlock_map_shared(dp, lock_mode);

	if (error)
		goto out;

	error = xfs_iget(dp->i_mount, NULL, inum, 0, 0, &ip);
	if (error)
		goto out;

	return assemble_file_pointer( ip);

out:
	return NULL;
}

static int tslib_get_blocks( struct xfs_inode *, sector_t, size_t, sector_t *, size_t *);

int read_file2( tslib_file_p fp, void *ptr, size_t ptr_size)
{
	int error;

	xfs_fileoff_t 		file_offset = fp->offset;

	xfs_fsize_t 		file_size = fp->i_root->i_d.di_size - file_offset;
	xfs_fsize_t 		size = file_size < ptr_size ? file_size : ptr_size;
	xfs_fsize_t 		acc_size = size;

	unsigned int 		blkbits = ffs(mount->m_sb.sb_blocksize)-1;
	sector_t 		iblock;

	xfs_fsize_t 		buf_size = ( ( size + mount->m_blockmask) >> blkbits) << blkbits;

	void 			*buf = kmem_zalloc_large( buf_size);
	void 			*buf_zero = buf;
	sector_t 		start_block;
	size_t 			read_size;

	if ( !buf)
	{
		error = ENOMEM;
		goto out;
	}

	while ( size)
	{
		iblock = file_offset >> blkbits;
		error = tslib_get_blocks( fp->i_root, iblock, size, &start_block, &read_size);
		if ( error)
			goto out_free_buf;

		error = read_disk_file_length( buf, start_block << blkbits, read_size, 1) == 0;
		if ( error)
			goto out_free_buf;

		file_offset += read_size;
		buf = ( char *)buf + read_size;
		size -= read_size < size ? read_size : size;
	}
	mem_cpy( ptr, buf_zero, acc_size);

	return 0;
out_free_buf:
	kmem_free_large( buf);
out:
	return error;
}

/*
 * From xfs_super.c
 */
__uint64_t
xfs_max_file_offset(
	unsigned int		blockshift)
{
	unsigned int		pagefactor = 1;
	unsigned int		bitshift = BITS_PER_LONG - 1;

	/* Figure out maximum filesize, on Linux this can depend on
	 * the filesystem blocksize (on 32 bit platforms).
	 * __block_write_begin does this in an [unsigned] long...
	 *      page->index << (PAGE_CACHE_SHIFT - bbits)
	 * So, for page sized blocks (4K on 32 bit platforms),
	 * this wraps at around 8Tb (hence MAX_LFS_FILESIZE which is
	 *      (((u64)PAGE_CACHE_SIZE << (BITS_PER_LONG-1))-1)
	 * but for smaller blocksizes it is less (bbits = log2 bsize).
	 * Note1: get_block_t takes a long (implicit cast from above)
	 * Note2: The Large Block Device (LBD and HAVE_SECTOR_T) patch
	 * can optionally convert the [unsigned] long from above into
	 * an [unsigned] long long.
	 */

#if BITS_PER_LONG == 32
# if defined(CONFIG_LBDAF)
	ASSERT(sizeof(sector_t) == 8);
	pagefactor = PAGE_CACHE_SIZE;
	bitshift = BITS_PER_LONG;
# else
	pagefactor = PAGE_CACHE_SIZE >> (PAGE_CACHE_SHIFT - blockshift);
# endif
#endif

	return (((__uint64_t)pagefactor) << bitshift) - 1;
}

/*
 * From xfs_aops.h
 */
STATIC int
tslib_get_blocks(
	struct xfs_inode	*ip,
	sector_t		iblock,
	size_t 			isize,
	sector_t 		*pbn,
	size_t 			*psz)
{
	struct xfs_mount	*mp = ip->i_mount;
	xfs_fileoff_t		offset_fsb, end_fsb;
	int			error = 0;
	int			lockmode = 0;
	struct xfs_bmbt_irec	imap;
	int			nimaps = 1;
	xfs_off_t		offset;
	ssize_t			size;
	unsigned int 		blkbits = ffs(mp->m_sb.sb_blocksize)-1;
	__uint64_t 		maxbytes = xfs_max_file_offset( blkbits);
	xfs_off_t		iomap_offset;
	xfs_daddr_t		iomap_bn;
	xfs_off_t		mapping_size;


	if (XFS_FORCED_SHUTDOWN(mp))
		return -XFS_ERROR(EIO);

	offset = (xfs_off_t)iblock << blkbits;
	ASSERT(isize >= (1 << blkbits));
	size = isize;

	lockmode = xfs_ilock_map_shared(ip);

	ASSERT(offset <= maxbytes);
	if (offset + size > maxbytes)
		size = maxbytes - offset;
	end_fsb = XFS_B_TO_FSB(mp, (xfs_ufsize_t)offset + size);
	offset_fsb = XFS_B_TO_FSBT(mp, offset);

	error = xfs_bmapi_read(ip, offset_fsb, end_fsb - offset_fsb,
				&imap, &nimaps, XFS_BMAPI_ENTIRE);
	if (error)
		goto out_unlock;

	if (nimaps) {
		xfs_iunlock(ip, lockmode);
	} else {
		goto out_unlock;
	}

	if (imap.br_startblock != HOLESTARTBLOCK &&
	    imap.br_startblock != DELAYSTARTBLOCK) {
		iomap_offset = XFS_FSB_TO_B(mp, imap.br_startoff);
		iomap_bn = xfs_fsb_to_db(ip, imap.br_startblock);

		*pbn = (iomap_bn >> (blkbits - BBSHIFT)) +
			((offset - iomap_offset) >> blkbits);
	}

	if (size > (1 << blkbits)) {
		mapping_size = imap.br_startoff + imap.br_blockcount - iblock;
		mapping_size <<= blkbits;

		ASSERT(mapping_size > 0);
		if (mapping_size > size)
			mapping_size = size;
		if (mapping_size > LONG_MAX)
			mapping_size = LONG_MAX;

		*psz = mapping_size;
	}

	return 0;

out_unlock:
	xfs_iunlock(ip, lockmode);
	return -error;
}
