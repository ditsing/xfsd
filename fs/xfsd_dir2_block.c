/*
 * Copyright (c) 2000-2003,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write the Free Software Foundation,
 * Inc.,  51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include "xfsd.h"

#include "xfs/xfs_fs.h"
#include "xfs/xfs_types.h"
#include "xfs/xfs_log.h"
#include "xfs/xfs_trans.h"
#include "xfs/xfs_sb.h"
#include "xfs/xfs_ag.h"
#include "xfs/xfs_mount.h"
#include "xfs/xfs_da_btree.h"
#include "xfs/xfs_bmap_btree.h"
#include "xfs/xfs_dinode.h"
#include "xfs/xfs_inode.h"
#include "xfs/xfs_inode_item.h"
#include "xfs/xfs_dir2.h"
#include "xfs/xfs_dir2_format.h"
#include "xfs/xfs_dir2_priv.h"
#include "xfs/xfs_error.h"

#include "xfsd_trace.h"

/*
 * Local function prototypes.
 */
static int xfs_dir2_block_lookup_int(xfs_da_args_t *args, struct xfs_buf **bpp,
				     int *entno);
static xfs_dahash_t xfs_dir_hash_dot, xfs_dir_hash_dotdot;

/*
 * One-time startup routine called from xfs_init().
 */
void
xfs_dir_startup(void)
{
	xfs_dir_hash_dot = xfs_da_hashname((unsigned char *)".", 1);
	xfs_dir_hash_dotdot = xfs_da_hashname((unsigned char *)"..", 2);
}

static void
xfs_dir2_block_verify(
	struct xfs_buf		*bp)
{
	struct xfs_mount	*mp = bp->b_target->bt_mount;
	struct xfs_dir2_data_hdr *hdr = bp->b_addr;
	int			block_ok = 0;

	block_ok = hdr->magic == cpu_to_be32(XFS_DIR2_BLOCK_MAGIC);
	block_ok = block_ok && __xfs_dir2_data_check(NULL, bp) == 0;

	if (!block_ok) {
		XFS_CORRUPTION_ERROR(__func__, XFS_ERRLEVEL_LOW, mp, hdr);
		xfs_buf_ioerror(bp, EFSCORRUPTED);
	}
}

static void
xfs_dir2_block_read_verify(
	struct xfs_buf	*bp)
{
	xfs_dir2_block_verify(bp);
}

static void
xfs_dir2_block_write_verify(
	struct xfs_buf	*bp)
{
	xfs_dir2_block_verify(bp);
}

const struct xfs_buf_ops xfs_dir2_block_buf_ops = {
#ifdef WIN32
#else
	.verify_read = xfs_dir2_block_read_verify,
	.verify_write = xfs_dir2_block_write_verify,
#endif
};

static int
xfs_dir2_block_read(
	struct xfs_trans	*tp,
	struct xfs_inode	*dp,
	struct xfs_buf		**bpp)
{
	struct xfs_mount	*mp = dp->i_mount;

	return xfs_da_read_buf(tp, dp, mp->m_dirdatablk, -1, bpp,
				XFS_DATA_FORK, &xfs_dir2_block_buf_ops);
}

/*
 * Readdir for block directories.
 */
int						/* error */
xfs_dir2_block_getdents(
	xfs_inode_t		*dp,		/* incore inode */
	void			*dirent,
	xfs_off_t		*offset,
	filldir_t		filldir)
{
	xfs_dir2_data_hdr_t	*hdr;		/* block header */
	struct xfs_buf		*bp;		/* buffer for block */
	xfs_dir2_block_tail_t	*btp;		/* block tail */
	xfs_dir2_data_entry_t	*dep;		/* block data entry */
	xfs_dir2_data_unused_t	*dup;		/* block unused entry */
	char			*endptr;	/* end of the data entries */
	int			error;		/* error return value */
	xfs_mount_t		*mp;		/* filesystem mount point */
	char			*ptr;		/* current data entry */
	int			wantoff;	/* starting block offset */
	xfs_off_t		cook;

	mp = dp->i_mount;
	/*
	 * If the block number in the offset is out of range, we're done.
	 */
	if (xfs_dir2_dataptr_to_db(mp, *offset) > mp->m_dirdatablk)
		return 0;

	error = xfs_dir2_block_read(NULL, dp, &bp);
	if (error)
		return error;

	/*
	 * Extract the byte offset we start at from the seek pointer.
	 * We'll skip entries before this.
	 */
	wantoff = xfs_dir2_dataptr_to_off(mp, *offset);
	hdr = bp->b_addr;
	xfs_dir2_data_check(dp, bp);
	/*
	 * Set up values for the loop.
	 */
	btp = xfs_dir2_block_tail_p(mp, hdr);
	ptr = (char *)(hdr + 1);
	endptr = (char *)xfs_dir2_block_leaf_p(btp);

	/*
	 * Loop over the data portion of the block.
	 * Each object is a real entry (dep) or an unused one (dup).
	 */
	while (ptr < endptr) {
		dup = (xfs_dir2_data_unused_t *)ptr;
		/*
		 * Unused, skip it.
		 */
		if (be16_to_cpu(dup->freetag) == XFS_DIR2_DATA_FREE_TAG) {
			ptr += be16_to_cpu(dup->length);
			continue;
		}

		dep = (xfs_dir2_data_entry_t *)ptr;

		/*
		 * Bump pointer for the next iteration.
		 */
		ptr += xfs_dir2_data_entsize(dep->namelen);
		/*
		 * The entry is before the desired starting point, skip it.
		 */
		if ((char *)dep - (char *)hdr < wantoff)
			continue;

		cook = xfs_dir2_db_off_to_dataptr(mp, mp->m_dirdatablk,
					    (char *)dep - (char *)hdr);

		/*
		 * If it didn't fit, set the final offset to here & return.
		 */
		if (filldir(dirent, (char *)dep->name, dep->namelen,
			    cook & 0x7fffffff, be64_to_cpu(dep->inumber),
			    DT_UNKNOWN)) {
			*offset = cook & 0x7fffffff;
			xfs_trans_brelse(NULL, bp);
			return 0;
		}
	}

	/*
	 * Reached the end of the block.
	 * Set the offset to a non-existent block 1 and return.
	 */
	*offset = xfs_dir2_db_off_to_dataptr(mp, mp->m_dirdatablk + 1, 0) &
			0x7fffffff;
	xfs_trans_brelse(NULL, bp);
	return 0;
}

/*
 * Look up an entry in the block.  This is the external routine,
 * xfs_dir2_block_lookup_int does the real work.
 */
int						/* error */
xfs_dir2_block_lookup(
	xfs_da_args_t		*args)		/* dir lookup arguments */
{
	xfs_dir2_data_hdr_t	*hdr;		/* block header */
	xfs_dir2_leaf_entry_t	*blp;		/* block leaf entries */
	struct xfs_buf		*bp;		/* block buffer */
	xfs_dir2_block_tail_t	*btp;		/* block tail */
	xfs_dir2_data_entry_t	*dep;		/* block data entry */
	xfs_inode_t		*dp;		/* incore inode */
	int			ent;		/* entry index */
	int			error;		/* error return value */
	xfs_mount_t		*mp;		/* filesystem mount point */

	trace_xfs_dir2_block_lookup(args);

	/*
	 * Get the buffer, look up the entry.
	 * If not found (ENOENT) then return, have no buffer.
	 */
	if ((error = xfs_dir2_block_lookup_int(args, &bp, &ent)))
		return error;
	dp = args->dp;
	mp = dp->i_mount;
	hdr = bp->b_addr;
	xfs_dir2_data_check(dp, bp);
	btp = xfs_dir2_block_tail_p(mp, hdr);
	blp = xfs_dir2_block_leaf_p(btp);
	/*
	 * Get the offset from the leaf entry, to point to the data.
	 */
	dep = (xfs_dir2_data_entry_t *)((char *)hdr +
		xfs_dir2_dataptr_to_off(mp, be32_to_cpu(blp[ent].address)));
	/*
	 * Fill in inode number, CI name if appropriate, release the block.
	 */
	args->inumber = be64_to_cpu(dep->inumber);
	error = xfs_dir_cilookup_result(args, dep->name, dep->namelen);
	xfs_trans_brelse(args->trans, bp);
	return XFS_ERROR(error);
}

/*
 * Internal block lookup routine.
 */
static int					/* error */
xfs_dir2_block_lookup_int(
	xfs_da_args_t		*args,		/* dir lookup arguments */
	struct xfs_buf		**bpp,		/* returned block buffer */
	int			*entno)		/* returned entry number */
{
	xfs_dir2_dataptr_t	addr;		/* data entry address */
	xfs_dir2_data_hdr_t	*hdr;		/* block header */
	xfs_dir2_leaf_entry_t	*blp;		/* block leaf entries */
	struct xfs_buf		*bp;		/* block buffer */
	xfs_dir2_block_tail_t	*btp;		/* block tail */
	xfs_dir2_data_entry_t	*dep;		/* block data entry */
	xfs_inode_t		*dp;		/* incore inode */
	int			error;		/* error return value */
	xfs_dahash_t		hash;		/* found hash value */
	int			high;		/* binary search high index */
	int			low;		/* binary search low index */
	int			mid;		/* binary search current idx */
	xfs_mount_t		*mp;		/* filesystem mount point */
	xfs_trans_t		*tp;		/* transaction pointer */
	enum xfs_dacmp		cmp;		/* comparison result */

	dp = args->dp;
	tp = args->trans;
	mp = dp->i_mount;

	error = xfs_dir2_block_read(tp, dp, &bp);
	if (error)
		return error;

	hdr = bp->b_addr;
	xfs_dir2_data_check(dp, bp);
	btp = xfs_dir2_block_tail_p(mp, hdr);
	blp = xfs_dir2_block_leaf_p(btp);
	/*
	 * Loop doing a binary search for our hash value.
	 * Find our entry, ENOENT if it's not there.
	 */
	for (low = 0, high = be32_to_cpu(btp->count) - 1; ; ) {
		ASSERT(low <= high);
		mid = (low + high) >> 1;
		if ((hash = be32_to_cpu(blp[mid].hashval)) == args->hashval)
			break;
		if (hash < args->hashval)
			low = mid + 1;
		else
			high = mid - 1;
		if (low > high) {
			ASSERT(args->op_flags & XFS_DA_OP_OKNOENT);
			xfs_trans_brelse(tp, bp);
			return XFS_ERROR(ENOENT);
		}
	}
	/*
	 * Back up to the first one with the right hash value.
	 */
	while (mid > 0 && be32_to_cpu(blp[mid - 1].hashval) == args->hashval) {
		mid--;
	}
	/*
	 * Now loop forward through all the entries with the
	 * right hash value looking for our name.
	 */
	do {
		if ((addr = be32_to_cpu(blp[mid].address)) == XFS_DIR2_NULL_DATAPTR)
			continue;
		/*
		 * Get pointer to the entry from the leaf.
		 */
		dep = (xfs_dir2_data_entry_t *)
			((char *)hdr + xfs_dir2_dataptr_to_off(mp, addr));
		/*
		 * Compare name and if it's an exact match, return the index
		 * and buffer. If it's the first case-insensitive match, store
		 * the index and buffer and continue looking for an exact match.
		 */
		cmp = mp->m_dirnameops->compname(args, dep->name, dep->namelen);
		if (cmp != XFS_CMP_DIFFERENT && cmp != args->cmpresult) {
			args->cmpresult = cmp;
			*bpp = bp;
			*entno = mid;
			if (cmp == XFS_CMP_EXACT)
				return 0;
		}
	} while (++mid < be32_to_cpu(btp->count) &&
			be32_to_cpu(blp[mid].hashval) == hash);

	ASSERT(args->op_flags & XFS_DA_OP_OKNOENT);
	/*
	 * Here, we can only be doing a lookup (not a rename or replace).
	 * If a case-insensitive match was found earlier, return success.
	 */
	if (args->cmpresult == XFS_CMP_CASE)
		return 0;
	/*
	 * No match, release the buffer and return ENOENT.
	 */
	xfs_trans_brelse(tp, bp);
	return XFS_ERROR(ENOENT);
}
