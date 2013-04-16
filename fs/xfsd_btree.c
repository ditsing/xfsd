/*
 * Copyright (c) 2000-2002,2005 Silicon Graphics, Inc.
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
#include "xfs/xfs_bit.h"
#include "xfs/xfs_log.h"
#include "xfsd_trans.h"
#include "xfs/xfs_sb.h"
#include "xfs/xfs_ag.h"
#include "xfs/xfs_mount.h"
#include "xfs/xfs_bmap_btree.h"
#include "xfs/xfs_alloc_btree.h"
#include "xfs/xfs_ialloc_btree.h"
#include "xfs/xfs_dinode.h"
#include "xfs/xfs_inode.h"
#include "xfs/xfs_inode_item.h"
#include "xfs/xfs_btree.h"
#include "xfs/xfs_error.h"

#include "xfsd_trace.h"

/*
 * Cursor allocation zone.
 */
kmem_zone_t	*xfs_btree_cur_zone;

/*
 * Btree magic numbers.
 */
const __uint32_t xfs_magics[XFS_BTNUM_MAX] = {
	XFS_ABTB_MAGIC, XFS_ABTC_MAGIC, XFS_BMAP_MAGIC, XFS_IBT_MAGIC
};


STATIC int				/* error (0 or EFSCORRUPTED) */
xfs_btree_check_lblock(
	struct xfs_btree_cur	*cur,	/* btree cursor */
	struct xfs_btree_block	*block,	/* btree long form block pointer */
	int			level,	/* level of the btree block */
	struct xfs_buf		*bp)	/* buffer for block, if any */
{
	int			lblock_ok; /* block passes checks */
	struct xfs_mount	*mp;	/* file system mount point */

	mp = cur->bc_mp;
	lblock_ok =
		be32_to_cpu(block->bb_magic) == xfs_magics[cur->bc_btnum] &&
		be16_to_cpu(block->bb_level) == level &&
		be16_to_cpu(block->bb_numrecs) <=
			cur->bc_ops->get_maxrecs(cur, level) &&
		block->bb_u.l.bb_leftsib &&
		(block->bb_u.l.bb_leftsib == cpu_to_be64(NULLDFSBNO) ||
		 XFS_FSB_SANITY_CHECK(mp,
		 	be64_to_cpu(block->bb_u.l.bb_leftsib))) &&
		block->bb_u.l.bb_rightsib &&
		(block->bb_u.l.bb_rightsib == cpu_to_be64(NULLDFSBNO) ||
		 XFS_FSB_SANITY_CHECK(mp,
		 	be64_to_cpu(block->bb_u.l.bb_rightsib)));
	if (unlikely(XFS_TEST_ERROR(!lblock_ok, mp,
			XFS_ERRTAG_BTREE_CHECK_LBLOCK,
			XFS_RANDOM_BTREE_CHECK_LBLOCK))) {
		if (bp)
			trace_xfs_btree_corrupt(bp, _RET_IP_);
		XFS_ERROR_REPORT("xfs_btree_check_lblock", XFS_ERRLEVEL_LOW,
				 mp);
		return XFS_ERROR(EFSCORRUPTED);
	}
	return 0;
}

STATIC int				/* error (0 or EFSCORRUPTED) */
xfs_btree_check_sblock(
	struct xfs_btree_cur	*cur,	/* btree cursor */
	struct xfs_btree_block	*block,	/* btree short form block pointer */
	int			level,	/* level of the btree block */
	struct xfs_buf		*bp)	/* buffer containing block */
{
	struct xfs_buf		*agbp;	/* buffer for ag. freespace struct */
	struct xfs_agf		*agf;	/* ag. freespace structure */
	xfs_agblock_t		agflen;	/* native ag. freespace length */
	int			sblock_ok; /* block passes checks */

	agbp = cur->bc_private.a.agbp;
	agf = XFS_BUF_TO_AGF(agbp);
	agflen = be32_to_cpu(agf->agf_length);
	sblock_ok =
		be32_to_cpu(block->bb_magic) == xfs_magics[cur->bc_btnum] &&
		be16_to_cpu(block->bb_level) == level &&
		be16_to_cpu(block->bb_numrecs) <=
			cur->bc_ops->get_maxrecs(cur, level) &&
		(block->bb_u.s.bb_leftsib == cpu_to_be32(NULLAGBLOCK) ||
		 be32_to_cpu(block->bb_u.s.bb_leftsib) < agflen) &&
		block->bb_u.s.bb_leftsib &&
		(block->bb_u.s.bb_rightsib == cpu_to_be32(NULLAGBLOCK) ||
		 be32_to_cpu(block->bb_u.s.bb_rightsib) < agflen) &&
		block->bb_u.s.bb_rightsib;
	if (unlikely(XFS_TEST_ERROR(!sblock_ok, cur->bc_mp,
			XFS_ERRTAG_BTREE_CHECK_SBLOCK,
			XFS_RANDOM_BTREE_CHECK_SBLOCK))) {
		if (bp)
			trace_xfs_btree_corrupt(bp, _RET_IP_);
		XFS_CORRUPTION_ERROR("xfs_btree_check_sblock",
			XFS_ERRLEVEL_LOW, cur->bc_mp, block);
		return XFS_ERROR(EFSCORRUPTED);
	}
	return 0;
}

/*
 * Debug routine: check that block header is ok.
 */
int
xfs_btree_check_block(
	struct xfs_btree_cur	*cur,	/* btree cursor */
	struct xfs_btree_block	*block,	/* generic btree block pointer */
	int			level,	/* level of the btree block */
	struct xfs_buf		*bp)	/* buffer containing block, if any */
{
	if (cur->bc_flags & XFS_BTREE_LONG_PTRS)
		return xfs_btree_check_lblock(cur, block, level, bp);
	else
		return xfs_btree_check_sblock(cur, block, level, bp);
}

/*
 * Check that (long) pointer is ok.
 */
int					/* error (0 or EFSCORRUPTED) */
xfs_btree_check_lptr(
	struct xfs_btree_cur	*cur,	/* btree cursor */
	xfs_dfsbno_t		bno,	/* btree block disk address */
	int			level)	/* btree block level */
{
	XFS_WANT_CORRUPTED_RETURN(
		level > 0 &&
		bno != NULLDFSBNO &&
		XFS_FSB_SANITY_CHECK(cur->bc_mp, bno));
	return 0;
}

#ifdef DEBUG
/*
 * Check that (short) pointer is ok.
 */
STATIC int				/* error (0 or EFSCORRUPTED) */
xfs_btree_check_sptr(
	struct xfs_btree_cur	*cur,	/* btree cursor */
	xfs_agblock_t		bno,	/* btree block disk address */
	int			level)	/* btree block level */
{
	xfs_agblock_t		agblocks = cur->bc_mp->m_sb.sb_agblocks;

	XFS_WANT_CORRUPTED_RETURN(
		level > 0 &&
		bno != NULLAGBLOCK &&
		bno != 0 &&
		bno < agblocks);
	return 0;
}

/*
 * Check that block ptr is ok.
 */
STATIC int				/* error (0 or EFSCORRUPTED) */
xfs_btree_check_ptr(
	struct xfs_btree_cur	*cur,	/* btree cursor */
	union xfs_btree_ptr	*ptr,	/* btree block disk address */
	int			index,	/* offset from ptr to check */
	int			level)	/* btree block level */
{
	if (cur->bc_flags & XFS_BTREE_LONG_PTRS) {
		return xfs_btree_check_lptr(cur,
				be64_to_cpu((&ptr->l)[index]), level);
	} else {
		return xfs_btree_check_sptr(cur,
				be32_to_cpu((&ptr->s)[index]), level);
	}
}
#endif

/*
 * Delete the btree cursor.
 */
void
xfs_btree_del_cursor(
	xfs_btree_cur_t	*cur,		/* btree cursor */
	int		error)		/* del because of error */
{
	int		i;		/* btree level */

	/*
	 * Clear the buffer pointers, and release the buffers.
	 * If we're doing this in the face of an error, we
	 * need to make sure to inspect all of the entries
	 * in the bc_bufs array for buffers to be unlocked.
	 * This is because some of the btree code works from
	 * level n down to 0, and if we get an error along
	 * the way we won't have initialized all the entries
	 * down to 0.
	 */
	for (i = 0; i < cur->bc_nlevels; i++) {
		if (cur->bc_bufs[i])
			xfs_trans_brelse(cur->bc_tp, cur->bc_bufs[i]);
		else if (!error)
			break;
	}
	/*
	 * Can't free a bmap cursor without having dealt with the
	 * allocated indirect blocks' accounting.
	 */
	ASSERT(cur->bc_btnum != XFS_BTNUM_BMAP ||
	       cur->bc_private.b.allocated == 0);
	/*
	 * Free the cursor.
	 */
	kmem_zone_free(xfs_btree_cur_zone, cur);
}

/*
 * Duplicate the btree cursor.
 * Allocate a new one, copy the record, re-get the buffers.
 */
int					/* error */
xfs_btree_dup_cursor(
	xfs_btree_cur_t	*cur,		/* input cursor */
	xfs_btree_cur_t	**ncur)		/* output cursor */
{
	xfs_buf_t	*bp;		/* btree block's buffer pointer */
	int		error;		/* error return value */
	int		i;		/* level number of btree block */
	xfs_mount_t	*mp;		/* mount structure for filesystem */
	xfs_btree_cur_t	*new;		/* new cursor value */
	xfs_trans_t	*tp;		/* transaction pointer, can be NULL */

	tp = cur->bc_tp;
	mp = cur->bc_mp;

	/*
	 * Allocate a new cursor like the old one.
	 */
	new = cur->bc_ops->dup_cursor(cur);

	/*
	 * Copy the record currently in the cursor.
	 */
	new->bc_rec = cur->bc_rec;

	/*
	 * For each level current, re-get the buffer and copy the ptr value.
	 */
	for (i = 0; i < new->bc_nlevels; i++) {
		new->bc_ptrs[i] = cur->bc_ptrs[i];
		new->bc_ra[i] = cur->bc_ra[i];
		bp = cur->bc_bufs[i];
		if (bp) {
			error = xfs_trans_read_buf(mp, tp, mp->m_ddev_targp,
						   XFS_BUF_ADDR(bp), mp->m_bsize,
						   0, &bp,
						   cur->bc_ops->buf_ops);
			if (error) {
				xfs_btree_del_cursor(new, error);
				*ncur = NULL;
				return error;
			}
			new->bc_bufs[i] = bp;
			ASSERT(!xfs_buf_geterror(bp));
		} else
			new->bc_bufs[i] = NULL;
	}
	*ncur = new;
	return 0;
}

/*
 * XFS btree block layout and addressing:
 *
 * There are two types of blocks in the btree: leaf and non-leaf blocks.
 *
 * The leaf record start with a header then followed by records containing
 * the values.  A non-leaf block also starts with the same header, and
 * then first contains lookup keys followed by an equal number of pointers
 * to the btree blocks at the previous level.
 *
 *		+--------+-------+-------+-------+-------+-------+-------+
 * Leaf:	| header | rec 1 | rec 2 | rec 3 | rec 4 | rec 5 | rec N |
 *		+--------+-------+-------+-------+-------+-------+-------+
 *
 *		+--------+-------+-------+-------+-------+-------+-------+
 * Non-Leaf:	| header | key 1 | key 2 | key N | ptr 1 | ptr 2 | ptr N |
 *		+--------+-------+-------+-------+-------+-------+-------+
 *
 * The header is called struct xfs_btree_block for reasons better left unknown
 * and comes in different versions for short (32bit) and long (64bit) block
 * pointers.  The record and key structures are defined by the btree instances
 * and opaque to the btree core.  The block pointers are simple disk endian
 * integers, available in a short (32bit) and long (64bit) variant.
 *
 * The helpers below calculate the offset of a given record, key or pointer
 * into a btree block (xfs_btree_*_offset) or return a pointer to the given
 * record, key or pointer (xfs_btree_*_addr).  Note that all addressing
 * inside the btree block is done using indices starting at one, not zero!
 */

/*
 * Return size of the btree block header for this btree instance.
 */
static inline size_t xfs_btree_block_len(struct xfs_btree_cur *cur)
{
	return (cur->bc_flags & XFS_BTREE_LONG_PTRS) ?
		XFS_BTREE_LBLOCK_LEN :
		XFS_BTREE_SBLOCK_LEN;
}

/*
 * Return size of btree block pointers for this btree instance.
 */
static inline size_t xfs_btree_ptr_len(struct xfs_btree_cur *cur)
{
	return (cur->bc_flags & XFS_BTREE_LONG_PTRS) ?
		sizeof(__be64) : sizeof(__be32);
}

/*
 * Calculate offset of the n-th record in a btree block.
 */
STATIC size_t
xfs_btree_rec_offset(
	struct xfs_btree_cur	*cur,
	int			n)
{
	return xfs_btree_block_len(cur) +
		(n - 1) * cur->bc_ops->rec_len;
}

/*
 * Calculate offset of the n-th key in a btree block.
 */
STATIC size_t
xfs_btree_key_offset(
	struct xfs_btree_cur	*cur,
	int			n)
{
	return xfs_btree_block_len(cur) +
		(n - 1) * cur->bc_ops->key_len;
}

/*
 * Calculate offset of the n-th block pointer in a btree block.
 */
STATIC size_t
xfs_btree_ptr_offset(
	struct xfs_btree_cur	*cur,
	int			n,
	int			level)
{
	return xfs_btree_block_len(cur) +
		cur->bc_ops->get_maxrecs(cur, level) * cur->bc_ops->key_len +
		(n - 1) * xfs_btree_ptr_len(cur);
}

/*
 * Return a pointer to the n-th record in the btree block.
 */
STATIC union xfs_btree_rec *
xfs_btree_rec_addr(
	struct xfs_btree_cur	*cur,
	int			n,
	struct xfs_btree_block	*block)
{
	return (union xfs_btree_rec *)
		((char *)block + xfs_btree_rec_offset(cur, n));
}

/*
 * Return a pointer to the n-th key in the btree block.
 */
STATIC union xfs_btree_key *
xfs_btree_key_addr(
	struct xfs_btree_cur	*cur,
	int			n,
	struct xfs_btree_block	*block)
{
	return (union xfs_btree_key *)
		((char *)block + xfs_btree_key_offset(cur, n));
}

/*
 * Return a pointer to the n-th block pointer in the btree block.
 */
STATIC union xfs_btree_ptr *
xfs_btree_ptr_addr(
	struct xfs_btree_cur	*cur,
	int			n,
	struct xfs_btree_block	*block)
{
	int			level = xfs_btree_get_level(block);

	ASSERT(block->bb_level != 0);

	return (union xfs_btree_ptr *)
		((char *)block + xfs_btree_ptr_offset(cur, n, level));
}

/*
 * Get a the root block which is stored in the inode.
 *
 * For now this btree implementation assumes the btree root is always
 * stored in the if_broot field of an inode fork.
 */
STATIC struct xfs_btree_block *
xfs_btree_get_iroot(
       struct xfs_btree_cur    *cur)
{
       struct xfs_ifork        *ifp;

       ifp = XFS_IFORK_PTR(cur->bc_private.b.ip, cur->bc_private.b.whichfork);
       return (struct xfs_btree_block *)ifp->if_broot;
}

/*
 * Retrieve the block pointer from the cursor at the given level.
 * This may be an inode btree root or from a buffer.
 */
STATIC struct xfs_btree_block *		/* generic btree block pointer */
xfs_btree_get_block(
	struct xfs_btree_cur	*cur,	/* btree cursor */
	int			level,	/* level in btree */
	struct xfs_buf		**bpp)	/* buffer containing the block */
{
	if ((cur->bc_flags & XFS_BTREE_ROOT_IN_INODE) &&
	    (level == cur->bc_nlevels - 1)) {
		*bpp = NULL;
		return xfs_btree_get_iroot(cur);
	}

	*bpp = cur->bc_bufs[level];
	return XFS_BUF_TO_BLOCK(*bpp);
}

/*
 * Get a buffer for the block, return it with no data read.
 * Long-form addressing.
 */
xfs_buf_t *				/* buffer for fsbno */
xfs_btree_get_bufl(
	xfs_mount_t	*mp,		/* file system mount point */
	xfs_trans_t	*tp,		/* transaction pointer */
	xfs_fsblock_t	fsbno,		/* file system block number */
	uint		lock)		/* lock flags for get_buf */
{
	xfs_buf_t	*bp;		/* buffer pointer (return value) */
	xfs_daddr_t		d;		/* real disk block address */

	ASSERT(fsbno != NULLFSBLOCK);
	d = XFS_FSB_TO_DADDR(mp, fsbno);
	bp = xfs_trans_get_buf(tp, mp->m_ddev_targp, d, mp->m_bsize, lock);
	ASSERT(!xfs_buf_geterror(bp));
	return bp;
}

/*
 * Get a buffer for the block, return it with no data read.
 * Short-form addressing.
 */
xfs_buf_t *				/* buffer for agno/agbno */
xfs_btree_get_bufs(
	xfs_mount_t	*mp,		/* file system mount point */
	xfs_trans_t	*tp,		/* transaction pointer */
	xfs_agnumber_t	agno,		/* allocation group number */
	xfs_agblock_t	agbno,		/* allocation group block number */
	uint		lock)		/* lock flags for get_buf */
{
	xfs_buf_t	*bp;		/* buffer pointer (return value) */
	xfs_daddr_t		d;		/* real disk block address */

	ASSERT(agno != NULLAGNUMBER);
	ASSERT(agbno != NULLAGBLOCK);
	d = XFS_AGB_TO_DADDR(mp, agno, agbno);
	bp = xfs_trans_get_buf(tp, mp->m_ddev_targp, d, mp->m_bsize, lock);
	ASSERT(!xfs_buf_geterror(bp));
	return bp;
}

/*
 * Check for the cursor referring to the last block at the given level.
 */
int					/* 1=is last block, 0=not last block */
xfs_btree_islastblock(
	xfs_btree_cur_t		*cur,	/* btree cursor */
	int			level)	/* level to check */
{
	struct xfs_btree_block	*block;	/* generic btree block pointer */
	xfs_buf_t		*bp;	/* buffer containing block */

	block = xfs_btree_get_block(cur, level, &bp);
	xfs_btree_check_block(cur, block, level, bp);
	if (cur->bc_flags & XFS_BTREE_LONG_PTRS)
		return block->bb_u.l.bb_rightsib == cpu_to_be64(NULLDFSBNO);
	else
		return block->bb_u.s.bb_rightsib == cpu_to_be32(NULLAGBLOCK);
}

/*
 * Change the cursor to point to the first record at the given level.
 * Other levels are unaffected.
 */
STATIC int				/* success=1, failure=0 */
xfs_btree_firstrec(
	xfs_btree_cur_t		*cur,	/* btree cursor */
	int			level)	/* level to change */
{
	struct xfs_btree_block	*block;	/* generic btree block pointer */
	xfs_buf_t		*bp;	/* buffer containing block */

	/*
	 * Get the block pointer for this level.
	 */
	block = xfs_btree_get_block(cur, level, &bp);
	xfs_btree_check_block(cur, block, level, bp);
	/*
	 * It's empty, there is no such record.
	 */
	if (!block->bb_numrecs)
		return 0;
	/*
	 * Set the ptr value to 1, that's the first record/key.
	 */
	cur->bc_ptrs[level] = 1;
	return 1;
}

/*
 * Change the cursor to point to the last record in the current block
 * at the given level.  Other levels are unaffected.
 */
STATIC int				/* success=1, failure=0 */
xfs_btree_lastrec(
	xfs_btree_cur_t		*cur,	/* btree cursor */
	int			level)	/* level to change */
{
	struct xfs_btree_block	*block;	/* generic btree block pointer */
	xfs_buf_t		*bp;	/* buffer containing block */

	/*
	 * Get the block pointer for this level.
	 */
	block = xfs_btree_get_block(cur, level, &bp);
	xfs_btree_check_block(cur, block, level, bp);
	/*
	 * It's empty, there is no such record.
	 */
	if (!block->bb_numrecs)
		return 0;
	/*
	 * Set the ptr value to numrecs, that's the last record/key.
	 */
	cur->bc_ptrs[level] = be16_to_cpu(block->bb_numrecs);
	return 1;
}

/*
 * Compute first and last byte offsets for the fields given.
 * Interprets the offsets table, which contains struct field offsets.
 */
void
xfs_btree_offsets(
	__int64_t	fields,		/* bitmask of fields */
	const short	*offsets,	/* table of field offsets */
	int		nbits,		/* number of bits to inspect */
	int		*first,		/* output: first byte offset */
	int		*last)		/* output: last byte offset */
{
	int		i;		/* current bit number */
	__int64_t	imask;		/* mask for current bit number */

	ASSERT(fields != 0);
	/*
	 * Find the lowest bit, so the first byte offset.
	 */
	for (i = 0, imask = 1LL; ; i++, imask <<= 1) {
		if (imask & fields) {
			*first = offsets[i];
			break;
		}
	}
	/*
	 * Find the highest bit, so the last byte offset.
	 */
	for (i = nbits - 1, imask = 1LL << i; ; i--, imask >>= 1) {
		if (imask & fields) {
			*last = offsets[i + 1] - 1;
			break;
		}
	}
}

/*
 * Get a buffer for the block, return it read in.
 * Long-form addressing.
 */
int
xfs_btree_read_bufl(
	struct xfs_mount	*mp,		/* file system mount point */
	struct xfs_trans	*tp,		/* transaction pointer */
	xfs_fsblock_t		fsbno,		/* file system block number */
	uint			lock,		/* lock flags for read_buf */
	struct xfs_buf		**bpp,		/* buffer for fsbno */
	int			refval,		/* ref count value for buffer */
	const struct xfs_buf_ops *ops)
{
	struct xfs_buf		*bp;		/* return value */
	xfs_daddr_t		d;		/* real disk block address */
	int			error;

	ASSERT(fsbno != NULLFSBLOCK);
	d = XFS_FSB_TO_DADDR(mp, fsbno);
	error = xfs_trans_read_buf(mp, tp, mp->m_ddev_targp, d,
				   mp->m_bsize, lock, &bp, ops);
	if (error)
		return error;
	ASSERT(!xfs_buf_geterror(bp));
	if (bp)
		xfs_buf_set_ref(bp, refval);
	*bpp = bp;
	return 0;
}

/*
 * Read-ahead the block, don't wait for it, don't return a buffer.
 * Long-form addressing.
 */
/* ARGSUSED */
void
xfs_btree_reada_bufl(
	struct xfs_mount	*mp,		/* file system mount point */
	xfs_fsblock_t		fsbno,		/* file system block number */
	xfs_extlen_t		count,		/* count of filesystem blocks */
	const struct xfs_buf_ops *ops)
{
	xfs_daddr_t		d;

	ASSERT(fsbno != NULLFSBLOCK);
	d = XFS_FSB_TO_DADDR(mp, fsbno);
	xfs_buf_readahead(mp->m_ddev_targp, d, mp->m_bsize * count, ops);
}

/*
 * Read-ahead the block, don't wait for it, don't return a buffer.
 * Short-form addressing.
 */
/* ARGSUSED */
void
xfs_btree_reada_bufs(
	struct xfs_mount	*mp,		/* file system mount point */
	xfs_agnumber_t		agno,		/* allocation group number */
	xfs_agblock_t		agbno,		/* allocation group block number */
	xfs_extlen_t		count,		/* count of filesystem blocks */
	const struct xfs_buf_ops *ops)
{
	xfs_daddr_t		d;

	ASSERT(agno != NULLAGNUMBER);
	ASSERT(agbno != NULLAGBLOCK);
	d = XFS_AGB_TO_DADDR(mp, agno, agbno);
	xfs_buf_readahead(mp->m_ddev_targp, d, mp->m_bsize * count, ops);
}

STATIC int
xfs_btree_readahead_lblock(
	struct xfs_btree_cur	*cur,
	int			lr,
	struct xfs_btree_block	*block)
{
	int			rval = 0;
	xfs_dfsbno_t		left = be64_to_cpu(block->bb_u.l.bb_leftsib);
	xfs_dfsbno_t		right = be64_to_cpu(block->bb_u.l.bb_rightsib);

	if ((lr & XFS_BTCUR_LEFTRA) && left != NULLDFSBNO) {
		xfs_btree_reada_bufl(cur->bc_mp, left, 1,
				     cur->bc_ops->buf_ops);
		rval++;
	}

	if ((lr & XFS_BTCUR_RIGHTRA) && right != NULLDFSBNO) {
		xfs_btree_reada_bufl(cur->bc_mp, right, 1,
				     cur->bc_ops->buf_ops);
		rval++;
	}

	return rval;
}

STATIC int
xfs_btree_readahead_sblock(
	struct xfs_btree_cur	*cur,
	int			lr,
	struct xfs_btree_block *block)
{
	int			rval = 0;
	xfs_agblock_t		left = be32_to_cpu(block->bb_u.s.bb_leftsib);
	xfs_agblock_t		right = be32_to_cpu(block->bb_u.s.bb_rightsib);


	if ((lr & XFS_BTCUR_LEFTRA) && left != NULLAGBLOCK) {
		xfs_btree_reada_bufs(cur->bc_mp, cur->bc_private.a.agno,
				     left, 1, cur->bc_ops->buf_ops);
		rval++;
	}

	if ((lr & XFS_BTCUR_RIGHTRA) && right != NULLAGBLOCK) {
		xfs_btree_reada_bufs(cur->bc_mp, cur->bc_private.a.agno,
				     right, 1, cur->bc_ops->buf_ops);
		rval++;
	}

	return rval;
}

/*
 * Read-ahead btree blocks, at the given level.
 * Bits in lr are set from XFS_BTCUR_{LEFT,RIGHT}RA.
 */
STATIC int
xfs_btree_readahead(
	struct xfs_btree_cur	*cur,		/* btree cursor */
	int			lev,		/* level in btree */
	int			lr)		/* left/right bits */
{
	struct xfs_btree_block	*block;

	/*
	 * No readahead needed if we are at the root level and the
	 * btree root is stored in the inode.
	 */
	if ((cur->bc_flags & XFS_BTREE_ROOT_IN_INODE) &&
	    (lev == cur->bc_nlevels - 1))
		return 0;

	if ((cur->bc_ra[lev] | lr) == cur->bc_ra[lev])
		return 0;

	cur->bc_ra[lev] |= lr;
	block = XFS_BUF_TO_BLOCK(cur->bc_bufs[lev]);

	if (cur->bc_flags & XFS_BTREE_LONG_PTRS)
		return xfs_btree_readahead_lblock(cur, lr, block);
	return xfs_btree_readahead_sblock(cur, lr, block);
}

/*
 * Set the buffer for level "lev" in the cursor to bp, releasing
 * any previous buffer.
 */
STATIC void
xfs_btree_setbuf(
	xfs_btree_cur_t		*cur,	/* btree cursor */
	int			lev,	/* level in btree */
	xfs_buf_t		*bp)	/* new buffer to set */
{
	struct xfs_btree_block	*b;	/* btree block */

	if (cur->bc_bufs[lev])
		xfs_trans_brelse(cur->bc_tp, cur->bc_bufs[lev]);
	cur->bc_bufs[lev] = bp;
	cur->bc_ra[lev] = 0;

	b = XFS_BUF_TO_BLOCK(bp);
	if (cur->bc_flags & XFS_BTREE_LONG_PTRS) {
		if (b->bb_u.l.bb_leftsib == cpu_to_be64(NULLDFSBNO))
			cur->bc_ra[lev] |= XFS_BTCUR_LEFTRA;
		if (b->bb_u.l.bb_rightsib == cpu_to_be64(NULLDFSBNO))
			cur->bc_ra[lev] |= XFS_BTCUR_RIGHTRA;
	} else {
		if (b->bb_u.s.bb_leftsib == cpu_to_be32(NULLAGBLOCK))
			cur->bc_ra[lev] |= XFS_BTCUR_LEFTRA;
		if (b->bb_u.s.bb_rightsib == cpu_to_be32(NULLAGBLOCK))
			cur->bc_ra[lev] |= XFS_BTCUR_RIGHTRA;
	}
}

STATIC int
xfs_btree_ptr_is_null(
	struct xfs_btree_cur	*cur,
	union xfs_btree_ptr	*ptr)
{
	if (cur->bc_flags & XFS_BTREE_LONG_PTRS)
		return ptr->l == cpu_to_be64(NULLDFSBNO);
	else
		return ptr->s == cpu_to_be32(NULLAGBLOCK);
}

STATIC void
xfs_btree_set_ptr_null(
	struct xfs_btree_cur	*cur,
	union xfs_btree_ptr	*ptr)
{
	if (cur->bc_flags & XFS_BTREE_LONG_PTRS)
		ptr->l = cpu_to_be64(NULLDFSBNO);
	else
		ptr->s = cpu_to_be32(NULLAGBLOCK);
}

/*
 * Get/set/init sibling pointers
 */
STATIC void
xfs_btree_get_sibling(
	struct xfs_btree_cur	*cur,
	struct xfs_btree_block	*block,
	union xfs_btree_ptr	*ptr,
	int			lr)
{
	ASSERT(lr == XFS_BB_LEFTSIB || lr == XFS_BB_RIGHTSIB);

	if (cur->bc_flags & XFS_BTREE_LONG_PTRS) {
		if (lr == XFS_BB_RIGHTSIB)
			ptr->l = block->bb_u.l.bb_rightsib;
		else
			ptr->l = block->bb_u.l.bb_leftsib;
	} else {
		if (lr == XFS_BB_RIGHTSIB)
			ptr->s = block->bb_u.s.bb_rightsib;
		else
			ptr->s = block->bb_u.s.bb_leftsib;
	}
}

STATIC void
xfs_btree_set_sibling(
	struct xfs_btree_cur	*cur,
	struct xfs_btree_block	*block,
	union xfs_btree_ptr	*ptr,
	int			lr)
{
	ASSERT(lr == XFS_BB_LEFTSIB || lr == XFS_BB_RIGHTSIB);

	if (cur->bc_flags & XFS_BTREE_LONG_PTRS) {
		if (lr == XFS_BB_RIGHTSIB)
			block->bb_u.l.bb_rightsib = ptr->l;
		else
			block->bb_u.l.bb_leftsib = ptr->l;
	} else {
		if (lr == XFS_BB_RIGHTSIB)
			block->bb_u.s.bb_rightsib = ptr->s;
		else
			block->bb_u.s.bb_leftsib = ptr->s;
	}
}

void
xfs_btree_init_block(
	struct xfs_mount *mp,
	struct xfs_buf	*bp,
	__u32		magic,
	__u16		level,
	__u16		numrecs,
	unsigned int	flags)
{
	struct xfs_btree_block	*new = XFS_BUF_TO_BLOCK(bp);

	new->bb_magic = cpu_to_be32(magic);
	new->bb_level = cpu_to_be16(level);
	new->bb_numrecs = cpu_to_be16(numrecs);

	if (flags & XFS_BTREE_LONG_PTRS) {
		new->bb_u.l.bb_leftsib = cpu_to_be64(NULLDFSBNO);
		new->bb_u.l.bb_rightsib = cpu_to_be64(NULLDFSBNO);
	} else {
		new->bb_u.s.bb_leftsib = cpu_to_be32(NULLAGBLOCK);
		new->bb_u.s.bb_rightsib = cpu_to_be32(NULLAGBLOCK);
	}
}

STATIC void
xfs_btree_init_block_cur(
	struct xfs_btree_cur	*cur,
	int			level,
	int			numrecs,
	struct xfs_buf		*bp)
{
	xfs_btree_init_block(cur->bc_mp, bp, xfs_magics[cur->bc_btnum],
			       level, numrecs, cur->bc_flags);
}

/*
 * Return true if ptr is the last record in the btree and
 * we need to track updateѕ to this record.  The decision
 * will be further refined in the update_lastrec method.
 */
STATIC int
xfs_btree_is_lastrec(
	struct xfs_btree_cur	*cur,
	struct xfs_btree_block	*block,
	int			level)
{
	union xfs_btree_ptr	ptr;

	if (level > 0)
		return 0;
	if (!(cur->bc_flags & XFS_BTREE_LASTREC_UPDATE))
		return 0;

	xfs_btree_get_sibling(cur, block, &ptr, XFS_BB_RIGHTSIB);
	if (!xfs_btree_ptr_is_null(cur, &ptr))
		return 0;
	return 1;
}

STATIC void
xfs_btree_buf_to_ptr(
	struct xfs_btree_cur	*cur,
	struct xfs_buf		*bp,
	union xfs_btree_ptr	*ptr)
{
	if (cur->bc_flags & XFS_BTREE_LONG_PTRS)
		ptr->l = cpu_to_be64(XFS_DADDR_TO_FSB(cur->bc_mp,
					XFS_BUF_ADDR(bp)));
	else {
		ptr->s = cpu_to_be32(xfs_daddr_to_agbno(cur->bc_mp,
					XFS_BUF_ADDR(bp)));
	}
}

STATIC xfs_daddr_t
xfs_btree_ptr_to_daddr(
	struct xfs_btree_cur	*cur,
	union xfs_btree_ptr	*ptr)
{
	if (cur->bc_flags & XFS_BTREE_LONG_PTRS) {
		ASSERT(ptr->l != cpu_to_be64(NULLDFSBNO));

		return XFS_FSB_TO_DADDR(cur->bc_mp, be64_to_cpu(ptr->l));
	} else {
		ASSERT(cur->bc_private.a.agno != NULLAGNUMBER);
		ASSERT(ptr->s != cpu_to_be32(NULLAGBLOCK));

		return XFS_AGB_TO_DADDR(cur->bc_mp, cur->bc_private.a.agno,
					be32_to_cpu(ptr->s));
	}
}

STATIC void
xfs_btree_set_refs(
	struct xfs_btree_cur	*cur,
	struct xfs_buf		*bp)
{
	switch (cur->bc_btnum) {
	case XFS_BTNUM_BNO:
	case XFS_BTNUM_CNT:
		xfs_buf_set_ref(bp, XFS_ALLOC_BTREE_REF);
		break;
	case XFS_BTNUM_INO:
		xfs_buf_set_ref(bp, XFS_INO_BTREE_REF);
		break;
	case XFS_BTNUM_BMAP:
		xfs_buf_set_ref(bp, XFS_BMAP_BTREE_REF);
		break;
	default:
		ASSERT(0);
	}
}

STATIC int
xfs_btree_get_buf_block(
	struct xfs_btree_cur	*cur,
	union xfs_btree_ptr	*ptr,
	int			flags,
	struct xfs_btree_block	**block,
	struct xfs_buf		**bpp)
{
	struct xfs_mount	*mp = cur->bc_mp;
	xfs_daddr_t		d;

	/* need to sort out how callers deal with failures first */
	ASSERT(!(flags & XBF_TRYLOCK));

	d = xfs_btree_ptr_to_daddr(cur, ptr);
	*bpp = xfs_trans_get_buf(cur->bc_tp, mp->m_ddev_targp, d,
				 mp->m_bsize, flags);

	if (!*bpp)
		return ENOMEM;

	(*bpp)->b_ops = cur->bc_ops->buf_ops;
	*block = XFS_BUF_TO_BLOCK(*bpp);
	return 0;
}

/*
 * Read in the buffer at the given ptr and return the buffer and
 * the block pointer within the buffer.
 */
STATIC int
xfs_btree_read_buf_block(
	struct xfs_btree_cur	*cur,
	union xfs_btree_ptr	*ptr,
	int			level,
	int			flags,
	struct xfs_btree_block	**block,
	struct xfs_buf		**bpp)
{
	struct xfs_mount	*mp = cur->bc_mp;
	xfs_daddr_t		d;
	int			error;

	/* need to sort out how callers deal with failures first */
	ASSERT(!(flags & XBF_TRYLOCK));

	d = xfs_btree_ptr_to_daddr(cur, ptr);
	error = xfs_trans_read_buf(mp, cur->bc_tp, mp->m_ddev_targp, d,
				   mp->m_bsize, flags, bpp,
				   cur->bc_ops->buf_ops);
	if (error)
		return error;

	ASSERT(!xfs_buf_geterror(*bpp));
	xfs_btree_set_refs(cur, *bpp);
	*block = XFS_BUF_TO_BLOCK(*bpp);
	return 0;
}

/*
 * Copy keys from one btree block to another.
 */
STATIC void
xfs_btree_copy_keys(
	struct xfs_btree_cur	*cur,
	union xfs_btree_key	*dst_key,
	union xfs_btree_key	*src_key,
	int			numkeys)
{
	ASSERT(numkeys >= 0);
	memcpy(dst_key, src_key, numkeys * cur->bc_ops->key_len);
}

/*
 * Copy records from one btree block to another.
 */
STATIC void
xfs_btree_copy_recs(
	struct xfs_btree_cur	*cur,
	union xfs_btree_rec	*dst_rec,
	union xfs_btree_rec	*src_rec,
	int			numrecs)
{
	ASSERT(numrecs >= 0);
	memcpy(dst_rec, src_rec, numrecs * cur->bc_ops->rec_len);
}

/*
 * Copy block pointers from one btree block to another.
 */
STATIC void
xfs_btree_copy_ptrs(
	struct xfs_btree_cur	*cur,
	union xfs_btree_ptr	*dst_ptr,
	union xfs_btree_ptr	*src_ptr,
	int			numptrs)
{
	ASSERT(numptrs >= 0);
	memcpy(dst_ptr, src_ptr, numptrs * xfs_btree_ptr_len(cur));
}

/*
 * Shift keys one index left/right inside a single btree block.
 */
STATIC void
xfs_btree_shift_keys(
	struct xfs_btree_cur	*cur,
	union xfs_btree_key	*key,
	int			dir,
	int			numkeys)
{
	char			*dst_key;

	ASSERT(numkeys >= 0);
	ASSERT(dir == 1 || dir == -1);

	dst_key = (char *)key + (dir * cur->bc_ops->key_len);
	memmove(dst_key, key, numkeys * cur->bc_ops->key_len);
}

/*
 * Shift records one index left/right inside a single btree block.
 */
STATIC void
xfs_btree_shift_recs(
	struct xfs_btree_cur	*cur,
	union xfs_btree_rec	*rec,
	int			dir,
	int			numrecs)
{
	char			*dst_rec;

	ASSERT(numrecs >= 0);
	ASSERT(dir == 1 || dir == -1);

	dst_rec = (char *)rec + (dir * cur->bc_ops->rec_len);
	memmove(dst_rec, rec, numrecs * cur->bc_ops->rec_len);
}

/*
 * Shift block pointers one index left/right inside a single btree block.
 */
STATIC void
xfs_btree_shift_ptrs(
	struct xfs_btree_cur	*cur,
	union xfs_btree_ptr	*ptr,
	int			dir,
	int			numptrs)
{
	char			*dst_ptr;

	ASSERT(numptrs >= 0);
	ASSERT(dir == 1 || dir == -1);

	dst_ptr = (char *)ptr + (dir * xfs_btree_ptr_len(cur));
	memmove(dst_ptr, ptr, numptrs * xfs_btree_ptr_len(cur));
}

/*
 * Increment cursor by one record at the level.
 * For nonzero levels the leaf-ward information is untouched.
 */
int						/* error */
xfs_btree_increment(
	struct xfs_btree_cur	*cur,
	int			level,
	int			*stat)		/* success/failure */
{
	struct xfs_btree_block	*block;
	union xfs_btree_ptr	ptr;
	struct xfs_buf		*bp;
	int			error;		/* error return value */
	int			lev;

	XFS_BTREE_TRACE_CURSOR(cur, XBT_ENTRY);
	XFS_BTREE_TRACE_ARGI(cur, level);

	ASSERT(level < cur->bc_nlevels);

	/* Read-ahead to the right at this level. */
	xfs_btree_readahead(cur, level, XFS_BTCUR_RIGHTRA);

	/* Get a pointer to the btree block. */
	block = xfs_btree_get_block(cur, level, &bp);

#ifdef DEBUG
	error = xfs_btree_check_block(cur, block, level, bp);
	if (error)
		goto error0;
#endif

	/* We're done if we remain in the block after the increment. */
	if (++cur->bc_ptrs[level] <= xfs_btree_get_numrecs(block))
		goto out1;

	/* Fail if we just went off the right edge of the tree. */
	xfs_btree_get_sibling(cur, block, &ptr, XFS_BB_RIGHTSIB);
	if (xfs_btree_ptr_is_null(cur, &ptr))
		goto out0;

	XFS_BTREE_STATS_INC(cur, increment);

	/*
	 * March up the tree incrementing pointers.
	 * Stop when we don't go off the right edge of a block.
	 */
	for (lev = level + 1; lev < cur->bc_nlevels; lev++) {
		block = xfs_btree_get_block(cur, lev, &bp);

#ifdef DEBUG
		error = xfs_btree_check_block(cur, block, lev, bp);
		if (error)
			goto error0;
#endif

		if (++cur->bc_ptrs[lev] <= xfs_btree_get_numrecs(block))
			break;

		/* Read-ahead the right block for the next loop. */
		xfs_btree_readahead(cur, lev, XFS_BTCUR_RIGHTRA);
	}

	/*
	 * If we went off the root then we are either seriously
	 * confused or have the tree root in an inode.
	 */
	if (lev == cur->bc_nlevels) {
		if (cur->bc_flags & XFS_BTREE_ROOT_IN_INODE)
			goto out0;
		ASSERT(0);
		error = EFSCORRUPTED;
		goto error0;
	}
	ASSERT(lev < cur->bc_nlevels);

	/*
	 * Now walk back down the tree, fixing up the cursor's buffer
	 * pointers and key numbers.
	 */
	for (block = xfs_btree_get_block(cur, lev, &bp); lev > level; ) {
		union xfs_btree_ptr	*ptrp;

		ptrp = xfs_btree_ptr_addr(cur, cur->bc_ptrs[lev], block);
		error = xfs_btree_read_buf_block(cur, ptrp, --lev,
							0, &block, &bp);
		if (error)
			goto error0;

		xfs_btree_setbuf(cur, lev, bp);
		cur->bc_ptrs[lev] = 1;
	}
out1:
	XFS_BTREE_TRACE_CURSOR(cur, XBT_EXIT);
	*stat = 1;
	return 0;

out0:
	XFS_BTREE_TRACE_CURSOR(cur, XBT_EXIT);
	*stat = 0;
	return 0;

error0:
	XFS_BTREE_TRACE_CURSOR(cur, XBT_ERROR);
	return error;
}

/*
 * Decrement cursor by one record at the level.
 * For nonzero levels the leaf-ward information is untouched.
 */
int						/* error */
xfs_btree_decrement(
	struct xfs_btree_cur	*cur,
	int			level,
	int			*stat)		/* success/failure */
{
	struct xfs_btree_block	*block;
	xfs_buf_t		*bp;
	int			error;		/* error return value */
	int			lev;
	union xfs_btree_ptr	ptr;

	XFS_BTREE_TRACE_CURSOR(cur, XBT_ENTRY);
	XFS_BTREE_TRACE_ARGI(cur, level);

	ASSERT(level < cur->bc_nlevels);

	/* Read-ahead to the left at this level. */
	xfs_btree_readahead(cur, level, XFS_BTCUR_LEFTRA);

	/* We're done if we remain in the block after the decrement. */
	if (--cur->bc_ptrs[level] > 0)
		goto out1;

	/* Get a pointer to the btree block. */
	block = xfs_btree_get_block(cur, level, &bp);

#ifdef DEBUG
	error = xfs_btree_check_block(cur, block, level, bp);
	if (error)
		goto error0;
#endif

	/* Fail if we just went off the left edge of the tree. */
	xfs_btree_get_sibling(cur, block, &ptr, XFS_BB_LEFTSIB);
	if (xfs_btree_ptr_is_null(cur, &ptr))
		goto out0;

	XFS_BTREE_STATS_INC(cur, decrement);

	/*
	 * March up the tree decrementing pointers.
	 * Stop when we don't go off the left edge of a block.
	 */
	for (lev = level + 1; lev < cur->bc_nlevels; lev++) {
		if (--cur->bc_ptrs[lev] > 0)
			break;
		/* Read-ahead the left block for the next loop. */
		xfs_btree_readahead(cur, lev, XFS_BTCUR_LEFTRA);
	}

	/*
	 * If we went off the root then we are seriously confused.
	 * or the root of the tree is in an inode.
	 */
	if (lev == cur->bc_nlevels) {
		if (cur->bc_flags & XFS_BTREE_ROOT_IN_INODE)
			goto out0;
		ASSERT(0);
		error = EFSCORRUPTED;
		goto error0;
	}
	ASSERT(lev < cur->bc_nlevels);

	/*
	 * Now walk back down the tree, fixing up the cursor's buffer
	 * pointers and key numbers.
	 */
	for (block = xfs_btree_get_block(cur, lev, &bp); lev > level; ) {
		union xfs_btree_ptr	*ptrp;

		ptrp = xfs_btree_ptr_addr(cur, cur->bc_ptrs[lev], block);
		error = xfs_btree_read_buf_block(cur, ptrp, --lev,
							0, &block, &bp);
		if (error)
			goto error0;
		xfs_btree_setbuf(cur, lev, bp);
		cur->bc_ptrs[lev] = xfs_btree_get_numrecs(block);
	}
out1:
	XFS_BTREE_TRACE_CURSOR(cur, XBT_EXIT);
	*stat = 1;
	return 0;

out0:
	XFS_BTREE_TRACE_CURSOR(cur, XBT_EXIT);
	*stat = 0;
	return 0;

error0:
	XFS_BTREE_TRACE_CURSOR(cur, XBT_ERROR);
	return error;
}

STATIC int
xfs_btree_lookup_get_block(
	struct xfs_btree_cur	*cur,	/* btree cursor */
	int			level,	/* level in the btree */
	union xfs_btree_ptr	*pp,	/* ptr to btree block */
	struct xfs_btree_block	**blkp) /* return btree block */
{
	struct xfs_buf		*bp;	/* buffer pointer for btree block */
	int			error = 0;

	/* special case the root block if in an inode */
	if ((cur->bc_flags & XFS_BTREE_ROOT_IN_INODE) &&
	    (level == cur->bc_nlevels - 1)) {
		*blkp = xfs_btree_get_iroot(cur);
		return 0;
	}

	/*
	 * If the old buffer at this level for the disk address we are
	 * looking for re-use it.
	 *
	 * Otherwise throw it away and get a new one.
	 */
	bp = cur->bc_bufs[level];
	if (bp && XFS_BUF_ADDR(bp) == xfs_btree_ptr_to_daddr(cur, pp)) {
		*blkp = XFS_BUF_TO_BLOCK(bp);
		return 0;
	}

	error = xfs_btree_read_buf_block(cur, pp, level, 0, blkp, &bp);
	if (error)
		return error;

	xfs_btree_setbuf(cur, level, bp);
	return 0;
}

/*
 * Get current search key.  For level 0 we don't actually have a key
 * structure so we make one up from the record.  For all other levels
 * we just return the right key.
 */
STATIC union xfs_btree_key *
xfs_lookup_get_search_key(
	struct xfs_btree_cur	*cur,
	int			level,
	int			keyno,
	struct xfs_btree_block	*block,
	union xfs_btree_key	*kp)
{
	if (level == 0) {
		cur->bc_ops->init_key_from_rec(kp,
				xfs_btree_rec_addr(cur, keyno, block));
		return kp;
	}

	return xfs_btree_key_addr(cur, keyno, block);
}

/*
 * Lookup the record.  The cursor is made to point to it, based on dir.
 * Return 0 if can't find any such record, 1 for success.
 */
int					/* error */
xfs_btree_lookup(
	struct xfs_btree_cur	*cur,	/* btree cursor */
	xfs_lookup_t		dir,	/* <=, ==, or >= */
	int			*stat)	/* success/failure */
{
	struct xfs_btree_block	*block;	/* current btree block */
	__int64_t		diff;	/* difference for the current key */
	int			error;	/* error return value */
	int			keyno;	/* current key number */
	int			level;	/* level in the btree */
	union xfs_btree_ptr	*pp;	/* ptr to btree block */
	union xfs_btree_ptr	ptr;	/* ptr to btree block */

	XFS_BTREE_TRACE_CURSOR(cur, XBT_ENTRY);
	XFS_BTREE_TRACE_ARGI(cur, dir);

	XFS_BTREE_STATS_INC(cur, lookup);

	block = NULL;
	keyno = 0;

	/* initialise start pointer from cursor */
	cur->bc_ops->init_ptr_from_cur(cur, &ptr);
	pp = &ptr;

	/*
	 * Iterate over each level in the btree, starting at the root.
	 * For each level above the leaves, find the key we need, based
	 * on the lookup record, then follow the corresponding block
	 * pointer down to the next level.
	 */
	for (level = cur->bc_nlevels - 1, diff = 1; level >= 0; level--) {
		/* Get the block we need to do the lookup on. */
		error = xfs_btree_lookup_get_block(cur, level, pp, &block);
		if (error)
			goto error0;

		if (diff == 0) {
			/*
			 * If we already had a key match at a higher level, we
			 * know we need to use the first entry in this block.
			 */
			keyno = 1;
		} else {
			/* Otherwise search this block. Do a binary search. */

			int	high;	/* high entry number */
			int	low;	/* low entry number */

			/* Set low and high entry numbers, 1-based. */
			low = 1;
			high = xfs_btree_get_numrecs(block);
			if (!high) {
				/* Block is empty, must be an empty leaf. */
				ASSERT(level == 0 && cur->bc_nlevels == 1);

				cur->bc_ptrs[0] = dir != XFS_LOOKUP_LE;
				XFS_BTREE_TRACE_CURSOR(cur, XBT_EXIT);
				*stat = 0;
				return 0;
			}

			/* Binary search the block. */
			while (low <= high) {
				union xfs_btree_key	key;
				union xfs_btree_key	*kp;

				XFS_BTREE_STATS_INC(cur, compare);

				/* keyno is average of low and high. */
				keyno = (low + high) >> 1;

				/* Get current search key */
				kp = xfs_lookup_get_search_key(cur, level,
						keyno, block, &key);

				/*
				 * Compute difference to get next direction:
				 *  - less than, move right
				 *  - greater than, move left
				 *  - equal, we're done
				 */
				diff = cur->bc_ops->key_diff(cur, kp);
				if (diff < 0)
					low = keyno + 1;
				else if (diff > 0)
					high = keyno - 1;
				else
					break;
			}
		}

		/*
		 * If there are more levels, set up for the next level
		 * by getting the block number and filling in the cursor.
		 */
		if (level > 0) {
			/*
			 * If we moved left, need the previous key number,
			 * unless there isn't one.
			 */
			if (diff > 0 && --keyno < 1)
				keyno = 1;
			pp = xfs_btree_ptr_addr(cur, keyno, block);

#ifdef DEBUG
			error = xfs_btree_check_ptr(cur, pp, 0, level);
			if (error)
				goto error0;
#endif
			cur->bc_ptrs[level] = keyno;
		}
	}

	/* Done with the search. See if we need to adjust the results. */
	if (dir != XFS_LOOKUP_LE && diff < 0) {
		keyno++;
		/*
		 * If ge search and we went off the end of the block, but it's
		 * not the last block, we're in the wrong block.
		 */
		xfs_btree_get_sibling(cur, block, &ptr, XFS_BB_RIGHTSIB);
		if (dir == XFS_LOOKUP_GE &&
		    keyno > xfs_btree_get_numrecs(block) &&
		    !xfs_btree_ptr_is_null(cur, &ptr)) {
			int	i;

			cur->bc_ptrs[0] = keyno;
			error = xfs_btree_increment(cur, 0, &i);
			if (error)
				goto error0;
			XFS_WANT_CORRUPTED_RETURN(i == 1);
			XFS_BTREE_TRACE_CURSOR(cur, XBT_EXIT);
			*stat = 1;
			return 0;
		}
	} else if (dir == XFS_LOOKUP_LE && diff > 0)
		keyno--;
	cur->bc_ptrs[0] = keyno;

	/* Return if we succeeded or not. */
	if (keyno == 0 || keyno > xfs_btree_get_numrecs(block))
		*stat = 0;
	else if (dir != XFS_LOOKUP_EQ || diff == 0)
		*stat = 1;
	else
		*stat = 0;
	XFS_BTREE_TRACE_CURSOR(cur, XBT_EXIT);
	return 0;

error0:
	XFS_BTREE_TRACE_CURSOR(cur, XBT_ERROR);
	return error;
}

/*
 * Kill the current root node, and replace it with it's only child node.
 */
STATIC int
xfs_btree_kill_root(
	struct xfs_btree_cur	*cur,
	struct xfs_buf		*bp,
	int			level,
	union xfs_btree_ptr	*newroot)
{
	int			error;

	XFS_BTREE_TRACE_CURSOR(cur, XBT_ENTRY);
	XFS_BTREE_STATS_INC(cur, killroot);

	/*
	 * Update the root pointer, decreasing the level by 1 and then
	 * free the old root.
	 */
	cur->bc_ops->set_root(cur, newroot, -1);

	error = cur->bc_ops->free_block(cur, bp);
	if (error) {
		XFS_BTREE_TRACE_CURSOR(cur, XBT_ERROR);
		return error;
	}

	XFS_BTREE_STATS_INC(cur, free);

	cur->bc_bufs[level] = NULL;
	cur->bc_ra[level] = 0;
	cur->bc_nlevels--;

	XFS_BTREE_TRACE_CURSOR(cur, XBT_EXIT);
	return 0;
}

STATIC int
xfs_btree_dec_cursor(
	struct xfs_btree_cur	*cur,
	int			level,
	int			*stat)
{
	int			error;
	int			i;

	if (level > 0) {
		error = xfs_btree_decrement(cur, level, &i);
		if (error)
			return error;
	}

	XFS_BTREE_TRACE_CURSOR(cur, XBT_EXIT);
	*stat = 1;
	return 0;
}


/*
 * Get the data from the pointed-to record.
 */
int					/* error */
xfs_btree_get_rec(
	struct xfs_btree_cur	*cur,	/* btree cursor */
	union xfs_btree_rec	**recp,	/* output: btree record */
	int			*stat)	/* output: success/failure */
{
	struct xfs_btree_block	*block;	/* btree block */
	struct xfs_buf		*bp;	/* buffer pointer */
	int			ptr;	/* record number */
#ifdef DEBUG
	int			error;	/* error return value */
#endif

	ptr = cur->bc_ptrs[0];
	block = xfs_btree_get_block(cur, 0, &bp);

#ifdef DEBUG
	error = xfs_btree_check_block(cur, block, 0, bp);
	if (error)
		return error;
#endif

	/*
	 * Off the right end or left end, return failure.
	 */
	if (ptr > xfs_btree_get_numrecs(block) || ptr <= 0) {
		*stat = 0;
		return 0;
	}

	/*
	 * Point to the record and extract its data.
	 */
	*recp = xfs_btree_rec_addr(cur, ptr, block);
	*stat = 1;
	return 0;
}
