/*
 * Copyright (c) 2000-2001,2005 Silicon Graphics, Inc.
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
#include "xfs/xfs_bmap_btree.h"
#include "xfs/xfs_alloc_btree.h"
#include "xfs/xfs_ialloc_btree.h"
#include "xfs/xfs_dinode.h"
#include "xfs/xfs_inode.h"
#include "xfs/xfs_btree.h"
#include "xfs/xfs_alloc.h"
#include "xfs/xfs_extent_busy.h"
#include "xfs/xfs_error.h"

#include "xfsd_trace.h"


STATIC struct xfs_btree_cur *
xfs_allocbt_dup_cursor(
	struct xfs_btree_cur	*cur)
{
	return xfs_allocbt_init_cursor(cur->bc_mp, cur->bc_tp,
			cur->bc_private.a.agbp, cur->bc_private.a.agno,
			cur->bc_btnum);
}

STATIC int
xfs_allocbt_get_minrecs(
	struct xfs_btree_cur	*cur,
	int			level)
{
	return cur->bc_mp->m_alloc_mnr[level != 0];
}

STATIC int
xfs_allocbt_get_maxrecs(
	struct xfs_btree_cur	*cur,
	int			level)
{
	return cur->bc_mp->m_alloc_mxr[level != 0];
}

STATIC void
xfs_allocbt_init_key_from_rec(
	union xfs_btree_key	*key,
	union xfs_btree_rec	*rec)
{
	ASSERT(rec->alloc.ar_startblock != 0);

	key->alloc.ar_startblock = rec->alloc.ar_startblock;
	key->alloc.ar_blockcount = rec->alloc.ar_blockcount;
}

STATIC void
xfs_allocbt_init_rec_from_key(
	union xfs_btree_key	*key,
	union xfs_btree_rec	*rec)
{
	ASSERT(key->alloc.ar_startblock != 0);

	rec->alloc.ar_startblock = key->alloc.ar_startblock;
	rec->alloc.ar_blockcount = key->alloc.ar_blockcount;
}

STATIC void
xfs_allocbt_init_rec_from_cur(
	struct xfs_btree_cur	*cur,
	union xfs_btree_rec	*rec)
{
	ASSERT(cur->bc_rec.a.ar_startblock != 0);

	rec->alloc.ar_startblock = cpu_to_be32(cur->bc_rec.a.ar_startblock);
	rec->alloc.ar_blockcount = cpu_to_be32(cur->bc_rec.a.ar_blockcount);
}

STATIC void
xfs_allocbt_init_ptr_from_cur(
	struct xfs_btree_cur	*cur,
	union xfs_btree_ptr	*ptr)
{
	struct xfs_agf		*agf = XFS_BUF_TO_AGF(cur->bc_private.a.agbp);

	ASSERT(cur->bc_private.a.agno == be32_to_cpu(agf->agf_seqno));
	ASSERT(agf->agf_roots[cur->bc_btnum] != 0);

	ptr->s = agf->agf_roots[cur->bc_btnum];
}

STATIC __int64_t
xfs_allocbt_key_diff(
	struct xfs_btree_cur	*cur,
	union xfs_btree_key	*key)
{
	xfs_alloc_rec_incore_t	*rec = &cur->bc_rec.a;
	xfs_alloc_key_t		*kp = &key->alloc;
	__int64_t		diff;

	if (cur->bc_btnum == XFS_BTNUM_BNO) {
		return (__int64_t)be32_to_cpu(kp->ar_startblock) -
				rec->ar_startblock;
	}

	diff = (__int64_t)be32_to_cpu(kp->ar_blockcount) - rec->ar_blockcount;
	if (diff)
		return diff;

	return (__int64_t)be32_to_cpu(kp->ar_startblock) - rec->ar_startblock;
}

static void
xfs_allocbt_verify(
	struct xfs_buf		*bp)
{
	struct xfs_mount	*mp = bp->b_target->bt_mount;
	struct xfs_btree_block	*block = XFS_BUF_TO_BLOCK(bp);
	struct xfs_perag	*pag = bp->b_pag;
	unsigned int		level;
	int			sblock_ok; /* block passes checks */

	/*
	 * magic number and level verification
	 *
	 * During growfs operations, we can't verify the exact level as the
	 * perag is not fully initialised and hence not attached to the buffer.
	 * In this case, check against the maximum tree depth.
	 */
	level = be16_to_cpu(block->bb_level);
	switch (block->bb_magic) {
	case cpu_to_be32(XFS_ABTB_MAGIC):
		if (pag)
			sblock_ok = level < pag->pagf_levels[XFS_BTNUM_BNOi];
		else
			sblock_ok = level < mp->m_ag_maxlevels;
		break;
	case cpu_to_be32(XFS_ABTC_MAGIC):
		if (pag)
			sblock_ok = level < pag->pagf_levels[XFS_BTNUM_CNTi];
		else
			sblock_ok = level < mp->m_ag_maxlevels;
		break;
	default:
		sblock_ok = 0;
		break;
	}

	/* numrecs verification */
	sblock_ok = sblock_ok &&
		be16_to_cpu(block->bb_numrecs) <= mp->m_alloc_mxr[level != 0];

	/* sibling pointer verification */
	sblock_ok = sblock_ok &&
		(block->bb_u.s.bb_leftsib == cpu_to_be32(NULLAGBLOCK) ||
		 be32_to_cpu(block->bb_u.s.bb_leftsib) < mp->m_sb.sb_agblocks) &&
		block->bb_u.s.bb_leftsib &&
		(block->bb_u.s.bb_rightsib == cpu_to_be32(NULLAGBLOCK) ||
		 be32_to_cpu(block->bb_u.s.bb_rightsib) < mp->m_sb.sb_agblocks) &&
		block->bb_u.s.bb_rightsib;

	if (!sblock_ok) {
		trace_xfs_btree_corrupt(bp, _RET_IP_);
		XFS_CORRUPTION_ERROR(__func__, XFS_ERRLEVEL_LOW, mp, block);
		xfs_buf_ioerror(bp, EFSCORRUPTED);
	}
}

static void
xfs_allocbt_read_verify(
	struct xfs_buf	*bp)
{
	xfs_allocbt_verify(bp);
}

static void
xfs_allocbt_write_verify(
	struct xfs_buf	*bp)
{
	xfs_allocbt_verify(bp);
}

const struct xfs_buf_ops xfs_allocbt_buf_ops = {
	.verify_read = xfs_allocbt_read_verify,
	.verify_write = xfs_allocbt_write_verify,
};


#ifdef DEBUG
STATIC int
xfs_allocbt_keys_inorder(
	struct xfs_btree_cur	*cur,
	union xfs_btree_key	*k1,
	union xfs_btree_key	*k2)
{
	if (cur->bc_btnum == XFS_BTNUM_BNO) {
		return be32_to_cpu(k1->alloc.ar_startblock) <
		       be32_to_cpu(k2->alloc.ar_startblock);
	} else {
		return be32_to_cpu(k1->alloc.ar_blockcount) <
			be32_to_cpu(k2->alloc.ar_blockcount) ||
			(k1->alloc.ar_blockcount == k2->alloc.ar_blockcount &&
			 be32_to_cpu(k1->alloc.ar_startblock) <
			 be32_to_cpu(k2->alloc.ar_startblock));
	}
}

STATIC int
xfs_allocbt_recs_inorder(
	struct xfs_btree_cur	*cur,
	union xfs_btree_rec	*r1,
	union xfs_btree_rec	*r2)
{
	if (cur->bc_btnum == XFS_BTNUM_BNO) {
		return be32_to_cpu(r1->alloc.ar_startblock) +
			be32_to_cpu(r1->alloc.ar_blockcount) <=
			be32_to_cpu(r2->alloc.ar_startblock);
	} else {
		return be32_to_cpu(r1->alloc.ar_blockcount) <
			be32_to_cpu(r2->alloc.ar_blockcount) ||
			(r1->alloc.ar_blockcount == r2->alloc.ar_blockcount &&
			 be32_to_cpu(r1->alloc.ar_startblock) <
			 be32_to_cpu(r2->alloc.ar_startblock));
	}
}
#endif	/* DEBUG */

static const struct xfs_btree_ops xfs_allocbt_ops = {
	.rec_len		= sizeof(xfs_alloc_rec_t),
	.key_len		= sizeof(xfs_alloc_key_t),

	.dup_cursor		= xfs_allocbt_dup_cursor,
	.get_minrecs		= xfs_allocbt_get_minrecs,
	.get_maxrecs		= xfs_allocbt_get_maxrecs,
	.init_key_from_rec	= xfs_allocbt_init_key_from_rec,
	.init_rec_from_key	= xfs_allocbt_init_rec_from_key,
	.init_rec_from_cur	= xfs_allocbt_init_rec_from_cur,
	.init_ptr_from_cur	= xfs_allocbt_init_ptr_from_cur,
	.key_diff		= xfs_allocbt_key_diff,
	.buf_ops		= &xfs_allocbt_buf_ops,
#ifdef DEBUG
	.keys_inorder		= xfs_allocbt_keys_inorder,
	.recs_inorder		= xfs_allocbt_recs_inorder,
#endif
};

/*
 * Allocate a new allocation btree cursor.
 */
struct xfs_btree_cur *			/* new alloc btree cursor */
xfs_allocbt_init_cursor(
	struct xfs_mount	*mp,		/* file system mount point */
	struct xfs_trans	*tp,		/* transaction pointer */
	struct xfs_buf		*agbp,		/* buffer for agf structure */
	xfs_agnumber_t		agno,		/* allocation group number */
	xfs_btnum_t		btnum)		/* btree identifier */
{
	struct xfs_agf		*agf = XFS_BUF_TO_AGF(agbp);
	struct xfs_btree_cur	*cur;

	ASSERT(btnum == XFS_BTNUM_BNO || btnum == XFS_BTNUM_CNT);

	cur = kmem_zone_zalloc(xfs_btree_cur_zone, KM_SLEEP);

	cur->bc_tp = tp;
	cur->bc_mp = mp;
	cur->bc_btnum = btnum;
	cur->bc_blocklog = mp->m_sb.sb_blocklog;
	cur->bc_ops = &xfs_allocbt_ops;

	if (btnum == XFS_BTNUM_CNT) {
		cur->bc_nlevels = be32_to_cpu(agf->agf_levels[XFS_BTNUM_CNT]);
		cur->bc_flags = XFS_BTREE_LASTREC_UPDATE;
	} else {
		cur->bc_nlevels = be32_to_cpu(agf->agf_levels[XFS_BTNUM_BNO]);
	}

	cur->bc_private.a.agbp = agbp;
	cur->bc_private.a.agno = agno;

	return cur;
}

/*
 * Calculate number of records in an alloc btree block.
 */
int
xfs_allocbt_maxrecs(
	struct xfs_mount	*mp,
	int			blocklen,
	int			leaf)
{
	blocklen -= XFS_ALLOC_BLOCK_LEN(mp);

	if (leaf)
		return blocklen / sizeof(xfs_alloc_rec_t);
	return blocklen / (sizeof(xfs_alloc_key_t) + sizeof(xfs_alloc_ptr_t));
}
