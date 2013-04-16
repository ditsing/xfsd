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
#include "xfs/xfs_btree.h"
#include "xfs/xfs_alloc.h"
#include "xfs/xfs_extent_busy.h"
#include "xfs/xfs_error.h"

#include "xfsd_trace.h"

struct workqueue_struct *xfs_alloc_wq;

#define XFS_ABSDIFF(a,b)	(((a) <= (b)) ? ((b) - (a)) : ((a) - (b)))

#define	XFSA_FIXUP_BNO_OK	1
#define	XFSA_FIXUP_CNT_OK	2

STATIC int xfs_alloc_ag_vextent_size(xfs_alloc_arg_t *);
STATIC int xfs_alloc_ag_vextent_small(xfs_alloc_arg_t *,
		xfs_btree_cur_t *, xfs_agblock_t *, xfs_extlen_t *, int *);

/*
 * Lookup the record equal to [bno, len] in the btree given by cur.
 */
STATIC int				/* error */
xfs_alloc_lookup_eq(
	struct xfs_btree_cur	*cur,	/* btree cursor */
	xfs_agblock_t		bno,	/* starting block of extent */
	xfs_extlen_t		len,	/* length of extent */
	int			*stat)	/* success/failure */
{
	cur->bc_rec.a.ar_startblock = bno;
	cur->bc_rec.a.ar_blockcount = len;
	return xfs_btree_lookup(cur, XFS_LOOKUP_EQ, stat);
}

/*
 * Lookup the first record greater than or equal to [bno, len]
 * in the btree given by cur.
 */
int				/* error */
xfs_alloc_lookup_ge(
	struct xfs_btree_cur	*cur,	/* btree cursor */
	xfs_agblock_t		bno,	/* starting block of extent */
	xfs_extlen_t		len,	/* length of extent */
	int			*stat)	/* success/failure */
{
	cur->bc_rec.a.ar_startblock = bno;
	cur->bc_rec.a.ar_blockcount = len;
	return xfs_btree_lookup(cur, XFS_LOOKUP_GE, stat);
}

/*
 * Lookup the first record less than or equal to [bno, len]
 * in the btree given by cur.
 */
int					/* error */
xfs_alloc_lookup_le(
	struct xfs_btree_cur	*cur,	/* btree cursor */
	xfs_agblock_t		bno,	/* starting block of extent */
	xfs_extlen_t		len,	/* length of extent */
	int			*stat)	/* success/failure */
{
	cur->bc_rec.a.ar_startblock = bno;
	cur->bc_rec.a.ar_blockcount = len;
	return xfs_btree_lookup(cur, XFS_LOOKUP_LE, stat);
}

/*
 * Get the data from the pointed-to record.
 */
int					/* error */
xfs_alloc_get_rec(
	struct xfs_btree_cur	*cur,	/* btree cursor */
	xfs_agblock_t		*bno,	/* output: starting block of extent */
	xfs_extlen_t		*len,	/* output: length of extent */
	int			*stat)	/* output: success/failure */
{
	union xfs_btree_rec	*rec;
	int			error;

	error = xfs_btree_get_rec(cur, &rec, stat);
	if (!error && *stat == 1) {
		*bno = be32_to_cpu(rec->alloc.ar_startblock);
		*len = be32_to_cpu(rec->alloc.ar_blockcount);
	}
	return error;
}

/*
 * Compute aligned version of the found extent.
 * Takes alignment and min length into account.
 */
STATIC void
xfs_alloc_compute_aligned(
	xfs_alloc_arg_t	*args,		/* allocation argument structure */
	xfs_agblock_t	foundbno,	/* starting block in found extent */
	xfs_extlen_t	foundlen,	/* length in found extent */
	xfs_agblock_t	*resbno,	/* result block number */
	xfs_extlen_t	*reslen)	/* result length */
{
	xfs_agblock_t	bno;
	xfs_extlen_t	len;

	/* Trim busy sections out of found extent */
	xfs_extent_busy_trim(args, foundbno, foundlen, &bno, &len);

	if (args->alignment > 1 && len >= args->minlen) {
		xfs_agblock_t	aligned_bno = roundup(bno, args->alignment);
		xfs_extlen_t	diff = aligned_bno - bno;

		*resbno = aligned_bno;
		*reslen = diff >= len ? 0 : len - diff;
	} else {
		*resbno = bno;
		*reslen = len;
	}
}

/*
 * Compute best start block and diff for "near" allocations.
 * freelen >= wantlen already checked by caller.
 */
STATIC xfs_extlen_t			/* difference value (absolute) */
xfs_alloc_compute_diff(
	xfs_agblock_t	wantbno,	/* target starting block */
	xfs_extlen_t	wantlen,	/* target length */
	xfs_extlen_t	alignment,	/* target alignment */
	xfs_agblock_t	freebno,	/* freespace's starting block */
	xfs_extlen_t	freelen,	/* freespace's length */
	xfs_agblock_t	*newbnop)	/* result: best start block from free */
{
	xfs_agblock_t	freeend;	/* end of freespace extent */
	xfs_agblock_t	newbno1;	/* return block number */
	xfs_agblock_t	newbno2;	/* other new block number */
	xfs_extlen_t	newlen1=0;	/* length with newbno1 */
	xfs_extlen_t	newlen2=0;	/* length with newbno2 */
	xfs_agblock_t	wantend;	/* end of target extent */

	ASSERT(freelen >= wantlen);
	freeend = freebno + freelen;
	wantend = wantbno + wantlen;
	if (freebno >= wantbno) {
		if ((newbno1 = roundup(freebno, alignment)) >= freeend)
			newbno1 = NULLAGBLOCK;
	} else if (freeend >= wantend && alignment > 1) {
		newbno1 = roundup(wantbno, alignment);
		newbno2 = newbno1 - alignment;
		if (newbno1 >= freeend)
			newbno1 = NULLAGBLOCK;
		else
			newlen1 = XFS_EXTLEN_MIN(wantlen, freeend - newbno1);
		if (newbno2 < freebno)
			newbno2 = NULLAGBLOCK;
		else
			newlen2 = XFS_EXTLEN_MIN(wantlen, freeend - newbno2);
		if (newbno1 != NULLAGBLOCK && newbno2 != NULLAGBLOCK) {
			if (newlen1 < newlen2 ||
			    (newlen1 == newlen2 &&
			     XFS_ABSDIFF(newbno1, wantbno) >
			     XFS_ABSDIFF(newbno2, wantbno)))
				newbno1 = newbno2;
		} else if (newbno2 != NULLAGBLOCK)
			newbno1 = newbno2;
	} else if (freeend >= wantend) {
		newbno1 = wantbno;
	} else if (alignment > 1) {
		newbno1 = roundup(freeend - wantlen, alignment);
		if (newbno1 > freeend - wantlen &&
		    newbno1 - alignment >= freebno)
			newbno1 -= alignment;
		else if (newbno1 >= freeend)
			newbno1 = NULLAGBLOCK;
	} else
		newbno1 = freeend - wantlen;
	*newbnop = newbno1;
	return newbno1 == NULLAGBLOCK ? 0 : XFS_ABSDIFF(newbno1, wantbno);
}

/*
 * Fix up the length, based on mod and prod.
 * len should be k * prod + mod for some k.
 * If len is too small it is returned unchanged.
 * If len hits maxlen it is left alone.
 */
STATIC void
xfs_alloc_fix_len(
	xfs_alloc_arg_t	*args)		/* allocation argument structure */
{
	xfs_extlen_t	k;
	xfs_extlen_t	rlen;

	ASSERT(args->mod < args->prod);
	rlen = args->len;
	ASSERT(rlen >= args->minlen);
	ASSERT(rlen <= args->maxlen);
	if (args->prod <= 1 || rlen < args->mod || rlen == args->maxlen ||
	    (args->mod == 0 && rlen < args->prod))
		return;
	k = rlen % args->prod;
	if (k == args->mod)
		return;
	if (k > args->mod) {
		if ((int)(rlen = rlen - k - args->mod) < (int)args->minlen)
			return;
	} else {
		if ((int)(rlen = rlen - args->prod - (args->mod - k)) <
		    (int)args->minlen)
			return;
	}
	ASSERT(rlen >= args->minlen);
	ASSERT(rlen <= args->maxlen);
	args->len = rlen;
}

/*
 * Fix up length if there is too little space left in the a.g.
 * Return 1 if ok, 0 if too little, should give up.
 */
STATIC int
xfs_alloc_fix_minleft(
	xfs_alloc_arg_t	*args)		/* allocation argument structure */
{
	xfs_agf_t	*agf;		/* a.g. freelist header */
	int		diff;		/* free space difference */

	if (args->minleft == 0)
		return 1;
	agf = XFS_BUF_TO_AGF(args->agbp);
	diff = be32_to_cpu(agf->agf_freeblks)
		- args->len - args->minleft;
	if (diff >= 0)
		return 1;
	args->len += diff;		/* shrink the allocated space */
	if (args->len >= args->minlen)
		return 1;
	args->agbno = NULLAGBLOCK;
	return 0;
}

static void
xfs_agfl_verify(
	struct xfs_buf	*bp)
{
#ifdef WHEN_CRCS_COME_ALONG
	/*
	 * we cannot actually do any verification of the AGFL because mkfs does
	 * not initialise the AGFL to zero or NULL. Hence the only valid part of
	 * the AGFL is what the AGF says is active. We can't get to the AGF, so
	 * we can't verify just those entries are valid.
	 *
	 * This problem goes away when the CRC format change comes along as that
	 * requires the AGFL to be initialised by mkfs. At that point, we can
	 * verify the blocks in the agfl -active or not- lie within the bounds
	 * of the AG. Until then, just leave this check ifdef'd out.
	 */
	struct xfs_mount *mp = bp->b_target->bt_mount;
	struct xfs_agfl	*agfl = XFS_BUF_TO_AGFL(bp);
	int		agfl_ok = 1;

	int		i;

	for (i = 0; i < XFS_AGFL_SIZE(mp); i++) {
		if (be32_to_cpu(agfl->agfl_bno[i]) == NULLAGBLOCK ||
		    be32_to_cpu(agfl->agfl_bno[i]) >= mp->m_sb.sb_agblocks)
			agfl_ok = 0;
	}

	if (!agfl_ok) {
		XFS_CORRUPTION_ERROR(__func__, XFS_ERRLEVEL_LOW, mp, agfl);
		xfs_buf_ioerror(bp, EFSCORRUPTED);
	}
#endif
}

static void
xfs_agfl_write_verify(
	struct xfs_buf	*bp)
{
	xfs_agfl_verify(bp);
}

static void
xfs_agfl_read_verify(
	struct xfs_buf	*bp)
{
	xfs_agfl_verify(bp);
}

const struct xfs_buf_ops xfs_agfl_buf_ops = {
	.verify_read = xfs_agfl_read_verify,
	.verify_write = xfs_agfl_write_verify,
};

/*
 * Read in the allocation group free block array.
 */
STATIC int				/* error */
xfs_alloc_read_agfl(
	xfs_mount_t	*mp,		/* mount point structure */
	xfs_trans_t	*tp,		/* transaction pointer */
	xfs_agnumber_t	agno,		/* allocation group number */
	xfs_buf_t	**bpp)		/* buffer for the ag free block array */
{
	xfs_buf_t	*bp;		/* return value */
	int		error;

	ASSERT(agno != NULLAGNUMBER);
	error = xfs_trans_read_buf(
			mp, tp, mp->m_ddev_targp,
			XFS_AG_DADDR(mp, agno, XFS_AGFL_DADDR(mp)),
			XFS_FSS_TO_BB(mp, 1), 0, &bp, &xfs_agfl_buf_ops);
	if (error)
		return error;
	ASSERT(!xfs_buf_geterror(bp));
	xfs_buf_set_ref(bp, XFS_AGFL_REF);
	*bpp = bp;
	return 0;
}

/*
 * Search the btree in a given direction via the search cursor and compare
 * the records found against the good extent we've already found.
 */
STATIC int
xfs_alloc_find_best_extent(
	struct xfs_alloc_arg	*args,	/* allocation argument structure */
	struct xfs_btree_cur	**gcur,	/* good cursor */
	struct xfs_btree_cur	**scur,	/* searching cursor */
	xfs_agblock_t		gdiff,	/* difference for search comparison */
	xfs_agblock_t		*sbno,	/* extent found by search */
	xfs_extlen_t		*slen,	/* extent length */
	xfs_agblock_t		*sbnoa,	/* aligned extent found by search */
	xfs_extlen_t		*slena,	/* aligned extent length */
	int			dir)	/* 0 = search right, 1 = search left */
{
	xfs_agblock_t		new;
	xfs_agblock_t		sdiff;
	int			error;
	int			i;

	/* The good extent is perfect, no need to  search. */
	if (!gdiff)
		goto out_use_good;

	/*
	 * Look until we find a better one, run out of space or run off the end.
	 */
	do {
		error = xfs_alloc_get_rec(*scur, sbno, slen, &i);
		if (error)
			goto error0;
		XFS_WANT_CORRUPTED_GOTO(i == 1, error0);
		xfs_alloc_compute_aligned(args, *sbno, *slen, sbnoa, slena);

		/*
		 * The good extent is closer than this one.
		 */
		if (!dir) {
			if (*sbnoa >= args->agbno + gdiff)
				goto out_use_good;
		} else {
			if (*sbnoa <= args->agbno - gdiff)
				goto out_use_good;
		}

		/*
		 * Same distance, compare length and pick the best.
		 */
		if (*slena >= args->minlen) {
			args->len = XFS_EXTLEN_MIN(*slena, args->maxlen);
			xfs_alloc_fix_len(args);

			sdiff = xfs_alloc_compute_diff(args->agbno, args->len,
						       args->alignment, *sbnoa,
						       *slena, &new);

			/*
			 * Choose closer size and invalidate other cursor.
			 */
			if (sdiff < gdiff)
				goto out_use_search;
			goto out_use_good;
		}

		if (!dir)
			error = xfs_btree_increment(*scur, 0, &i);
		else
			error = xfs_btree_decrement(*scur, 0, &i);
		if (error)
			goto error0;
	} while (i);

out_use_good:
	xfs_btree_del_cursor(*scur, XFS_BTREE_NOERROR);
	*scur = NULL;
	return 0;

out_use_search:
	xfs_btree_del_cursor(*gcur, XFS_BTREE_NOERROR);
	*gcur = NULL;
	return 0;

error0:
	/* caller invalidates cursors */
	return error;
}

/*
 * Visible (exported) allocation/free functions.
 * Some of these are used just by xfs_alloc_btree.c and this file.
 */

/*
 * Compute and fill in value of m_ag_maxlevels.
 */
void
xfs_alloc_compute_maxlevels(
	xfs_mount_t	*mp)	/* file system mount structure */
{
	int		level;
	uint		maxblocks;
	uint		maxleafents;
	int		minleafrecs;
	int		minnoderecs;

	maxleafents = (mp->m_sb.sb_agblocks + 1) / 2;
	minleafrecs = mp->m_alloc_mnr[0];
	minnoderecs = mp->m_alloc_mnr[1];
	maxblocks = (maxleafents + minleafrecs - 1) / minleafrecs;
	for (level = 1; maxblocks > 1; level++)
		maxblocks = (maxblocks + minnoderecs - 1) / minnoderecs;
	mp->m_ag_maxlevels = level;
}

/*
 * Find the length of the longest extent in an AG.
 */
xfs_extlen_t
xfs_alloc_longest_free_extent(
	struct xfs_mount	*mp,
	struct xfs_perag	*pag)
{
	xfs_extlen_t		need, delta = 0;

	need = XFS_MIN_FREELIST_PAG(pag, mp);
	if (need > pag->pagf_flcount)
		delta = need - pag->pagf_flcount;

	if (pag->pagf_longest > delta)
		return pag->pagf_longest - delta;
	return pag->pagf_flcount > 0 || pag->pagf_longest > 0;
}

/*
 * Interface for inode allocation to force the pag data to be initialized.
 */
int					/* error */
xfs_alloc_pagf_init(
	xfs_mount_t		*mp,	/* file system mount structure */
	xfs_trans_t		*tp,	/* transaction pointer */
	xfs_agnumber_t		agno,	/* allocation group number */
	int			flags)	/* XFS_ALLOC_FLAGS_... */
{
	xfs_buf_t		*bp;
	int			error;

	if ((error = xfs_alloc_read_agf(mp, tp, agno, flags, &bp)))
		return error;
	if (bp)
		xfs_trans_brelse(tp, bp);
	return 0;
}

static void
xfs_agf_verify(
	struct xfs_buf	*bp)
{
	struct xfs_mount *mp = bp->b_target->bt_mount;
	struct xfs_agf	*agf;
	int		agf_ok;

	agf = XFS_BUF_TO_AGF(bp);

	agf_ok = agf->agf_magicnum == cpu_to_be32(XFS_AGF_MAGIC) &&
		XFS_AGF_GOOD_VERSION(be32_to_cpu(agf->agf_versionnum)) &&
		be32_to_cpu(agf->agf_freeblks) <= be32_to_cpu(agf->agf_length) &&
		be32_to_cpu(agf->agf_flfirst) < XFS_AGFL_SIZE(mp) &&
		be32_to_cpu(agf->agf_fllast) < XFS_AGFL_SIZE(mp) &&
		be32_to_cpu(agf->agf_flcount) <= XFS_AGFL_SIZE(mp);

	/*
	 * during growfs operations, the perag is not fully initialised,
	 * so we can't use it for any useful checking. growfs ensures we can't
	 * use it by using uncached buffers that don't have the perag attached
	 * so we can detect and avoid this problem.
	 */
	if (bp->b_pag)
		agf_ok = agf_ok && be32_to_cpu(agf->agf_seqno) ==
						bp->b_pag->pag_agno;

	if (xfs_sb_version_haslazysbcount(&mp->m_sb))
		agf_ok = agf_ok && be32_to_cpu(agf->agf_btreeblks) <=
						be32_to_cpu(agf->agf_length);

	if (unlikely(XFS_TEST_ERROR(!agf_ok, mp, XFS_ERRTAG_ALLOC_READ_AGF,
			XFS_RANDOM_ALLOC_READ_AGF))) {
		XFS_CORRUPTION_ERROR(__func__, XFS_ERRLEVEL_LOW, mp, agf);
		xfs_buf_ioerror(bp, EFSCORRUPTED);
	}
}

static void
xfs_agf_read_verify(
	struct xfs_buf	*bp)
{
	xfs_agf_verify(bp);
}

static void
xfs_agf_write_verify(
	struct xfs_buf	*bp)
{
	xfs_agf_verify(bp);
}

const struct xfs_buf_ops xfs_agf_buf_ops = {
	.verify_read = xfs_agf_read_verify,
	.verify_write = xfs_agf_write_verify,
};

/*
 * Read in the allocation group header (free/alloc section).
 */
int					/* error */
xfs_read_agf(
	struct xfs_mount	*mp,	/* mount point structure */
	struct xfs_trans	*tp,	/* transaction pointer */
	xfs_agnumber_t		agno,	/* allocation group number */
	int			flags,	/* XFS_BUF_ */
	struct xfs_buf		**bpp)	/* buffer for the ag freelist header */
{
	int		error;

	ASSERT(agno != NULLAGNUMBER);
	error = xfs_trans_read_buf(
			mp, tp, mp->m_ddev_targp,
			XFS_AG_DADDR(mp, agno, XFS_AGF_DADDR(mp)),
			XFS_FSS_TO_BB(mp, 1), flags, bpp, &xfs_agf_buf_ops);
	if (error)
		return error;
	if (!*bpp)
		return 0;

	ASSERT(!(*bpp)->b_error);
	xfs_buf_set_ref(*bpp, XFS_AGF_REF);
	return 0;
}

/*
 * Read in the allocation group header (free/alloc section).
 */
int					/* error */
xfs_alloc_read_agf(
	struct xfs_mount	*mp,	/* mount point structure */
	struct xfs_trans	*tp,	/* transaction pointer */
	xfs_agnumber_t		agno,	/* allocation group number */
	int			flags,	/* XFS_ALLOC_FLAG_... */
	struct xfs_buf		**bpp)	/* buffer for the ag freelist header */
{
	struct xfs_agf		*agf;		/* ag freelist header */
	struct xfs_perag	*pag;		/* per allocation group data */
	int			error;

	ASSERT(agno != NULLAGNUMBER);

	error = xfs_read_agf(mp, tp, agno,
			(flags & XFS_ALLOC_FLAG_TRYLOCK) ? XBF_TRYLOCK : 0,
			bpp);
	if (error)
		return error;
	if (!*bpp)
		return 0;
	ASSERT(!(*bpp)->b_error);

	agf = XFS_BUF_TO_AGF(*bpp);
	pag = xfs_perag_get(mp, agno);
	if (!pag->pagf_init) {
		pag->pagf_freeblks = be32_to_cpu(agf->agf_freeblks);
		pag->pagf_btreeblks = be32_to_cpu(agf->agf_btreeblks);
		pag->pagf_flcount = be32_to_cpu(agf->agf_flcount);
		pag->pagf_longest = be32_to_cpu(agf->agf_longest);
		pag->pagf_levels[XFS_BTNUM_BNOi] =
			be32_to_cpu(agf->agf_levels[XFS_BTNUM_BNOi]);
		pag->pagf_levels[XFS_BTNUM_CNTi] =
			be32_to_cpu(agf->agf_levels[XFS_BTNUM_CNTi]);
		spin_lock_init(&pag->pagb_lock);
		pag->pagb_count = 0;
		pag->pagb_tree = RB_ROOT;
		pag->pagf_init = 1;
	}
#ifdef DEBUG
	else if (!XFS_FORCED_SHUTDOWN(mp)) {
		ASSERT(pag->pagf_freeblks == be32_to_cpu(agf->agf_freeblks));
		ASSERT(pag->pagf_btreeblks == be32_to_cpu(agf->agf_btreeblks));
		ASSERT(pag->pagf_flcount == be32_to_cpu(agf->agf_flcount));
		ASSERT(pag->pagf_longest == be32_to_cpu(agf->agf_longest));
		ASSERT(pag->pagf_levels[XFS_BTNUM_BNOi] ==
		       be32_to_cpu(agf->agf_levels[XFS_BTNUM_BNOi]));
		ASSERT(pag->pagf_levels[XFS_BTNUM_CNTi] ==
		       be32_to_cpu(agf->agf_levels[XFS_BTNUM_CNTi]));
	}
#endif
	xfs_perag_put(pag);
	return 0;
}
