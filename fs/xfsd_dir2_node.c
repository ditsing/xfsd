/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
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
#include "xfsd_types.h"

#include "xfs/xfs_fs.h"
#include "xfs/xfs_types.h"
#include "xfs/xfs_log.h"
#include "xfsd_trans.h"
#include "xfs/xfs_sb.h"
#include "xfs/xfs_ag.h"
#include "xfs/xfs_mount.h"
#include "xfs/xfs_da_btree.h"
#include "xfs/xfs_bmap_btree.h"
#include "xfs/xfs_dinode.h"
#include "xfs/xfs_inode.h"
#include "xfs/xfs_bmap.h"
#include "xfs/xfs_dir2_format.h"
#include "xfs/xfs_dir2_priv.h"
#include "xfs/xfs_error.h"

#include "xfsd_trace.h"

/*
 * Function declarations.
 */
static int xfs_dir2_leafn_add(struct xfs_buf *bp, xfs_da_args_t *args,
			      int index);
#ifdef DEBUG
static void xfs_dir2_leafn_check(struct xfs_inode *dp, struct xfs_buf *bp);
#else
#define	xfs_dir2_leafn_check(dp, bp)
#endif
static void xfs_dir2_leafn_moveents(xfs_da_args_t *args, struct xfs_buf *bp_s,
				    int start_s, struct xfs_buf *bp_d,
				    int start_d, int count);
static void xfs_dir2_leafn_rebalance(xfs_da_state_t *state,
				     xfs_da_state_blk_t *blk1,
				     xfs_da_state_blk_t *blk2);
static int xfs_dir2_leafn_remove(xfs_da_args_t *args, struct xfs_buf *bp,
				 int index, xfs_da_state_blk_t *dblk,
				 int *rval);
static int xfs_dir2_node_addname_int(xfs_da_args_t *args,
				     xfs_da_state_blk_t *fblk);

static void
xfs_dir2_free_verify(
	struct xfs_buf		*bp)
{
	struct xfs_mount	*mp = bp->b_target->bt_mount;
	struct xfs_dir2_free_hdr *hdr = bp->b_addr;
	int			block_ok = 0;

	block_ok = hdr->magic == cpu_to_be32(XFS_DIR2_FREE_MAGIC);
	if (!block_ok) {
		XFS_CORRUPTION_ERROR("xfs_dir2_free_verify magic",
				     XFS_ERRLEVEL_LOW, mp, hdr);
		xfs_buf_ioerror(bp, EFSCORRUPTED);
	}
}

static void
xfs_dir2_free_read_verify(
	struct xfs_buf	*bp)
{
	xfs_dir2_free_verify(bp);
}

static void
xfs_dir2_free_write_verify(
	struct xfs_buf	*bp)
{
	xfs_dir2_free_verify(bp);
}

static const struct xfs_buf_ops xfs_dir2_free_buf_ops = {
	.verify_read = xfs_dir2_free_read_verify,
	.verify_write = xfs_dir2_free_write_verify,
};


static int
__xfs_dir2_free_read(
	struct xfs_trans	*tp,
	struct xfs_inode	*dp,
	xfs_dablk_t		fbno,
	xfs_daddr_t		mappedbno,
	struct xfs_buf		**bpp)
{
	return xfs_da_read_buf(tp, dp, fbno, mappedbno, bpp,
				XFS_DATA_FORK, &xfs_dir2_free_buf_ops);
}

int
xfs_dir2_free_read(
	struct xfs_trans	*tp,
	struct xfs_inode	*dp,
	xfs_dablk_t		fbno,
	struct xfs_buf		**bpp)
{
	return __xfs_dir2_free_read(tp, dp, fbno, -1, bpp);
}

static int
xfs_dir2_free_try_read(
	struct xfs_trans	*tp,
	struct xfs_inode	*dp,
	xfs_dablk_t		fbno,
	struct xfs_buf		**bpp)
{
	return __xfs_dir2_free_read(tp, dp, fbno, -2, bpp);
}

#ifdef DEBUG
/*
 * Check internal consistency of a leafn block.
 */
void
xfs_dir2_leafn_check(
	struct xfs_inode *dp,
	struct xfs_buf	*bp)
{
	int		i;			/* leaf index */
	xfs_dir2_leaf_t	*leaf;			/* leaf structure */
	xfs_mount_t	*mp;			/* filesystem mount point */
	int		stale;			/* count of stale leaves */

	leaf = bp->b_addr;
	mp = dp->i_mount;
	ASSERT(leaf->hdr.info.magic == cpu_to_be16(XFS_DIR2_LEAFN_MAGIC));
	ASSERT(be16_to_cpu(leaf->hdr.count) <= xfs_dir2_max_leaf_ents(mp));
	for (i = stale = 0; i < be16_to_cpu(leaf->hdr.count); i++) {
		if (i + 1 < be16_to_cpu(leaf->hdr.count)) {
			ASSERT(be32_to_cpu(leaf->ents[i].hashval) <=
			       be32_to_cpu(leaf->ents[i + 1].hashval));
		}
		if (leaf->ents[i].address == cpu_to_be32(XFS_DIR2_NULL_DATAPTR))
			stale++;
	}
	ASSERT(be16_to_cpu(leaf->hdr.stale) == stale);
}
#endif	/* DEBUG */

/*
 * Return the last hash value in the leaf.
 * Stale entries are ok.
 */
xfs_dahash_t					/* hash value */
xfs_dir2_leafn_lasthash(
	struct xfs_buf	*bp,			/* leaf buffer */
	int		*count)			/* count of entries in leaf */
{
	xfs_dir2_leaf_t	*leaf;			/* leaf structure */

	leaf = bp->b_addr;
	ASSERT(leaf->hdr.info.magic == cpu_to_be16(XFS_DIR2_LEAFN_MAGIC));
	if (count)
		*count = be16_to_cpu(leaf->hdr.count);
	if (!leaf->hdr.count)
		return 0;
	return be32_to_cpu(leaf->ents[be16_to_cpu(leaf->hdr.count) - 1].hashval);
}

/*
 * Look up a leaf entry for space to add a name in a node-format leaf block.
 * The extrablk in state is a freespace block.
 */
STATIC int
xfs_dir2_leafn_lookup_for_addname(
	struct xfs_buf		*bp,		/* leaf buffer */
	xfs_da_args_t		*args,		/* operation arguments */
	int			*indexp,	/* out: leaf entry index */
	xfs_da_state_t		*state)		/* state to fill in */
{
	struct xfs_buf		*curbp = NULL;	/* current data/free buffer */
	xfs_dir2_db_t		curdb = -1;	/* current data block number */
	xfs_dir2_db_t		curfdb = -1;	/* current free block number */
	xfs_inode_t		*dp;		/* incore directory inode */
	int			error;		/* error return value */
	int			fi;		/* free entry index */
	xfs_dir2_free_t		*free = NULL;	/* free block structure */
	int			index;		/* leaf entry index */
	xfs_dir2_leaf_t		*leaf;		/* leaf structure */
	int			length;		/* length of new data entry */
	xfs_dir2_leaf_entry_t	*lep;		/* leaf entry */
	xfs_mount_t		*mp;		/* filesystem mount point */
	xfs_dir2_db_t		newdb;		/* new data block number */
	xfs_dir2_db_t		newfdb;		/* new free block number */
	xfs_trans_t		*tp;		/* transaction pointer */

	dp = args->dp;
	tp = args->trans;
	mp = dp->i_mount;
	leaf = bp->b_addr;
	ASSERT(leaf->hdr.info.magic == cpu_to_be16(XFS_DIR2_LEAFN_MAGIC));
#ifdef __KERNEL__
	ASSERT(be16_to_cpu(leaf->hdr.count) > 0);
#endif
	xfs_dir2_leafn_check(dp, bp);
	/*
	 * Look up the hash value in the leaf entries.
	 */
	index = xfs_dir2_leaf_search_hash(args, bp);
	/*
	 * Do we have a buffer coming in?
	 */
	if (state->extravalid) {
		/* If so, it's a free block buffer, get the block number. */
		curbp = state->extrablk.bp;
		curfdb = state->extrablk.blkno;
		free = curbp->b_addr;
		ASSERT(free->hdr.magic == cpu_to_be32(XFS_DIR2_FREE_MAGIC));
	}
	length = xfs_dir2_data_entsize(args->namelen);
	/*
	 * Loop over leaf entries with the right hash value.
	 */
	for (lep = &leaf->ents[index]; index < be16_to_cpu(leaf->hdr.count) &&
				be32_to_cpu(lep->hashval) == args->hashval;
				lep++, index++) {
		/*
		 * Skip stale leaf entries.
		 */
		if (be32_to_cpu(lep->address) == XFS_DIR2_NULL_DATAPTR)
			continue;
		/*
		 * Pull the data block number from the entry.
		 */
		newdb = xfs_dir2_dataptr_to_db(mp, be32_to_cpu(lep->address));
		/*
		 * For addname, we're looking for a place to put the new entry.
		 * We want to use a data block with an entry of equal
		 * hash value to ours if there is one with room.
		 *
		 * If this block isn't the data block we already have
		 * in hand, take a look at it.
		 */
		if (newdb != curdb) {
			curdb = newdb;
			/*
			 * Convert the data block to the free block
			 * holding its freespace information.
			 */
			newfdb = xfs_dir2_db_to_fdb(mp, newdb);
			/*
			 * If it's not the one we have in hand, read it in.
			 */
			if (newfdb != curfdb) {
				/*
				 * If we had one before, drop it.
				 */
				if (curbp)
					xfs_trans_brelse(tp, curbp);

				error = xfs_dir2_free_read(tp, dp,
						xfs_dir2_db_to_da(mp, newfdb),
						&curbp);
				if (error)
					return error;
				free = curbp->b_addr;
				ASSERT(be32_to_cpu(free->hdr.magic) ==
					XFS_DIR2_FREE_MAGIC);
				ASSERT((be32_to_cpu(free->hdr.firstdb) %
					xfs_dir2_free_max_bests(mp)) == 0);
				ASSERT(be32_to_cpu(free->hdr.firstdb) <= curdb);
				ASSERT(curdb < be32_to_cpu(free->hdr.firstdb) +
					be32_to_cpu(free->hdr.nvalid));
			}
			/*
			 * Get the index for our entry.
			 */
			fi = xfs_dir2_db_to_fdindex(mp, curdb);
			/*
			 * If it has room, return it.
			 */
			if (unlikely(free->bests[fi] ==
			    cpu_to_be16(NULLDATAOFF))) {
				XFS_ERROR_REPORT("xfs_dir2_leafn_lookup_int",
							XFS_ERRLEVEL_LOW, mp);
				if (curfdb != newfdb)
					xfs_trans_brelse(tp, curbp);
				return XFS_ERROR(EFSCORRUPTED);
			}
			curfdb = newfdb;
			if (be16_to_cpu(free->bests[fi]) >= length)
				goto out;
		}
	}
	/* Didn't find any space */
	fi = -1;
out:
	ASSERT(args->op_flags & XFS_DA_OP_OKNOENT);
	if (curbp) {
		/* Giving back a free block. */
		state->extravalid = 1;
		state->extrablk.bp = curbp;
		state->extrablk.index = fi;
		state->extrablk.blkno = curfdb;
		state->extrablk.magic = XFS_DIR2_FREE_MAGIC;
	} else {
		state->extravalid = 0;
	}
	/*
	 * Return the index, that will be the insertion point.
	 */
	*indexp = index;
	return XFS_ERROR(ENOENT);
}

/*
 * Look up a leaf entry in a node-format leaf block.
 * The extrablk in state a data block.
 */
STATIC int
xfs_dir2_leafn_lookup_for_entry(
	struct xfs_buf		*bp,		/* leaf buffer */
	xfs_da_args_t		*args,		/* operation arguments */
	int			*indexp,	/* out: leaf entry index */
	xfs_da_state_t		*state)		/* state to fill in */
{
	struct xfs_buf		*curbp = NULL;	/* current data/free buffer */
	xfs_dir2_db_t		curdb = -1;	/* current data block number */
	xfs_dir2_data_entry_t	*dep;		/* data block entry */
	xfs_inode_t		*dp;		/* incore directory inode */
	int			error;		/* error return value */
	int			index;		/* leaf entry index */
	xfs_dir2_leaf_t		*leaf;		/* leaf structure */
	xfs_dir2_leaf_entry_t	*lep;		/* leaf entry */
	xfs_mount_t		*mp;		/* filesystem mount point */
	xfs_dir2_db_t		newdb;		/* new data block number */
	xfs_trans_t		*tp;		/* transaction pointer */
	enum xfs_dacmp		cmp;		/* comparison result */

	dp = args->dp;
	tp = args->trans;
	mp = dp->i_mount;
	leaf = bp->b_addr;
	ASSERT(leaf->hdr.info.magic == cpu_to_be16(XFS_DIR2_LEAFN_MAGIC));
#ifdef __KERNEL__
	ASSERT(be16_to_cpu(leaf->hdr.count) > 0);
#endif
	xfs_dir2_leafn_check(dp, bp);
	/*
	 * Look up the hash value in the leaf entries.
	 */
	index = xfs_dir2_leaf_search_hash(args, bp);
	/*
	 * Do we have a buffer coming in?
	 */
	if (state->extravalid) {
		curbp = state->extrablk.bp;
		curdb = state->extrablk.blkno;
	}
	/*
	 * Loop over leaf entries with the right hash value.
	 */
	for (lep = &leaf->ents[index]; index < be16_to_cpu(leaf->hdr.count) &&
				be32_to_cpu(lep->hashval) == args->hashval;
				lep++, index++) {
		/*
		 * Skip stale leaf entries.
		 */
		if (be32_to_cpu(lep->address) == XFS_DIR2_NULL_DATAPTR)
			continue;
		/*
		 * Pull the data block number from the entry.
		 */
		newdb = xfs_dir2_dataptr_to_db(mp, be32_to_cpu(lep->address));
		/*
		 * Not adding a new entry, so we really want to find
		 * the name given to us.
		 *
		 * If it's a different data block, go get it.
		 */
		if (newdb != curdb) {
			/*
			 * If we had a block before that we aren't saving
			 * for a CI name, drop it
			 */
			if (curbp && (args->cmpresult == XFS_CMP_DIFFERENT ||
						curdb != state->extrablk.blkno))
				xfs_trans_brelse(tp, curbp);
			/*
			 * If needing the block that is saved with a CI match,
			 * use it otherwise read in the new data block.
			 */
			if (args->cmpresult != XFS_CMP_DIFFERENT &&
					newdb == state->extrablk.blkno) {
				ASSERT(state->extravalid);
				curbp = state->extrablk.bp;
			} else {
				error = xfs_dir2_data_read(tp, dp,
						xfs_dir2_db_to_da(mp, newdb),
						-1, &curbp);
				if (error)
					return error;
			}
			xfs_dir2_data_check(dp, curbp);
			curdb = newdb;
		}
		/*
		 * Point to the data entry.
		 */
		dep = (xfs_dir2_data_entry_t *)((char *)curbp->b_addr +
			xfs_dir2_dataptr_to_off(mp, be32_to_cpu(lep->address)));
		/*
		 * Compare the entry and if it's an exact match, return
		 * EEXIST immediately. If it's the first case-insensitive
		 * match, store the block & inode number and continue looking.
		 */
		cmp = mp->m_dirnameops->compname(args, dep->name, dep->namelen);
		if (cmp != XFS_CMP_DIFFERENT && cmp != args->cmpresult) {
			/* If there is a CI match block, drop it */
			if (args->cmpresult != XFS_CMP_DIFFERENT &&
						curdb != state->extrablk.blkno)
				xfs_trans_brelse(tp, state->extrablk.bp);
			args->cmpresult = cmp;
			args->inumber = be64_to_cpu(dep->inumber);
			*indexp = index;
			state->extravalid = 1;
			state->extrablk.bp = curbp;
			state->extrablk.blkno = curdb;
			state->extrablk.index = (int)((char *)dep -
							(char *)curbp->b_addr);
			state->extrablk.magic = XFS_DIR2_DATA_MAGIC;
			curbp->b_ops = &xfs_dir2_data_buf_ops;
			if (cmp == XFS_CMP_EXACT)
				return XFS_ERROR(EEXIST);
		}
	}
	ASSERT(index == be16_to_cpu(leaf->hdr.count) ||
					(args->op_flags & XFS_DA_OP_OKNOENT));
	if (curbp) {
		if (args->cmpresult == XFS_CMP_DIFFERENT) {
			/* Giving back last used data block. */
			state->extravalid = 1;
			state->extrablk.bp = curbp;
			state->extrablk.index = -1;
			state->extrablk.blkno = curdb;
			state->extrablk.magic = XFS_DIR2_DATA_MAGIC;
			curbp->b_ops = &xfs_dir2_data_buf_ops;
		} else {
			/* If the curbp is not the CI match block, drop it */
			if (state->extrablk.bp != curbp)
				xfs_trans_brelse(tp, curbp);
		}
	} else {
		state->extravalid = 0;
	}
	*indexp = index;
	return XFS_ERROR(ENOENT);
}

/*
 * Look up a leaf entry in a node-format leaf block.
 * If this is an addname then the extrablk in state is a freespace block,
 * otherwise it's a data block.
 */
int
xfs_dir2_leafn_lookup_int(
	struct xfs_buf		*bp,		/* leaf buffer */
	xfs_da_args_t		*args,		/* operation arguments */
	int			*indexp,	/* out: leaf entry index */
	xfs_da_state_t		*state)		/* state to fill in */
{
	if (args->op_flags & XFS_DA_OP_ADDNAME)
		return xfs_dir2_leafn_lookup_for_addname(bp, args, indexp,
							state);
	return xfs_dir2_leafn_lookup_for_entry(bp, args, indexp, state);
}

/*
 * Determine the sort order of two leaf blocks.
 * Returns 1 if both are valid and leaf2 should be before leaf1, else 0.
 */
int						/* sort order */
xfs_dir2_leafn_order(
	struct xfs_buf	*leaf1_bp,		/* leaf1 buffer */
	struct xfs_buf	*leaf2_bp)		/* leaf2 buffer */
{
	xfs_dir2_leaf_t	*leaf1;			/* leaf1 structure */
	xfs_dir2_leaf_t	*leaf2;			/* leaf2 structure */

	leaf1 = leaf1_bp->b_addr;
	leaf2 = leaf2_bp->b_addr;
	ASSERT(leaf1->hdr.info.magic == cpu_to_be16(XFS_DIR2_LEAFN_MAGIC));
	ASSERT(leaf2->hdr.info.magic == cpu_to_be16(XFS_DIR2_LEAFN_MAGIC));
	if (be16_to_cpu(leaf1->hdr.count) > 0 &&
	    be16_to_cpu(leaf2->hdr.count) > 0 &&
	    (be32_to_cpu(leaf2->ents[0].hashval) < be32_to_cpu(leaf1->ents[0].hashval) ||
	     be32_to_cpu(leaf2->ents[be16_to_cpu(leaf2->hdr.count) - 1].hashval) <
	     be32_to_cpu(leaf1->ents[be16_to_cpu(leaf1->hdr.count) - 1].hashval)))
		return 1;
	return 0;
}

/*
 * Check a leaf block and its neighbors to see if the block should be
 * collapsed into one or the other neighbor.  Always keep the block
 * with the smaller block number.
 * If the current block is over 50% full, don't try to join it, return 0.
 * If the block is empty, fill in the state structure and return 2.
 * If it can be collapsed, fill in the state structure and return 1.
 * If nothing can be done, return 0.
 */
int						/* error */
xfs_dir2_leafn_toosmall(
	xfs_da_state_t		*state,		/* btree cursor */
	int			*action)	/* resulting action to take */
{
	xfs_da_state_blk_t	*blk;		/* leaf block */
	xfs_dablk_t		blkno;		/* leaf block number */
	struct xfs_buf		*bp;		/* leaf buffer */
	int			bytes;		/* bytes in use */
	int			count;		/* leaf live entry count */
	int			error;		/* error return value */
	int			forward;	/* sibling block direction */
	int			i;		/* sibling counter */
	xfs_da_blkinfo_t	*info;		/* leaf block header */
	xfs_dir2_leaf_t		*leaf;		/* leaf structure */
	int			rval;		/* result from path_shift */

	/*
	 * Check for the degenerate case of the block being over 50% full.
	 * If so, it's not worth even looking to see if we might be able
	 * to coalesce with a sibling.
	 */
	blk = &state->path.blk[state->path.active - 1];
	info = blk->bp->b_addr;
	ASSERT(info->magic == cpu_to_be16(XFS_DIR2_LEAFN_MAGIC));
	leaf = (xfs_dir2_leaf_t *)info;
	count = be16_to_cpu(leaf->hdr.count) - be16_to_cpu(leaf->hdr.stale);
	bytes = (uint)sizeof(leaf->hdr) + count * (uint)sizeof(leaf->ents[0]);
	if (bytes > (state->blocksize >> 1)) {
		/*
		 * Blk over 50%, don't try to join.
		 */
		*action = 0;
		return 0;
	}
	/*
	 * Check for the degenerate case of the block being empty.
	 * If the block is empty, we'll simply delete it, no need to
	 * coalesce it with a sibling block.  We choose (arbitrarily)
	 * to merge with the forward block unless it is NULL.
	 */
	if (count == 0) {
		/*
		 * Make altpath point to the block we want to keep and
		 * path point to the block we want to drop (this one).
		 */
		forward = (info->forw != 0);
		memcpy(&state->altpath, &state->path, sizeof(state->path));
		error = xfs_da_path_shift(state, &state->altpath, forward, 0,
			&rval);
		if (error)
			return error;
		*action = rval ? 2 : 0;
		return 0;
	}
	/*
	 * Examine each sibling block to see if we can coalesce with
	 * at least 25% free space to spare.  We need to figure out
	 * whether to merge with the forward or the backward block.
	 * We prefer coalescing with the lower numbered sibling so as
	 * to shrink a directory over time.
	 */
	forward = be32_to_cpu(info->forw) < be32_to_cpu(info->back);
	for (i = 0, bp = NULL; i < 2; forward = !forward, i++) {
		blkno = forward ? be32_to_cpu(info->forw) : be32_to_cpu(info->back);
		if (blkno == 0)
			continue;
		/*
		 * Read the sibling leaf block.
		 */
		error = xfs_dir2_leafn_read(state->args->trans, state->args->dp,
					    blkno, -1, &bp);
		if (error)
			return error;

		/*
		 * Count bytes in the two blocks combined.
		 */
		leaf = (xfs_dir2_leaf_t *)info;
		count = be16_to_cpu(leaf->hdr.count) - be16_to_cpu(leaf->hdr.stale);
		bytes = state->blocksize - (state->blocksize >> 2);
		leaf = bp->b_addr;
		ASSERT(leaf->hdr.info.magic == cpu_to_be16(XFS_DIR2_LEAFN_MAGIC));
		count += be16_to_cpu(leaf->hdr.count) - be16_to_cpu(leaf->hdr.stale);
		bytes -= count * (uint)sizeof(leaf->ents[0]);
		/*
		 * Fits with at least 25% to spare.
		 */
		if (bytes >= 0)
			break;
		xfs_trans_brelse(state->args->trans, bp);
	}
	/*
	 * Didn't like either block, give up.
	 */
	if (i >= 2) {
		*action = 0;
		return 0;
	}

	/*
	 * Make altpath point to the block we want to keep (the lower
	 * numbered block) and path point to the block we want to drop.
	 */
	memcpy(&state->altpath, &state->path, sizeof(state->path));
	if (blkno < blk->blkno)
		error = xfs_da_path_shift(state, &state->altpath, forward, 0,
			&rval);
	else
		error = xfs_da_path_shift(state, &state->path, forward, 0,
			&rval);
	if (error) {
		return error;
	}
	*action = rval ? 0 : 1;
	return 0;
}

/*
 * Lookup an entry in a node-format directory.
 * All the real work happens in xfs_da_node_lookup_int.
 * The only real output is the inode number of the entry.
 */
int						/* error */
xfs_dir2_node_lookup(
	xfs_da_args_t	*args)			/* operation arguments */
{
	int		error;			/* error return value */
	int		i;			/* btree level */
	int		rval;			/* operation return value */
	xfs_da_state_t	*state;			/* btree cursor */

	trace_xfs_dir2_node_lookup(args);

	/*
	 * Allocate and initialize the btree cursor.
	 */
	state = xfs_da_state_alloc();
	state->args = args;
	state->mp = args->dp->i_mount;
	state->blocksize = state->mp->m_dirblksize;
	state->node_ents = state->mp->m_dir_node_ents;
	/*
	 * Fill in the path to the entry in the cursor.
	 */
	error = xfs_da_node_lookup_int(state, &rval);
	if (error)
		rval = error;
	else if (rval == ENOENT && args->cmpresult == XFS_CMP_CASE) {
		/* If a CI match, dup the actual name and return EEXIST */
		xfs_dir2_data_entry_t	*dep;

		dep = (xfs_dir2_data_entry_t *)
			((char *)state->extrablk.bp->b_addr +
						 state->extrablk.index);
		rval = xfs_dir_cilookup_result(args, dep->name, dep->namelen);
	}
	/*
	 * Release the btree blocks and leaf block.
	 */
	for (i = 0; i < state->path.active; i++) {
		xfs_trans_brelse(args->trans, state->path.blk[i].bp);
		state->path.blk[i].bp = NULL;
	}
	/*
	 * Release the data block if we have it.
	 */
	if (state->extravalid && state->extrablk.bp) {
		xfs_trans_brelse(args->trans, state->extrablk.bp);
		state->extrablk.bp = NULL;
	}
	xfs_da_state_free(state);
	return rval;
}

