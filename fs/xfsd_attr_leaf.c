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

#include "xfs/xfs_fs.h"
#include "xfs/xfs_types.h"
#include "xfs/xfs_bit.h"
#include "xfs/xfs_log.h"
#include "xfsd_trans.h"
#include "xfs/xfs_sb.h"
#include "xfs/xfs_ag.h"
#include "xfs/xfs_mount.h"
#include "xfs/xfs_da_btree.h"
#include "xfs/xfs_bmap_btree.h"
#include "xfs/xfs_alloc_btree.h"
#include "xfs/xfs_ialloc_btree.h"
#include "xfs/xfs_alloc.h"
#include "xfs/xfs_btree.h"
#include "xfs/xfs_attr_sf.h"
#include "xfs/xfs_dinode.h"
#include "xfs/xfs_inode.h"
#include "xfs/xfs_inode_item.h"
#include "xfs/xfs_bmap.h"
#include "xfs/xfs_attr.h"
#include "xfs/xfs_attr_leaf.h"
#include "xfs/xfs_error.h"

#include "xfsd_trace.h"

/*
 * xfs_attr_leaf.c
 *
 * Routines to implement leaf blocks of attributes as Btrees of hashed names.
 */

/*========================================================================
 * Function prototypes for the kernel.
 *========================================================================*/

/*
 * Routines used for growing the Btree.
 */
STATIC int xfs_attr_leaf_create(xfs_da_args_t *args, xfs_dablk_t which_block,
				struct xfs_buf **bpp);
STATIC void xfs_attr_leaf_rebalance(xfs_da_state_t *state,
						   xfs_da_state_blk_t *blk1,
						   xfs_da_state_blk_t *blk2);
STATIC int xfs_attr_leaf_figure_balance(xfs_da_state_t *state,
					   xfs_da_state_blk_t *leaf_blk_1,
					   xfs_da_state_blk_t *leaf_blk_2,
					   int *number_entries_in_blk1,
					   int *number_usedbytes_in_blk1);

/*
 * Routines used for shrinking the Btree.
 */
STATIC int xfs_attr_node_inactive(xfs_trans_t **trans, xfs_inode_t *dp,
				  struct xfs_buf *bp, int level);
STATIC int xfs_attr_leaf_inactive(xfs_trans_t **trans, xfs_inode_t *dp,
				  struct xfs_buf *bp);
STATIC int xfs_attr_leaf_freextent(xfs_trans_t **trans, xfs_inode_t *dp,
				   xfs_dablk_t blkno, int blkcnt);

/*
 * Utility routines.
 */
STATIC void xfs_attr_leaf_moveents(xfs_attr_leafblock_t *src_leaf,
					 int src_start,
					 xfs_attr_leafblock_t *dst_leaf,
					 int dst_start, int move_count,
					 xfs_mount_t *mp);
STATIC int xfs_attr_leaf_entsize(xfs_attr_leafblock_t *leaf, int index);

static void
xfs_attr_leaf_verify(
	struct xfs_buf		*bp)
{
	struct xfs_mount	*mp = bp->b_target->bt_mount;
	struct xfs_attr_leaf_hdr *hdr = bp->b_addr;
	int			block_ok = 0;

	block_ok = hdr->info.magic == cpu_to_be16(XFS_ATTR_LEAF_MAGIC);
	if (!block_ok) {
		XFS_CORRUPTION_ERROR(__func__, XFS_ERRLEVEL_LOW, mp, hdr);
		xfs_buf_ioerror(bp, EFSCORRUPTED);
	}
}

static void
xfs_attr_leaf_read_verify(
	struct xfs_buf	*bp)
{
	xfs_attr_leaf_verify(bp);
}

static void
xfs_attr_leaf_write_verify(
	struct xfs_buf	*bp)
{
	xfs_attr_leaf_verify(bp);
}

const struct xfs_buf_ops xfs_attr_leaf_buf_ops = {
	.verify_read = xfs_attr_leaf_read_verify,
	.verify_write = xfs_attr_leaf_write_verify,
};

int
xfs_attr_leaf_read(
	struct xfs_trans	*tp,
	struct xfs_inode	*dp,
	xfs_dablk_t		bno,
	xfs_daddr_t		mappedbno,
	struct xfs_buf		**bpp)
{
	return xfs_da_read_buf(tp, dp, bno, mappedbno, bpp,
				XFS_ATTR_FORK, &xfs_attr_leaf_buf_ops);
}

/*========================================================================
 * Namespace helper routines
 *========================================================================*/

/*
 * If namespace bits don't match return 0.
 * If all match then return 1.
 */
STATIC int
xfs_attr_namesp_match(int arg_flags, int ondisk_flags)
{
	return XFS_ATTR_NSP_ONDISK(ondisk_flags) == XFS_ATTR_NSP_ARGS_TO_ONDISK(arg_flags);
}


/*========================================================================
 * External routines when attribute fork size < XFS_LITINO(mp).
 *========================================================================*/

/*
 * Query whether the requested number of additional bytes of extended
 * attribute space will be able to fit inline.
 *
 * Returns zero if not, else the di_forkoff fork offset to be used in the
 * literal area for attribute data once the new bytes have been added.
 *
 * di_forkoff must be 8 byte aligned, hence is stored as a >>3 value;
 * special case for dev/uuid inodes, they have fixed size data forks.
 */
int
xfs_attr_shortform_bytesfit(xfs_inode_t *dp, int bytes)
{
	int offset;
	int minforkoff;	/* lower limit on valid forkoff locations */
	int maxforkoff;	/* upper limit on valid forkoff locations */
	int dsize;
	xfs_mount_t *mp = dp->i_mount;

	/* rounded down */
	offset = (XFS_LITINO(mp, dp->i_d.di_version) - bytes) >> 3;

	switch (dp->i_d.di_format) {
	case XFS_DINODE_FMT_DEV:
		minforkoff = roundup(sizeof(xfs_dev_t), 8) >> 3;
		return (offset >= minforkoff) ? minforkoff : 0;
	case XFS_DINODE_FMT_UUID:
		minforkoff = roundup(sizeof(uuid_t), 8) >> 3;
		return (offset >= minforkoff) ? minforkoff : 0;
	}

	/*
	 * If the requested numbers of bytes is smaller or equal to the
	 * current attribute fork size we can always proceed.
	 *
	 * Note that if_bytes in the data fork might actually be larger than
	 * the current data fork size is due to delalloc extents. In that
	 * case either the extent count will go down when they are converted
	 * to real extents, or the delalloc conversion will take care of the
	 * literal area rebalancing.
	 */
	if (bytes <= XFS_IFORK_ASIZE(dp))
		return dp->i_d.di_forkoff;

	/*
	 * For attr2 we can try to move the forkoff if there is space in the
	 * literal area, but for the old format we are done if there is no
	 * space in the fixed attribute fork.
	 */
	if (!(mp->m_flags & XFS_MOUNT_ATTR2))
		return 0;

	dsize = dp->i_df.if_bytes;

	switch (dp->i_d.di_format) {
	case XFS_DINODE_FMT_EXTENTS:
		/*
		 * If there is no attr fork and the data fork is extents,
		 * determine if creating the default attr fork will result
		 * in the extents form migrating to btree. If so, the
		 * minimum offset only needs to be the space required for
		 * the btree root.
		 */
		if (!dp->i_d.di_forkoff && dp->i_df.if_bytes >
		    xfs_default_attroffset(dp))
			dsize = XFS_BMDR_SPACE_CALC(MINDBTPTRS);
		break;
	case XFS_DINODE_FMT_BTREE:
		/*
		 * If we have a data btree then keep forkoff if we have one,
		 * otherwise we are adding a new attr, so then we set
		 * minforkoff to where the btree root can finish so we have
		 * plenty of room for attrs
		 */
		if (dp->i_d.di_forkoff) {
			if (offset < dp->i_d.di_forkoff)
				return 0;
			return dp->i_d.di_forkoff;
		}
		dsize = XFS_BMAP_BROOT_SPACE(dp->i_df.if_broot);
		break;
	}

	/*
	 * A data fork btree root must have space for at least
	 * MINDBTPTRS key/ptr pairs if the data fork is small or empty.
	 */
	minforkoff = MAX(dsize, XFS_BMDR_SPACE_CALC(MINDBTPTRS));
	minforkoff = roundup(minforkoff, 8) >> 3;

	/* attr fork btree root can have at least this many key/ptr pairs */
	maxforkoff = XFS_LITINO(mp, dp->i_d.di_version) -
			XFS_BMDR_SPACE_CALC(MINABTPTRS);
	maxforkoff = maxforkoff >> 3;	/* rounded down */

	if (offset >= maxforkoff)
		return maxforkoff;
	if (offset >= minforkoff)
		return offset;
	return 0;
}

/*
 * Create the initial contents of a shortform attribute list.
 */
void
xfs_attr_shortform_create(xfs_da_args_t *args)
{
	xfs_attr_sf_hdr_t *hdr;
	xfs_inode_t *dp;
	xfs_ifork_t *ifp;

	trace_xfs_attr_sf_create(args);

	dp = args->dp;
	ASSERT(dp != NULL);
	ifp = dp->i_afp;
	ASSERT(ifp != NULL);
	ASSERT(ifp->if_bytes == 0);
	if (dp->i_d.di_aformat == XFS_DINODE_FMT_EXTENTS) {
		ifp->if_flags &= ~XFS_IFEXTENTS;	/* just in case */
		dp->i_d.di_aformat = XFS_DINODE_FMT_LOCAL;
		ifp->if_flags |= XFS_IFINLINE;
	} else {
		ASSERT(ifp->if_flags & XFS_IFINLINE);
	}
	xfs_idata_realloc(dp, sizeof(*hdr), XFS_ATTR_FORK);
	hdr = (xfs_attr_sf_hdr_t *)ifp->if_u1.if_data;
	hdr->count = 0;
	hdr->totsize = cpu_to_be16(sizeof(*hdr));
	xfs_trans_log_inode(args->trans, dp, XFS_ILOG_CORE | XFS_ILOG_ADATA);
}

/*
 * After the last attribute is removed revert to original inode format,
 * making all literal area available to the data fork once more.
 */
STATIC void
xfs_attr_fork_reset(
	struct xfs_inode	*ip,
	struct xfs_trans	*tp)
{
	xfs_idestroy_fork(ip, XFS_ATTR_FORK);
	ip->i_d.di_forkoff = 0;
	ip->i_d.di_aformat = XFS_DINODE_FMT_EXTENTS;

	ASSERT(ip->i_d.di_anextents == 0);
	ASSERT(ip->i_afp == NULL);

	xfs_trans_log_inode(tp, ip, XFS_ILOG_CORE);
}

/*
 * Look up a name in a shortform attribute list structure.
 */
/*ARGSUSED*/
int
xfs_attr_shortform_lookup(xfs_da_args_t *args)
{
	xfs_attr_shortform_t *sf;
	xfs_attr_sf_entry_t *sfe;
	int i;
	xfs_ifork_t *ifp;

	trace_xfs_attr_sf_lookup(args);

	ifp = args->dp->i_afp;
	ASSERT(ifp->if_flags & XFS_IFINLINE);
	sf = (xfs_attr_shortform_t *)ifp->if_u1.if_data;
	sfe = &sf->list[0];
	for (i = 0; i < sf->hdr.count;
				sfe = XFS_ATTR_SF_NEXTENTRY(sfe), i++) {
		if (sfe->namelen != args->namelen)
			continue;
		if (memcmp(args->name, sfe->nameval, args->namelen) != 0)
			continue;
		if (!xfs_attr_namesp_match(args->flags, sfe->flags))
			continue;
		return(XFS_ERROR(EEXIST));
	}
	return(XFS_ERROR(ENOATTR));
}

/*
 * Look up a name in a shortform attribute list structure.
 */
/*ARGSUSED*/
int
xfs_attr_shortform_getvalue(xfs_da_args_t *args)
{
	xfs_attr_shortform_t *sf;
	xfs_attr_sf_entry_t *sfe;
	int i;

	ASSERT(args->dp->i_d.di_aformat == XFS_IFINLINE);
	sf = (xfs_attr_shortform_t *)args->dp->i_afp->if_u1.if_data;
	sfe = &sf->list[0];
	for (i = 0; i < sf->hdr.count;
				sfe = XFS_ATTR_SF_NEXTENTRY(sfe), i++) {
		if (sfe->namelen != args->namelen)
			continue;
		if (memcmp(args->name, sfe->nameval, args->namelen) != 0)
			continue;
		if (!xfs_attr_namesp_match(args->flags, sfe->flags))
			continue;
		if (args->flags & ATTR_KERNOVAL) {
			args->valuelen = sfe->valuelen;
			return(XFS_ERROR(EEXIST));
		}
		if (args->valuelen < sfe->valuelen) {
			args->valuelen = sfe->valuelen;
			return(XFS_ERROR(ERANGE));
		}
		args->valuelen = sfe->valuelen;
		memcpy(args->value, &sfe->nameval[args->namelen],
						    args->valuelen);
		return(XFS_ERROR(EEXIST));
	}
	return(XFS_ERROR(ENOATTR));
}

STATIC int
xfs_attr_shortform_compare(const void *a, const void *b)
{
	xfs_attr_sf_sort_t *sa, *sb;

	sa = (xfs_attr_sf_sort_t *)a;
	sb = (xfs_attr_sf_sort_t *)b;
	if (sa->hash < sb->hash) {
		return(-1);
	} else if (sa->hash > sb->hash) {
		return(1);
	} else {
		return(sa->entno - sb->entno);
	}
}


#define XFS_ISRESET_CURSOR(cursor) \
	(!((cursor)->initted) && !((cursor)->hashval) && \
	 !((cursor)->blkno) && !((cursor)->offset))
/*
 * Copy out entries of shortform attribute lists for attr_list().
 * Shortform attribute lists are not stored in hashval sorted order.
 * If the output buffer is not large enough to hold them all, then we
 * we have to calculate each entries' hashvalue and sort them before
 * we can begin returning them to the user.
 */
/*ARGSUSED*/
int
xfs_attr_shortform_list(xfs_attr_list_context_t *context)
{
	attrlist_cursor_kern_t *cursor;
	xfs_attr_sf_sort_t *sbuf, *sbp;
	xfs_attr_shortform_t *sf;
	xfs_attr_sf_entry_t *sfe;
	xfs_inode_t *dp;
	int sbsize, nsbuf, count, i;
	int error;

	ASSERT(context != NULL);
	dp = context->dp;
	ASSERT(dp != NULL);
	ASSERT(dp->i_afp != NULL);
	sf = (xfs_attr_shortform_t *)dp->i_afp->if_u1.if_data;
	ASSERT(sf != NULL);
	if (!sf->hdr.count)
		return(0);
	cursor = context->cursor;
	ASSERT(cursor != NULL);

	trace_xfs_attr_list_sf(context);

	/*
	 * If the buffer is large enough and the cursor is at the start,
	 * do not bother with sorting since we will return everything in
	 * one buffer and another call using the cursor won't need to be
	 * made.
	 * Note the generous fudge factor of 16 overhead bytes per entry.
	 * If bufsize is zero then put_listent must be a search function
	 * and can just scan through what we have.
	 */
	if (context->bufsize == 0 ||
	    (XFS_ISRESET_CURSOR(cursor) &&
             (dp->i_afp->if_bytes + sf->hdr.count * 16) < context->bufsize)) {
		for (i = 0, sfe = &sf->list[0]; i < sf->hdr.count; i++) {
			error = context->put_listent(context,
					   sfe->flags,
					   sfe->nameval,
					   (int)sfe->namelen,
					   (int)sfe->valuelen,
					   &sfe->nameval[sfe->namelen]);

			/*
			 * Either search callback finished early or
			 * didn't fit it all in the buffer after all.
			 */
			if (context->seen_enough)
				break;

			if (error)
				return error;
			sfe = XFS_ATTR_SF_NEXTENTRY(sfe);
		}
		trace_xfs_attr_list_sf_all(context);
		return(0);
	}

	/* do no more for a search callback */
	if (context->bufsize == 0)
		return 0;

	/*
	 * It didn't all fit, so we have to sort everything on hashval.
	 */
	sbsize = sf->hdr.count * sizeof(*sbuf);
	sbp = sbuf = kmem_alloc(sbsize, KM_SLEEP | KM_NOFS);

	/*
	 * Scan the attribute list for the rest of the entries, storing
	 * the relevant info from only those that match into a buffer.
	 */
	nsbuf = 0;
	for (i = 0, sfe = &sf->list[0]; i < sf->hdr.count; i++) {
		if (unlikely(
		    ((char *)sfe < (char *)sf) ||
		    ((char *)sfe >= ((char *)sf + dp->i_afp->if_bytes)))) {
			XFS_CORRUPTION_ERROR("xfs_attr_shortform_list",
					     XFS_ERRLEVEL_LOW,
					     context->dp->i_mount, sfe);
			kmem_free(sbuf);
			return XFS_ERROR(EFSCORRUPTED);
		}

		sbp->entno = i;
		sbp->hash = xfs_da_hashname(sfe->nameval, sfe->namelen);
		sbp->name = sfe->nameval;
		sbp->namelen = sfe->namelen;
		/* These are bytes, and both on-disk, don't endian-flip */
		sbp->valuelen = sfe->valuelen;
		sbp->flags = sfe->flags;
		sfe = XFS_ATTR_SF_NEXTENTRY(sfe);
		sbp++;
		nsbuf++;
	}

	/*
	 * Sort the entries on hash then entno.
	 */
	xfs_sort(sbuf, nsbuf, sizeof(*sbuf), xfs_attr_shortform_compare);

	/*
	 * Re-find our place IN THE SORTED LIST.
	 */
	count = 0;
	cursor->initted = 1;
	cursor->blkno = 0;
	for (sbp = sbuf, i = 0; i < nsbuf; i++, sbp++) {
		if (sbp->hash == cursor->hashval) {
			if (cursor->offset == count) {
				break;
			}
			count++;
		} else if (sbp->hash > cursor->hashval) {
			break;
		}
	}
	if (i == nsbuf) {
		kmem_free(sbuf);
		return(0);
	}

	/*
	 * Loop putting entries into the user buffer.
	 */
	for ( ; i < nsbuf; i++, sbp++) {
		if (cursor->hashval != sbp->hash) {
			cursor->hashval = sbp->hash;
			cursor->offset = 0;
		}
		error = context->put_listent(context,
					sbp->flags,
					sbp->name,
					sbp->namelen,
					sbp->valuelen,
					&sbp->name[sbp->namelen]);
		if (error)
			return error;
		if (context->seen_enough)
			break;
		cursor->offset++;
	}

	kmem_free(sbuf);
	return(0);
}

/*
 * Check a leaf attribute block to see if all the entries would fit into
 * a shortform attribute list.
 */
int
xfs_attr_shortform_allfit(
	struct xfs_buf	*bp,
	struct xfs_inode *dp)
{
	xfs_attr_leafblock_t *leaf;
	xfs_attr_leaf_entry_t *entry;
	xfs_attr_leaf_name_local_t *name_loc;
	int bytes, i;

	leaf = bp->b_addr;
	ASSERT(leaf->hdr.info.magic == cpu_to_be16(XFS_ATTR_LEAF_MAGIC));

	entry = &leaf->entries[0];
	bytes = sizeof(struct xfs_attr_sf_hdr);
	for (i = 0; i < be16_to_cpu(leaf->hdr.count); entry++, i++) {
		if (entry->flags & XFS_ATTR_INCOMPLETE)
			continue;		/* don't copy partial entries */
		if (!(entry->flags & XFS_ATTR_LOCAL))
			return(0);
		name_loc = xfs_attr_leaf_name_local(leaf, i);
		if (name_loc->namelen >= XFS_ATTR_SF_ENTSIZE_MAX)
			return(0);
		if (be16_to_cpu(name_loc->valuelen) >= XFS_ATTR_SF_ENTSIZE_MAX)
			return(0);
		bytes += sizeof(struct xfs_attr_sf_entry)-1
				+ name_loc->namelen
				+ be16_to_cpu(name_loc->valuelen);
	}
	if ((dp->i_mount->m_flags & XFS_MOUNT_ATTR2) &&
	    (dp->i_d.di_format != XFS_DINODE_FMT_BTREE) &&
	    (bytes == sizeof(struct xfs_attr_sf_hdr)))
		return(-1);
	return(xfs_attr_shortform_bytesfit(dp, bytes));
}

/*========================================================================
 * Routines used for growing the Btree.
 *========================================================================*/

/*
 * Examine entries until we reduce the absolute difference in
 * byte usage between the two blocks to a minimum.
 * GROT: Is this really necessary?  With other than a 512 byte blocksize,
 * GROT: there will always be enough room in either block for a new entry.
 * GROT: Do a double-split for this case?
 */
STATIC int
xfs_attr_leaf_figure_balance(xfs_da_state_t *state,
				    xfs_da_state_blk_t *blk1,
				    xfs_da_state_blk_t *blk2,
				    int *countarg, int *usedbytesarg)
{
	xfs_attr_leafblock_t *leaf1, *leaf2;
	xfs_attr_leaf_hdr_t *hdr1, *hdr2;
	xfs_attr_leaf_entry_t *entry;
	int count, max, index, totallen, half;
	int lastdelta, foundit, tmp;

	/*
	 * Set up environment.
	 */
	leaf1 = blk1->bp->b_addr;
	leaf2 = blk2->bp->b_addr;
	hdr1 = &leaf1->hdr;
	hdr2 = &leaf2->hdr;
	foundit = 0;
	totallen = 0;

	/*
	 * Examine entries until we reduce the absolute difference in
	 * byte usage between the two blocks to a minimum.
	 */
	max = be16_to_cpu(hdr1->count) + be16_to_cpu(hdr2->count);
	half  = (max+1) * sizeof(*entry);
	half += be16_to_cpu(hdr1->usedbytes) +
		be16_to_cpu(hdr2->usedbytes) +
		xfs_attr_leaf_newentsize(
				state->args->namelen,
				state->args->valuelen,
				state->blocksize, NULL);
	half /= 2;
	lastdelta = state->blocksize;
	entry = &leaf1->entries[0];
	for (count = index = 0; count < max; entry++, index++, count++) {

#define XFS_ATTR_ABS(A)	(((A) < 0) ? -(A) : (A))
		/*
		 * The new entry is in the first block, account for it.
		 */
		if (count == blk1->index) {
			tmp = totallen + sizeof(*entry) +
				xfs_attr_leaf_newentsize(
						state->args->namelen,
						state->args->valuelen,
						state->blocksize, NULL);
			if (XFS_ATTR_ABS(half - tmp) > lastdelta)
				break;
			lastdelta = XFS_ATTR_ABS(half - tmp);
			totallen = tmp;
			foundit = 1;
		}

		/*
		 * Wrap around into the second block if necessary.
		 */
		if (count == be16_to_cpu(hdr1->count)) {
			leaf1 = leaf2;
			entry = &leaf1->entries[0];
			index = 0;
		}

		/*
		 * Figure out if next leaf entry would be too much.
		 */
		tmp = totallen + sizeof(*entry) + xfs_attr_leaf_entsize(leaf1,
									index);
		if (XFS_ATTR_ABS(half - tmp) > lastdelta)
			break;
		lastdelta = XFS_ATTR_ABS(half - tmp);
		totallen = tmp;
#undef XFS_ATTR_ABS
	}

	/*
	 * Calculate the number of usedbytes that will end up in lower block.
	 * If new entry not in lower block, fix up the count.
	 */
	totallen -= count * sizeof(*entry);
	if (foundit) {
		totallen -= sizeof(*entry) +
				xfs_attr_leaf_newentsize(
						state->args->namelen,
						state->args->valuelen,
						state->blocksize, NULL);
	}

	*countarg = count;
	*usedbytesarg = totallen;
	return(foundit);
}

/*========================================================================
 * Routines used for shrinking the Btree.
 *========================================================================*/

/*
 * Check a leaf block and its neighbors to see if the block should be
 * collapsed into one or the other neighbor.  Always keep the block
 * with the smaller block number.
 * If the current block is over 50% full, don't try to join it, return 0.
 * If the block is empty, fill in the state structure and return 2.
 * If it can be collapsed, fill in the state structure and return 1.
 * If nothing can be done, return 0.
 *
 * GROT: allow for INCOMPLETE entries in calculation.
 */
int
xfs_attr_leaf_toosmall(xfs_da_state_t *state, int *action)
{
	xfs_attr_leafblock_t *leaf;
	xfs_da_state_blk_t *blk;
	xfs_da_blkinfo_t *info;
	int count, bytes, forward, error, retval, i;
	xfs_dablk_t blkno;
	struct xfs_buf *bp;

	trace_xfs_attr_leaf_toosmall(state->args);

	/*
	 * Check for the degenerate case of the block being over 50% full.
	 * If so, it's not worth even looking to see if we might be able
	 * to coalesce with a sibling.
	 */
	blk = &state->path.blk[ state->path.active-1 ];
	info = blk->bp->b_addr;
	ASSERT(info->magic == cpu_to_be16(XFS_ATTR_LEAF_MAGIC));
	leaf = (xfs_attr_leafblock_t *)info;
	count = be16_to_cpu(leaf->hdr.count);
	bytes = sizeof(xfs_attr_leaf_hdr_t) +
		count * sizeof(xfs_attr_leaf_entry_t) +
		be16_to_cpu(leaf->hdr.usedbytes);
	if (bytes > (state->blocksize >> 1)) {
		*action = 0;	/* blk over 50%, don't try to join */
		return(0);
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
		error = xfs_da_path_shift(state, &state->altpath, forward,
						 0, &retval);
		if (error)
			return(error);
		if (retval) {
			*action = 0;
		} else {
			*action = 2;
		}
		return(0);
	}

	/*
	 * Examine each sibling block to see if we can coalesce with
	 * at least 25% free space to spare.  We need to figure out
	 * whether to merge with the forward or the backward block.
	 * We prefer coalescing with the lower numbered sibling so as
	 * to shrink an attribute list over time.
	 */
	/* start with smaller blk num */
	forward = (be32_to_cpu(info->forw) < be32_to_cpu(info->back));
	for (i = 0; i < 2; forward = !forward, i++) {
		if (forward)
			blkno = be32_to_cpu(info->forw);
		else
			blkno = be32_to_cpu(info->back);
		if (blkno == 0)
			continue;
		error = xfs_attr_leaf_read(state->args->trans, state->args->dp,
					blkno, -1, &bp);
		if (error)
			return(error);

		leaf = (xfs_attr_leafblock_t *)info;
		count  = be16_to_cpu(leaf->hdr.count);
		bytes  = state->blocksize - (state->blocksize>>2);
		bytes -= be16_to_cpu(leaf->hdr.usedbytes);
		leaf = bp->b_addr;
		count += be16_to_cpu(leaf->hdr.count);
		bytes -= be16_to_cpu(leaf->hdr.usedbytes);
		bytes -= count * sizeof(xfs_attr_leaf_entry_t);
		bytes -= sizeof(xfs_attr_leaf_hdr_t);
		xfs_trans_brelse(state->args->trans, bp);
		if (bytes >= 0)
			break;	/* fits with at least 25% to spare */
	}
	if (i >= 2) {
		*action = 0;
		return(0);
	}

	/*
	 * Make altpath point to the block we want to keep (the lower
	 * numbered block) and path point to the block we want to drop.
	 */
	memcpy(&state->altpath, &state->path, sizeof(state->path));
	if (blkno < blk->blkno) {
		error = xfs_da_path_shift(state, &state->altpath, forward,
						 0, &retval);
	} else {
		error = xfs_da_path_shift(state, &state->path, forward,
						 0, &retval);
	}
	if (error)
		return(error);
	if (retval) {
		*action = 0;
	} else {
		*action = 1;
	}
	return(0);
}

/*========================================================================
 * Routines used for finding things in the Btree.
 *========================================================================*/

/*
 * Look up a name in a leaf attribute list structure.
 * This is the internal routine, it uses the caller's buffer.
 *
 * Note that duplicate keys are allowed, but only check within the
 * current leaf node.  The Btree code must check in adjacent leaf nodes.
 *
 * Return in args->index the index into the entry[] array of either
 * the found entry, or where the entry should have been (insert before
 * that entry).
 *
 * Don't change the args->value unless we find the attribute.
 */
int
xfs_attr_leaf_lookup_int(
	struct xfs_buf	*bp,
	xfs_da_args_t	*args)
{
	xfs_attr_leafblock_t *leaf;
	xfs_attr_leaf_entry_t *entry;
	xfs_attr_leaf_name_local_t *name_loc;
	xfs_attr_leaf_name_remote_t *name_rmt;
	int probe, span;
	xfs_dahash_t hashval;

	trace_xfs_attr_leaf_lookup(args);

	leaf = bp->b_addr;
	ASSERT(leaf->hdr.info.magic == cpu_to_be16(XFS_ATTR_LEAF_MAGIC));
	ASSERT(be16_to_cpu(leaf->hdr.count)
					< (XFS_LBSIZE(args->dp->i_mount)/8));

	/*
	 * Binary search.  (note: small blocks will skip this loop)
	 */
	hashval = args->hashval;
	probe = span = be16_to_cpu(leaf->hdr.count) / 2;
	for (entry = &leaf->entries[probe]; span > 4;
		   entry = &leaf->entries[probe]) {
		span /= 2;
		if (be32_to_cpu(entry->hashval) < hashval)
			probe += span;
		else if (be32_to_cpu(entry->hashval) > hashval)
			probe -= span;
		else
			break;
	}
	ASSERT((probe >= 0) &&
	       (!leaf->hdr.count
	       || (probe < be16_to_cpu(leaf->hdr.count))));
	ASSERT((span <= 4) || (be32_to_cpu(entry->hashval) == hashval));

	/*
	 * Since we may have duplicate hashval's, find the first matching
	 * hashval in the leaf.
	 */
	while ((probe > 0) && (be32_to_cpu(entry->hashval) >= hashval)) {
		entry--;
		probe--;
	}
	while ((probe < be16_to_cpu(leaf->hdr.count)) &&
	       (be32_to_cpu(entry->hashval) < hashval)) {
		entry++;
		probe++;
	}
	if ((probe == be16_to_cpu(leaf->hdr.count)) ||
	    (be32_to_cpu(entry->hashval) != hashval)) {
		args->index = probe;
		return(XFS_ERROR(ENOATTR));
	}

	/*
	 * Duplicate keys may be present, so search all of them for a match.
	 */
	for (  ; (probe < be16_to_cpu(leaf->hdr.count)) &&
			(be32_to_cpu(entry->hashval) == hashval);
			entry++, probe++) {
/*
 * GROT: Add code to remove incomplete entries.
 */
		/*
		 * If we are looking for INCOMPLETE entries, show only those.
		 * If we are looking for complete entries, show only those.
		 */
		if ((args->flags & XFS_ATTR_INCOMPLETE) !=
		    (entry->flags & XFS_ATTR_INCOMPLETE)) {
			continue;
		}
		if (entry->flags & XFS_ATTR_LOCAL) {
			name_loc = xfs_attr_leaf_name_local(leaf, probe);
			if (name_loc->namelen != args->namelen)
				continue;
			if (memcmp(args->name, (char *)name_loc->nameval, args->namelen) != 0)
				continue;
			if (!xfs_attr_namesp_match(args->flags, entry->flags))
				continue;
			args->index = probe;
			return(XFS_ERROR(EEXIST));
		} else {
			name_rmt = xfs_attr_leaf_name_remote(leaf, probe);
			if (name_rmt->namelen != args->namelen)
				continue;
			if (memcmp(args->name, (char *)name_rmt->name,
					     args->namelen) != 0)
				continue;
			if (!xfs_attr_namesp_match(args->flags, entry->flags))
				continue;
			args->index = probe;
			args->rmtblkno = be32_to_cpu(name_rmt->valueblk);
			args->rmtblkcnt = XFS_B_TO_FSB(args->dp->i_mount,
						   be32_to_cpu(name_rmt->valuelen));
			return(XFS_ERROR(EEXIST));
		}
	}
	args->index = probe;
	return(XFS_ERROR(ENOATTR));
}

/*
 * Get the value associated with an attribute name from a leaf attribute
 * list structure.
 */
int
xfs_attr_leaf_getvalue(
	struct xfs_buf	*bp,
	xfs_da_args_t	*args)
{
	int valuelen;
	xfs_attr_leafblock_t *leaf;
	xfs_attr_leaf_entry_t *entry;
	xfs_attr_leaf_name_local_t *name_loc;
	xfs_attr_leaf_name_remote_t *name_rmt;

	leaf = bp->b_addr;
	ASSERT(leaf->hdr.info.magic == cpu_to_be16(XFS_ATTR_LEAF_MAGIC));
	ASSERT(be16_to_cpu(leaf->hdr.count)
					< (XFS_LBSIZE(args->dp->i_mount)/8));
	ASSERT(args->index < be16_to_cpu(leaf->hdr.count));

	entry = &leaf->entries[args->index];
	if (entry->flags & XFS_ATTR_LOCAL) {
		name_loc = xfs_attr_leaf_name_local(leaf, args->index);
		ASSERT(name_loc->namelen == args->namelen);
		ASSERT(memcmp(args->name, name_loc->nameval, args->namelen) == 0);
		valuelen = be16_to_cpu(name_loc->valuelen);
		if (args->flags & ATTR_KERNOVAL) {
			args->valuelen = valuelen;
			return(0);
		}
		if (args->valuelen < valuelen) {
			args->valuelen = valuelen;
			return(XFS_ERROR(ERANGE));
		}
		args->valuelen = valuelen;
		memcpy(args->value, &name_loc->nameval[args->namelen], valuelen);
	} else {
		name_rmt = xfs_attr_leaf_name_remote(leaf, args->index);
		ASSERT(name_rmt->namelen == args->namelen);
		ASSERT(memcmp(args->name, name_rmt->name, args->namelen) == 0);
		valuelen = be32_to_cpu(name_rmt->valuelen);
		args->rmtblkno = be32_to_cpu(name_rmt->valueblk);
		args->rmtblkcnt = XFS_B_TO_FSB(args->dp->i_mount, valuelen);
		if (args->flags & ATTR_KERNOVAL) {
			args->valuelen = valuelen;
			return(0);
		}
		if (args->valuelen < valuelen) {
			args->valuelen = valuelen;
			return(XFS_ERROR(ERANGE));
		}
		args->valuelen = valuelen;
	}
	return(0);
}

/*========================================================================
 * Utility routines.
 *========================================================================*/

/*
 * Move the indicated entries from one leaf to another.
 * NOTE: this routine modifies both source and destination leaves.
 */
/*ARGSUSED*/
STATIC void
xfs_attr_leaf_moveents(xfs_attr_leafblock_t *leaf_s, int start_s,
			xfs_attr_leafblock_t *leaf_d, int start_d,
			int count, xfs_mount_t *mp)
{
	xfs_attr_leaf_hdr_t *hdr_s, *hdr_d;
	xfs_attr_leaf_entry_t *entry_s, *entry_d;
	int desti, tmp, i;

	/*
	 * Check for nothing to do.
	 */
	if (count == 0)
		return;

	/*
	 * Set up environment.
	 */
	ASSERT(leaf_s->hdr.info.magic == cpu_to_be16(XFS_ATTR_LEAF_MAGIC));
	ASSERT(leaf_d->hdr.info.magic == cpu_to_be16(XFS_ATTR_LEAF_MAGIC));
	hdr_s = &leaf_s->hdr;
	hdr_d = &leaf_d->hdr;
	ASSERT((be16_to_cpu(hdr_s->count) > 0) &&
	       (be16_to_cpu(hdr_s->count) < (XFS_LBSIZE(mp)/8)));
	ASSERT(be16_to_cpu(hdr_s->firstused) >=
		((be16_to_cpu(hdr_s->count)
					* sizeof(*entry_s))+sizeof(*hdr_s)));
	ASSERT(be16_to_cpu(hdr_d->count) < (XFS_LBSIZE(mp)/8));
	ASSERT(be16_to_cpu(hdr_d->firstused) >=
		((be16_to_cpu(hdr_d->count)
					* sizeof(*entry_d))+sizeof(*hdr_d)));

	ASSERT(start_s < be16_to_cpu(hdr_s->count));
	ASSERT(start_d <= be16_to_cpu(hdr_d->count));
	ASSERT(count <= be16_to_cpu(hdr_s->count));

	/*
	 * Move the entries in the destination leaf up to make a hole?
	 */
	if (start_d < be16_to_cpu(hdr_d->count)) {
		tmp  = be16_to_cpu(hdr_d->count) - start_d;
		tmp *= sizeof(xfs_attr_leaf_entry_t);
		entry_s = &leaf_d->entries[start_d];
		entry_d = &leaf_d->entries[start_d + count];
		memmove((char *)entry_d, (char *)entry_s, tmp);
	}

	/*
	 * Copy all entry's in the same (sorted) order,
	 * but allocate attribute info packed and in sequence.
	 */
	entry_s = &leaf_s->entries[start_s];
	entry_d = &leaf_d->entries[start_d];
	desti = start_d;
	for (i = 0; i < count; entry_s++, entry_d++, desti++, i++) {
		ASSERT(be16_to_cpu(entry_s->nameidx)
				>= be16_to_cpu(hdr_s->firstused));
		tmp = xfs_attr_leaf_entsize(leaf_s, start_s + i);
#ifdef GROT
		/*
		 * Code to drop INCOMPLETE entries.  Difficult to use as we
		 * may also need to change the insertion index.  Code turned
		 * off for 6.2, should be revisited later.
		 */
		if (entry_s->flags & XFS_ATTR_INCOMPLETE) { /* skip partials? */
			memset(xfs_attr_leaf_name(leaf_s, start_s + i), 0, tmp);
			be16_add_cpu(&hdr_s->usedbytes, -tmp);
			be16_add_cpu(&hdr_s->count, -1);
			entry_d--;	/* to compensate for ++ in loop hdr */
			desti--;
			if ((start_s + i) < offset)
				result++;	/* insertion index adjustment */
		} else {
#endif /* GROT */
			be16_add_cpu(&hdr_d->firstused, -tmp);
			/* both on-disk, don't endian flip twice */
			entry_d->hashval = entry_s->hashval;
			/* both on-disk, don't endian flip twice */
			entry_d->nameidx = hdr_d->firstused;
			entry_d->flags = entry_s->flags;
			ASSERT(be16_to_cpu(entry_d->nameidx) + tmp
							<= XFS_LBSIZE(mp));
			memmove(xfs_attr_leaf_name(leaf_d, desti),
				xfs_attr_leaf_name(leaf_s, start_s + i), tmp);
			ASSERT(be16_to_cpu(entry_s->nameidx) + tmp
							<= XFS_LBSIZE(mp));
			memset(xfs_attr_leaf_name(leaf_s, start_s + i), 0, tmp);
			be16_add_cpu(&hdr_s->usedbytes, -tmp);
			be16_add_cpu(&hdr_d->usedbytes, tmp);
			be16_add_cpu(&hdr_s->count, -1);
			be16_add_cpu(&hdr_d->count, 1);
			tmp = be16_to_cpu(hdr_d->count)
						* sizeof(xfs_attr_leaf_entry_t)
						+ sizeof(xfs_attr_leaf_hdr_t);
			ASSERT(be16_to_cpu(hdr_d->firstused) >= tmp);
#ifdef GROT
		}
#endif /* GROT */
	}

	/*
	 * Zero out the entries we just copied.
	 */
	if (start_s == be16_to_cpu(hdr_s->count)) {
		tmp = count * sizeof(xfs_attr_leaf_entry_t);
		entry_s = &leaf_s->entries[start_s];
		ASSERT(((char *)entry_s + tmp) <=
		       ((char *)leaf_s + XFS_LBSIZE(mp)));
		memset((char *)entry_s, 0, tmp);
	} else {
		/*
		 * Move the remaining entries down to fill the hole,
		 * then zero the entries at the top.
		 */
		tmp  = be16_to_cpu(hdr_s->count) - count;
		tmp *= sizeof(xfs_attr_leaf_entry_t);
		entry_s = &leaf_s->entries[start_s + count];
		entry_d = &leaf_s->entries[start_s];
		memmove((char *)entry_d, (char *)entry_s, tmp);

		tmp = count * sizeof(xfs_attr_leaf_entry_t);
		entry_s = &leaf_s->entries[be16_to_cpu(hdr_s->count)];
		ASSERT(((char *)entry_s + tmp) <=
		       ((char *)leaf_s + XFS_LBSIZE(mp)));
		memset((char *)entry_s, 0, tmp);
	}

	/*
	 * Fill in the freemap information
	 */
	hdr_d->freemap[0].base = cpu_to_be16(sizeof(xfs_attr_leaf_hdr_t));
	be16_add_cpu(&hdr_d->freemap[0].base, be16_to_cpu(hdr_d->count) *
			sizeof(xfs_attr_leaf_entry_t));
	hdr_d->freemap[0].size = cpu_to_be16(be16_to_cpu(hdr_d->firstused)
			      - be16_to_cpu(hdr_d->freemap[0].base));
	hdr_d->freemap[1].base = 0;
	hdr_d->freemap[2].base = 0;
	hdr_d->freemap[1].size = 0;
	hdr_d->freemap[2].size = 0;
	hdr_s->holes = 1;	/* leaf may not be compact */
}

/*
 * Compare two leaf blocks "order".
 * Return 0 unless leaf2 should go before leaf1.
 */
int
xfs_attr_leaf_order(
	struct xfs_buf	*leaf1_bp,
	struct xfs_buf	*leaf2_bp)
{
	xfs_attr_leafblock_t *leaf1, *leaf2;

	leaf1 = leaf1_bp->b_addr;
	leaf2 = leaf2_bp->b_addr;
	ASSERT((leaf1->hdr.info.magic == cpu_to_be16(XFS_ATTR_LEAF_MAGIC)) &&
	       (leaf2->hdr.info.magic == cpu_to_be16(XFS_ATTR_LEAF_MAGIC)));
	if ((be16_to_cpu(leaf1->hdr.count) > 0) &&
	    (be16_to_cpu(leaf2->hdr.count) > 0) &&
	    ((be32_to_cpu(leaf2->entries[0].hashval) <
	      be32_to_cpu(leaf1->entries[0].hashval)) ||
	     (be32_to_cpu(leaf2->entries[
			be16_to_cpu(leaf2->hdr.count)-1].hashval) <
	      be32_to_cpu(leaf1->entries[
			be16_to_cpu(leaf1->hdr.count)-1].hashval)))) {
		return(1);
	}
	return(0);
}

/*
 * Pick up the last hashvalue from a leaf block.
 */
xfs_dahash_t
xfs_attr_leaf_lasthash(
	struct xfs_buf	*bp,
	int		*count)
{
	xfs_attr_leafblock_t *leaf;

	leaf = bp->b_addr;
	ASSERT(leaf->hdr.info.magic == cpu_to_be16(XFS_ATTR_LEAF_MAGIC));
	if (count)
		*count = be16_to_cpu(leaf->hdr.count);
	if (!leaf->hdr.count)
		return(0);
	return be32_to_cpu(leaf->entries[be16_to_cpu(leaf->hdr.count)-1].hashval);
}

/*
 * Calculate the number of bytes used to store the indicated attribute
 * (whether local or remote only calculate bytes in this block).
 */
STATIC int
xfs_attr_leaf_entsize(xfs_attr_leafblock_t *leaf, int index)
{
	xfs_attr_leaf_name_local_t *name_loc;
	xfs_attr_leaf_name_remote_t *name_rmt;
	int size;

	ASSERT(leaf->hdr.info.magic == cpu_to_be16(XFS_ATTR_LEAF_MAGIC));
	if (leaf->entries[index].flags & XFS_ATTR_LOCAL) {
		name_loc = xfs_attr_leaf_name_local(leaf, index);
		size = xfs_attr_leaf_entsize_local(name_loc->namelen,
						   be16_to_cpu(name_loc->valuelen));
	} else {
		name_rmt = xfs_attr_leaf_name_remote(leaf, index);
		size = xfs_attr_leaf_entsize_remote(name_rmt->namelen);
	}
	return(size);
}

/*
 * Calculate the number of bytes that would be required to store the new
 * attribute (whether local or remote only calculate bytes in this block).
 * This routine decides as a side effect whether the attribute will be
 * a "local" or a "remote" attribute.
 */
int
xfs_attr_leaf_newentsize(int namelen, int valuelen, int blocksize, int *local)
{
	int size;

	size = xfs_attr_leaf_entsize_local(namelen, valuelen);
	if (size < xfs_attr_leaf_entsize_local_max(blocksize)) {
		if (local) {
			*local = 1;
		}
	} else {
		size = xfs_attr_leaf_entsize_remote(namelen);
		if (local) {
			*local = 0;
		}
	}
	return(size);
}

/*
 * Copy out attribute list entries for attr_list(), for leaf attribute lists.
 */
int
xfs_attr_leaf_list_int(
	struct xfs_buf		*bp,
	xfs_attr_list_context_t	*context)
{
	attrlist_cursor_kern_t *cursor;
	xfs_attr_leafblock_t *leaf;
	xfs_attr_leaf_entry_t *entry;
	int retval, i;

	ASSERT(bp != NULL);
	leaf = bp->b_addr;
	cursor = context->cursor;
	cursor->initted = 1;

	trace_xfs_attr_list_leaf(context);

	/*
	 * Re-find our place in the leaf block if this is a new syscall.
	 */
	if (context->resynch) {
		entry = &leaf->entries[0];
		for (i = 0; i < be16_to_cpu(leaf->hdr.count); entry++, i++) {
			if (be32_to_cpu(entry->hashval) == cursor->hashval) {
				if (cursor->offset == context->dupcnt) {
					context->dupcnt = 0;
					break;
				}
				context->dupcnt++;
			} else if (be32_to_cpu(entry->hashval) >
					cursor->hashval) {
				context->dupcnt = 0;
				break;
			}
		}
		if (i == be16_to_cpu(leaf->hdr.count)) {
			trace_xfs_attr_list_notfound(context);
			return(0);
		}
	} else {
		entry = &leaf->entries[0];
		i = 0;
	}
	context->resynch = 0;

	/*
	 * We have found our place, start copying out the new attributes.
	 */
	retval = 0;
	for (  ; (i < be16_to_cpu(leaf->hdr.count)); entry++, i++) {
		if (be32_to_cpu(entry->hashval) != cursor->hashval) {
			cursor->hashval = be32_to_cpu(entry->hashval);
			cursor->offset = 0;
		}

		if (entry->flags & XFS_ATTR_INCOMPLETE)
			continue;		/* skip incomplete entries */

		if (entry->flags & XFS_ATTR_LOCAL) {
			xfs_attr_leaf_name_local_t *name_loc =
				xfs_attr_leaf_name_local(leaf, i);

			retval = context->put_listent(context,
						entry->flags,
						name_loc->nameval,
						(int)name_loc->namelen,
						be16_to_cpu(name_loc->valuelen),
						&name_loc->nameval[name_loc->namelen]);
			if (retval)
				return retval;
		} else {
			xfs_attr_leaf_name_remote_t *name_rmt =
				xfs_attr_leaf_name_remote(leaf, i);

			int valuelen = be32_to_cpu(name_rmt->valuelen);

			if (context->put_value) {
				xfs_da_args_t args;

				memset((char *)&args, 0, sizeof(args));
				args.dp = context->dp;
				args.whichfork = XFS_ATTR_FORK;
				args.valuelen = valuelen;
				args.value = kmem_alloc(valuelen, KM_SLEEP | KM_NOFS);
				args.rmtblkno = be32_to_cpu(name_rmt->valueblk);
				args.rmtblkcnt = XFS_B_TO_FSB(args.dp->i_mount, valuelen);
				retval = xfs_attr_rmtval_get(&args);
				if (retval)
					return retval;
				retval = context->put_listent(context,
						entry->flags,
						name_rmt->name,
						(int)name_rmt->namelen,
						valuelen,
						args.value);
				kmem_free(args.value);
			} else {
				retval = context->put_listent(context,
						entry->flags,
						name_rmt->name,
						(int)name_rmt->namelen,
						valuelen,
						NULL);
			}
			if (retval)
				return retval;
		}
		if (context->seen_enough)
			break;
		cursor->offset++;
	}
	trace_xfs_attr_list_leaf_end(context);
	return(retval);
}

/*========================================================================
 * Indiscriminately delete the entire attribute fork
 *========================================================================*/

/*
 * Recurse (gasp!) through the attribute nodes until we find leaves.
 * We're doing a depth-first traversal in order to invalidate everything.
 */
int
xfs_attr_root_inactive(xfs_trans_t **trans, xfs_inode_t *dp)
{
	xfs_da_blkinfo_t *info;
	xfs_daddr_t blkno;
	struct xfs_buf *bp;
	int error;

	/*
	 * Read block 0 to see what we have to work with.
	 * We only get here if we have extents, since we remove
	 * the extents in reverse order the extent containing
	 * block 0 must still be there.
	 */
	error = xfs_da_node_read(*trans, dp, 0, -1, &bp, XFS_ATTR_FORK);
	if (error)
		return(error);
	blkno = XFS_BUF_ADDR(bp);

	/*
	 * Invalidate the tree, even if the "tree" is only a single leaf block.
	 * This is a depth-first traversal!
	 */
	info = bp->b_addr;
	if (info->magic == cpu_to_be16(XFS_DA_NODE_MAGIC)) {
		error = xfs_attr_node_inactive(trans, dp, bp, 1);
	} else if (info->magic == cpu_to_be16(XFS_ATTR_LEAF_MAGIC)) {
		error = xfs_attr_leaf_inactive(trans, dp, bp);
	} else {
		error = XFS_ERROR(EIO);
		xfs_trans_brelse(*trans, bp);
	}
	if (error)
		return(error);

	/*
	 * Invalidate the incore copy of the root block.
	 */
	error = xfs_da_get_buf(*trans, dp, 0, blkno, &bp, XFS_ATTR_FORK);
	if (error)
		return(error);
	xfs_trans_binval(*trans, bp);	/* remove from cache */
	/*
	 * Commit the invalidate and start the next transaction.
	 */
	error = xfs_trans_roll(trans, dp);

	return (error);
}

/*
 * Recurse (gasp!) through the attribute nodes until we find leaves.
 * We're doing a depth-first traversal in order to invalidate everything.
 */
STATIC int
xfs_attr_node_inactive(
	struct xfs_trans **trans,
	struct xfs_inode *dp,
	struct xfs_buf	*bp,
	int		level)
{
	xfs_da_blkinfo_t *info;
	xfs_da_intnode_t *node;
	xfs_dablk_t child_fsb;
	xfs_daddr_t parent_blkno, child_blkno;
	int error, count, i;
	struct xfs_buf *child_bp;

	/*
	 * Since this code is recursive (gasp!) we must protect ourselves.
	 */
	if (level > XFS_DA_NODE_MAXDEPTH) {
		xfs_trans_brelse(*trans, bp);	/* no locks for later trans */
		return(XFS_ERROR(EIO));
	}

	node = bp->b_addr;
	ASSERT(node->hdr.info.magic == cpu_to_be16(XFS_DA_NODE_MAGIC));
	parent_blkno = XFS_BUF_ADDR(bp);	/* save for re-read later */
	count = be16_to_cpu(node->hdr.count);
	if (!count) {
		xfs_trans_brelse(*trans, bp);
		return(0);
	}
	child_fsb = be32_to_cpu(node->btree[0].before);
	xfs_trans_brelse(*trans, bp);	/* no locks for later trans */

	/*
	 * If this is the node level just above the leaves, simply loop
	 * over the leaves removing all of them.  If this is higher up
	 * in the tree, recurse downward.
	 */
	for (i = 0; i < count; i++) {
		/*
		 * Read the subsidiary block to see what we have to work with.
		 * Don't do this in a transaction.  This is a depth-first
		 * traversal of the tree so we may deal with many blocks
		 * before we come back to this one.
		 */
		error = xfs_da_node_read(*trans, dp, child_fsb, -2, &child_bp,
						XFS_ATTR_FORK);
		if (error)
			return(error);
		if (child_bp) {
						/* save for re-read later */
			child_blkno = XFS_BUF_ADDR(child_bp);

			/*
			 * Invalidate the subtree, however we have to.
			 */
			info = child_bp->b_addr;
			if (info->magic == cpu_to_be16(XFS_DA_NODE_MAGIC)) {
				error = xfs_attr_node_inactive(trans, dp,
						child_bp, level+1);
			} else if (info->magic == cpu_to_be16(XFS_ATTR_LEAF_MAGIC)) {
				error = xfs_attr_leaf_inactive(trans, dp,
						child_bp);
			} else {
				error = XFS_ERROR(EIO);
				xfs_trans_brelse(*trans, child_bp);
			}
			if (error)
				return(error);

			/*
			 * Remove the subsidiary block from the cache
			 * and from the log.
			 */
			error = xfs_da_get_buf(*trans, dp, 0, child_blkno,
				&child_bp, XFS_ATTR_FORK);
			if (error)
				return(error);
			xfs_trans_binval(*trans, child_bp);
		}

		/*
		 * If we're not done, re-read the parent to get the next
		 * child block number.
		 */
		if ((i+1) < count) {
			error = xfs_da_node_read(*trans, dp, 0, parent_blkno,
						 &bp, XFS_ATTR_FORK);
			if (error)
				return(error);
			child_fsb = be32_to_cpu(node->btree[i+1].before);
			xfs_trans_brelse(*trans, bp);
		}
		/*
		 * Atomically commit the whole invalidate stuff.
		 */
		error = xfs_trans_roll(trans, dp);
		if (error)
			return (error);
	}

	return(0);
}

/*
 * Invalidate all of the "remote" value regions pointed to by a particular
 * leaf block.
 * Note that we must release the lock on the buffer so that we are not
 * caught holding something that the logging code wants to flush to disk.
 */
STATIC int
xfs_attr_leaf_inactive(
	struct xfs_trans **trans,
	struct xfs_inode *dp,
	struct xfs_buf	*bp)
{
	xfs_attr_leafblock_t *leaf;
	xfs_attr_leaf_entry_t *entry;
	xfs_attr_leaf_name_remote_t *name_rmt;
	xfs_attr_inactive_list_t *list, *lp;
	int error, count, size, tmp, i;

	leaf = bp->b_addr;
	ASSERT(leaf->hdr.info.magic == cpu_to_be16(XFS_ATTR_LEAF_MAGIC));

	/*
	 * Count the number of "remote" value extents.
	 */
	count = 0;
	entry = &leaf->entries[0];
	for (i = 0; i < be16_to_cpu(leaf->hdr.count); entry++, i++) {
		if (be16_to_cpu(entry->nameidx) &&
		    ((entry->flags & XFS_ATTR_LOCAL) == 0)) {
			name_rmt = xfs_attr_leaf_name_remote(leaf, i);
			if (name_rmt->valueblk)
				count++;
		}
	}

	/*
	 * If there are no "remote" values, we're done.
	 */
	if (count == 0) {
		xfs_trans_brelse(*trans, bp);
		return(0);
	}

	/*
	 * Allocate storage for a list of all the "remote" value extents.
	 */
	size = count * sizeof(xfs_attr_inactive_list_t);
	list = (xfs_attr_inactive_list_t *)kmem_alloc(size, KM_SLEEP);

	/*
	 * Identify each of the "remote" value extents.
	 */
	lp = list;
	entry = &leaf->entries[0];
	for (i = 0; i < be16_to_cpu(leaf->hdr.count); entry++, i++) {
		if (be16_to_cpu(entry->nameidx) &&
		    ((entry->flags & XFS_ATTR_LOCAL) == 0)) {
			name_rmt = xfs_attr_leaf_name_remote(leaf, i);
			if (name_rmt->valueblk) {
				lp->valueblk = be32_to_cpu(name_rmt->valueblk);
				lp->valuelen = XFS_B_TO_FSB(dp->i_mount,
						    be32_to_cpu(name_rmt->valuelen));
				lp++;
			}
		}
	}
	xfs_trans_brelse(*trans, bp);	/* unlock for trans. in freextent() */

	/*
	 * Invalidate each of the "remote" value extents.
	 */
	error = 0;
	for (lp = list, i = 0; i < count; i++, lp++) {
		tmp = xfs_attr_leaf_freextent(trans, dp,
				lp->valueblk, lp->valuelen);

		if (error == 0)
			error = tmp;	/* save only the 1st errno */
	}

	kmem_free((xfs_caddr_t)list);
	return(error);
}

/*
 * Look at all the extents for this logical region,
 * invalidate any buffers that are incore/in transactions.
 */
STATIC int
xfs_attr_leaf_freextent(xfs_trans_t **trans, xfs_inode_t *dp,
				    xfs_dablk_t blkno, int blkcnt)
{
	xfs_bmbt_irec_t map;
	xfs_dablk_t tblkno;
	int tblkcnt, dblkcnt, nmap, error;
	xfs_daddr_t dblkno;
	xfs_buf_t *bp;

	/*
	 * Roll through the "value", invalidating the attribute value's
	 * blocks.
	 */
	tblkno = blkno;
	tblkcnt = blkcnt;
	while (tblkcnt > 0) {
		/*
		 * Try to remember where we decided to put the value.
		 */
		nmap = 1;
		error = xfs_bmapi_read(dp, (xfs_fileoff_t)tblkno, tblkcnt,
				       &map, &nmap, XFS_BMAPI_ATTRFORK);
		if (error) {
			return(error);
		}
		ASSERT(nmap == 1);
		ASSERT(map.br_startblock != DELAYSTARTBLOCK);

		/*
		 * If it's a hole, these are already unmapped
		 * so there's nothing to invalidate.
		 */
		if (map.br_startblock != HOLESTARTBLOCK) {

			dblkno = XFS_FSB_TO_DADDR(dp->i_mount,
						  map.br_startblock);
			dblkcnt = XFS_FSB_TO_BB(dp->i_mount,
						map.br_blockcount);
			bp = xfs_trans_get_buf(*trans,
					dp->i_mount->m_ddev_targp,
					dblkno, dblkcnt, 0);
			if (!bp)
				return ENOMEM;
			xfs_trans_binval(*trans, bp);
			/*
			 * Roll to next transaction.
			 */
			error = xfs_trans_roll(trans, dp);
			if (error)
				return (error);
		}

		tblkno += map.br_blockcount;
		tblkcnt -= map.br_blockcount;
	}

	return(0);
}
