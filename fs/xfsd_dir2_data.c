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
#include "xfs/xfs_log.h"
#include "xfs/xfs_trans.h"
#include "xfs/xfs_sb.h"
#include "xfs/xfs_ag.h"
#include "xfs/xfs_mount.h"
#include "xfs/xfs_da_btree.h"
#include "xfs/xfs_bmap_btree.h"
#include "xfs/xfs_dinode.h"
#include "xfs/xfs_inode.h"
#include "xfs/xfs_dir2_format.h"
#include "xfs/xfs_dir2_priv.h"
#include "xfs/xfs_error.h"

STATIC xfs_dir2_data_free_t *
xfs_dir2_data_freefind(xfs_dir2_data_hdr_t *hdr, xfs_dir2_data_unused_t *dup);

/*
 * Check the consistency of the data block.
 * The input can also be a block-format directory.
 * Return 0 is the buffer is good, otherwise an error.
 */
int
__xfs_dir2_data_check(
	struct xfs_inode	*dp,		/* incore inode pointer */
	struct xfs_buf		*bp)		/* data block's buffer */
{
	xfs_dir2_dataptr_t	addr;		/* addr for leaf lookup */
	xfs_dir2_data_free_t	*bf;		/* bestfree table */
	xfs_dir2_block_tail_t	*btp=NULL;	/* block tail */
	int			count;		/* count of entries found */
	xfs_dir2_data_hdr_t	*hdr;		/* data block header */
	xfs_dir2_data_entry_t	*dep;		/* data entry */
	xfs_dir2_data_free_t	*dfp;		/* bestfree entry */
	xfs_dir2_data_unused_t	*dup;		/* unused entry */
	char			*endp;		/* end of useful data */
	int			freeseen;	/* mask of bestfrees seen */
	xfs_dahash_t		hash;		/* hash of current name */
	int			i;		/* leaf index */
	int			lastfree;	/* last entry was unused */
	xfs_dir2_leaf_entry_t	*lep=NULL;	/* block leaf entries */
	xfs_mount_t		*mp;		/* filesystem mount point */
	char			*p;		/* current data position */
	int			stale;		/* count of stale leaves */
	struct xfs_name		name;

	mp = bp->b_target->bt_mount;
	hdr = bp->b_addr;
	bf = hdr->bestfree;
	p = (char *)(hdr + 1);

	switch (hdr->magic) {
	case cpu_to_be32(XFS_DIR2_BLOCK_MAGIC):
		btp = xfs_dir2_block_tail_p(mp, hdr);
		lep = xfs_dir2_block_leaf_p(btp);
		endp = (char *)lep;
		break;
	case cpu_to_be32(XFS_DIR2_DATA_MAGIC):
		endp = (char *)hdr + mp->m_dirblksize;
		break;
	default:
		XFS_ERROR_REPORT("Bad Magic", XFS_ERRLEVEL_LOW, mp);
		return EFSCORRUPTED;
	}

	count = lastfree = freeseen = 0;
	/*
	 * Account for zero bestfree entries.
	 */
	if (!bf[0].length) {
		XFS_WANT_CORRUPTED_RETURN(!bf[0].offset);
		freeseen |= 1 << 0;
	}
	if (!bf[1].length) {
		XFS_WANT_CORRUPTED_RETURN(!bf[1].offset);
		freeseen |= 1 << 1;
	}
	if (!bf[2].length) {
		XFS_WANT_CORRUPTED_RETURN(!bf[2].offset);
		freeseen |= 1 << 2;
	}

	XFS_WANT_CORRUPTED_RETURN(be16_to_cpu(bf[0].length) >=
						be16_to_cpu(bf[1].length));
	XFS_WANT_CORRUPTED_RETURN(be16_to_cpu(bf[1].length) >=
						be16_to_cpu(bf[2].length));
	/*
	 * Loop over the data/unused entries.
	 */
	while (p < endp) {
		dup = (xfs_dir2_data_unused_t *)p;
		/*
		 * If it's unused, look for the space in the bestfree table.
		 * If we find it, account for that, else make sure it
		 * doesn't need to be there.
		 */
		if (be16_to_cpu(dup->freetag) == XFS_DIR2_DATA_FREE_TAG) {
			XFS_WANT_CORRUPTED_RETURN(lastfree == 0);
			XFS_WANT_CORRUPTED_RETURN(
				be16_to_cpu(*xfs_dir2_data_unused_tag_p(dup)) ==
					       (char *)dup - (char *)hdr);
			dfp = xfs_dir2_data_freefind(hdr, dup);
			if (dfp) {
				i = (int)(dfp - bf);
				XFS_WANT_CORRUPTED_RETURN(
					(freeseen & (1 << i)) == 0);
				freeseen |= 1 << i;
			} else {
				XFS_WANT_CORRUPTED_RETURN(
					be16_to_cpu(dup->length) <=
						be16_to_cpu(bf[2].length));
			}
			p += be16_to_cpu(dup->length);
			lastfree = 1;
			continue;
		}
		/*
		 * It's a real entry.  Validate the fields.
		 * If this is a block directory then make sure it's
		 * in the leaf section of the block.
		 * The linear search is crude but this is DEBUG code.
		 */
		dep = (xfs_dir2_data_entry_t *)p;
		XFS_WANT_CORRUPTED_RETURN(dep->namelen != 0);
		XFS_WANT_CORRUPTED_RETURN(
			!xfs_dir_ino_validate(mp, be64_to_cpu(dep->inumber)));
		XFS_WANT_CORRUPTED_RETURN(
			be16_to_cpu(*xfs_dir2_data_entry_tag_p(dep)) ==
					       (char *)dep - (char *)hdr);
		count++;
		lastfree = 0;
		if (hdr->magic == cpu_to_be32(XFS_DIR2_BLOCK_MAGIC)) {
			addr = xfs_dir2_db_off_to_dataptr(mp, mp->m_dirdatablk,
				(xfs_dir2_data_aoff_t)
				((char *)dep - (char *)hdr));
			name.name = dep->name;
			name.len = dep->namelen;
			hash = mp->m_dirnameops->hashname(&name);
			for (i = 0; i < be32_to_cpu(btp->count); i++) {
				if (be32_to_cpu(lep[i].address) == addr &&
				    be32_to_cpu(lep[i].hashval) == hash)
					break;
			}
			XFS_WANT_CORRUPTED_RETURN(i < be32_to_cpu(btp->count));
		}
		p += xfs_dir2_data_entsize(dep->namelen);
	}
	/*
	 * Need to have seen all the entries and all the bestfree slots.
	 */
	XFS_WANT_CORRUPTED_RETURN(freeseen == 7);
	if (hdr->magic == cpu_to_be32(XFS_DIR2_BLOCK_MAGIC)) {
		for (i = stale = 0; i < be32_to_cpu(btp->count); i++) {
			if (lep[i].address ==
			    cpu_to_be32(XFS_DIR2_NULL_DATAPTR))
				stale++;
			if (i > 0)
				XFS_WANT_CORRUPTED_RETURN(
					be32_to_cpu(lep[i].hashval) >=
						be32_to_cpu(lep[i - 1].hashval));
		}
		XFS_WANT_CORRUPTED_RETURN(count ==
			be32_to_cpu(btp->count) - be32_to_cpu(btp->stale));
		XFS_WANT_CORRUPTED_RETURN(stale == be32_to_cpu(btp->stale));
	}
	return 0;
}

static void
xfs_dir2_data_verify(
	struct xfs_buf		*bp)
{
	struct xfs_mount	*mp = bp->b_target->bt_mount;
	struct xfs_dir2_data_hdr *hdr = bp->b_addr;
	int			block_ok = 0;

	block_ok = hdr->magic == cpu_to_be32(XFS_DIR2_DATA_MAGIC);
	block_ok = block_ok && __xfs_dir2_data_check(NULL, bp) == 0;

	if (!block_ok) {
		XFS_CORRUPTION_ERROR(__func__, XFS_ERRLEVEL_LOW, mp, hdr);
		xfs_buf_ioerror(bp, EFSCORRUPTED);
	}
}

/*
 * Readahead of the first block of the directory when it is opened is completely
 * oblivious to the format of the directory. Hence we can either get a block
 * format buffer or a data format buffer on readahead.
 */
static void
xfs_dir2_data_reada_verify(
	struct xfs_buf		*bp)
{
	struct xfs_mount	*mp = bp->b_target->bt_mount;
	struct xfs_dir2_data_hdr *hdr = bp->b_addr;

	switch (hdr->magic) {
	case cpu_to_be32(XFS_DIR2_BLOCK_MAGIC):
		bp->b_ops = &xfs_dir2_block_buf_ops;
		bp->b_ops->verify_read(bp);
		return;
	case cpu_to_be32(XFS_DIR2_DATA_MAGIC):
		xfs_dir2_data_verify(bp);
		return;
	default:
		XFS_CORRUPTION_ERROR(__func__, XFS_ERRLEVEL_LOW, mp, hdr);
		xfs_buf_ioerror(bp, EFSCORRUPTED);
		break;
	}
}

static void
xfs_dir2_data_read_verify(
	struct xfs_buf	*bp)
{
	xfs_dir2_data_verify(bp);
}

static void
xfs_dir2_data_write_verify(
	struct xfs_buf	*bp)
{
	xfs_dir2_data_verify(bp);
}

const struct xfs_buf_ops xfs_dir2_data_buf_ops = {
	.verify_read = xfs_dir2_data_read_verify,
	.verify_write = xfs_dir2_data_write_verify,
};

static const struct xfs_buf_ops xfs_dir2_data_reada_buf_ops = {
	.verify_read = xfs_dir2_data_reada_verify,
	.verify_write = xfs_dir2_data_write_verify,
};


int
xfs_dir2_data_read(
	struct xfs_trans	*tp,
	struct xfs_inode	*dp,
	xfs_dablk_t		bno,
	xfs_daddr_t		mapped_bno,
	struct xfs_buf		**bpp)
{
	return xfs_da_read_buf(tp, dp, bno, mapped_bno, bpp,
				XFS_DATA_FORK, &xfs_dir2_data_buf_ops);
}

int
xfs_dir2_data_readahead(
	struct xfs_trans	*tp,
	struct xfs_inode	*dp,
	xfs_dablk_t		bno,
	xfs_daddr_t		mapped_bno)
{
	return xfs_da_reada_buf(tp, dp, bno, mapped_bno,
				XFS_DATA_FORK, &xfs_dir2_data_reada_buf_ops);
}

/*
 * Given a data block and an unused entry from that block,
 * return the bestfree entry if any that corresponds to it.
 */
STATIC xfs_dir2_data_free_t *
xfs_dir2_data_freefind(
	xfs_dir2_data_hdr_t	*hdr,		/* data block */
	xfs_dir2_data_unused_t	*dup)		/* data unused entry */
{
	xfs_dir2_data_free_t	*dfp;		/* bestfree entry */
	xfs_dir2_data_aoff_t	off;		/* offset value needed */
#if defined(DEBUG) && defined(__KERNEL__)
	int			matched;	/* matched the value */
	int			seenzero;	/* saw a 0 bestfree entry */
#endif

	off = (xfs_dir2_data_aoff_t)((char *)dup - (char *)hdr);
#if defined(DEBUG) && defined(__KERNEL__)
	/*
	 * Validate some consistency in the bestfree table.
	 * Check order, non-overlapping entries, and if we find the
	 * one we're looking for it has to be exact.
	 */
	ASSERT(hdr->magic == cpu_to_be32(XFS_DIR2_DATA_MAGIC) ||
	       hdr->magic == cpu_to_be32(XFS_DIR2_BLOCK_MAGIC));
	for (dfp = &hdr->bestfree[0], seenzero = matched = 0;
	     dfp < &hdr->bestfree[XFS_DIR2_DATA_FD_COUNT];
	     dfp++) {
		if (!dfp->offset) {
			ASSERT(!dfp->length);
			seenzero = 1;
			continue;
		}
		ASSERT(seenzero == 0);
		if (be16_to_cpu(dfp->offset) == off) {
			matched = 1;
			ASSERT(dfp->length == dup->length);
		} else if (off < be16_to_cpu(dfp->offset))
			ASSERT(off + be16_to_cpu(dup->length) <= be16_to_cpu(dfp->offset));
		else
			ASSERT(be16_to_cpu(dfp->offset) + be16_to_cpu(dfp->length) <= off);
		ASSERT(matched || be16_to_cpu(dfp->length) >= be16_to_cpu(dup->length));
		if (dfp > &hdr->bestfree[0])
			ASSERT(be16_to_cpu(dfp[-1].length) >= be16_to_cpu(dfp[0].length));
	}
#endif
	/*
	 * If this is smaller than the smallest bestfree entry,
	 * it can't be there since they're sorted.
	 */
	if (be16_to_cpu(dup->length) <
	    be16_to_cpu(hdr->bestfree[XFS_DIR2_DATA_FD_COUNT - 1].length))
		return NULL;
	/*
	 * Look at the three bestfree entries for our guy.
	 */
	for (dfp = &hdr->bestfree[0];
	     dfp < &hdr->bestfree[XFS_DIR2_DATA_FD_COUNT];
	     dfp++) {
		if (!dfp->offset)
			return NULL;
		if (be16_to_cpu(dfp->offset) == off)
			return dfp;
	}
	/*
	 * Didn't find it.  This only happens if there are duplicate lengths.
	 */
	return NULL;
}

/*
 * Insert an unused-space entry into the bestfree table.
 */
xfs_dir2_data_free_t *				/* entry inserted */
xfs_dir2_data_freeinsert(
	xfs_dir2_data_hdr_t	*hdr,		/* data block pointer */
	xfs_dir2_data_unused_t	*dup,		/* unused space */
	int			*loghead)	/* log the data header (out) */
{
	xfs_dir2_data_free_t	*dfp;		/* bestfree table pointer */
	xfs_dir2_data_free_t	new;		/* new bestfree entry */

#ifdef __KERNEL__
	ASSERT(hdr->magic == cpu_to_be32(XFS_DIR2_DATA_MAGIC) ||
	       hdr->magic == cpu_to_be32(XFS_DIR2_BLOCK_MAGIC));
#endif
	dfp = hdr->bestfree;
	new.length = dup->length;
	new.offset = cpu_to_be16((char *)dup - (char *)hdr);

	/*
	 * Insert at position 0, 1, or 2; or not at all.
	 */
	if (be16_to_cpu(new.length) > be16_to_cpu(dfp[0].length)) {
		dfp[2] = dfp[1];
		dfp[1] = dfp[0];
		dfp[0] = new;
		*loghead = 1;
		return &dfp[0];
	}
	if (be16_to_cpu(new.length) > be16_to_cpu(dfp[1].length)) {
		dfp[2] = dfp[1];
		dfp[1] = new;
		*loghead = 1;
		return &dfp[1];
	}
	if (be16_to_cpu(new.length) > be16_to_cpu(dfp[2].length)) {
		dfp[2] = new;
		*loghead = 1;
		return &dfp[2];
	}
	return NULL;
}

/*
 * Remove a bestfree entry from the table.
 */
STATIC void
xfs_dir2_data_freeremove(
	xfs_dir2_data_hdr_t	*hdr,		/* data block header */
	xfs_dir2_data_free_t	*dfp,		/* bestfree entry pointer */
	int			*loghead)	/* out: log data header */
{
#ifdef __KERNEL__
	ASSERT(hdr->magic == cpu_to_be32(XFS_DIR2_DATA_MAGIC) ||
	       hdr->magic == cpu_to_be32(XFS_DIR2_BLOCK_MAGIC));
#endif
	/*
	 * It's the first entry, slide the next 2 up.
	 */
	if (dfp == &hdr->bestfree[0]) {
		hdr->bestfree[0] = hdr->bestfree[1];
		hdr->bestfree[1] = hdr->bestfree[2];
	}
	/*
	 * It's the second entry, slide the 3rd entry up.
	 */
	else if (dfp == &hdr->bestfree[1])
		hdr->bestfree[1] = hdr->bestfree[2];
	/*
	 * Must be the last entry.
	 */
	else
		ASSERT(dfp == &hdr->bestfree[2]);
	/*
	 * Clear the 3rd entry, must be zero now.
	 */
	hdr->bestfree[2].length = 0;
	hdr->bestfree[2].offset = 0;
	*loghead = 1;
}

/*
 * Given a data block, reconstruct its bestfree map.
 */
void
xfs_dir2_data_freescan(
	xfs_mount_t		*mp,		/* filesystem mount point */
	xfs_dir2_data_hdr_t	*hdr,		/* data block header */
	int			*loghead)	/* out: log data header */
{
	xfs_dir2_block_tail_t	*btp;		/* block tail */
	xfs_dir2_data_entry_t	*dep;		/* active data entry */
	xfs_dir2_data_unused_t	*dup;		/* unused data entry */
	char			*endp;		/* end of block's data */
	char			*p;		/* current entry pointer */

#ifdef __KERNEL__
	ASSERT(hdr->magic == cpu_to_be32(XFS_DIR2_DATA_MAGIC) ||
	       hdr->magic == cpu_to_be32(XFS_DIR2_BLOCK_MAGIC));
#endif
	/*
	 * Start by clearing the table.
	 */
	memset(hdr->bestfree, 0, sizeof(hdr->bestfree));
	*loghead = 1;
	/*
	 * Set up pointers.
	 */
	p = (char *)(hdr + 1);
	if (hdr->magic == cpu_to_be32(XFS_DIR2_BLOCK_MAGIC)) {
		btp = xfs_dir2_block_tail_p(mp, hdr);
		endp = (char *)xfs_dir2_block_leaf_p(btp);
	} else
		endp = (char *)hdr + mp->m_dirblksize;
	/*
	 * Loop over the block's entries.
	 */
	while (p < endp) {
		dup = (xfs_dir2_data_unused_t *)p;
		/*
		 * If it's a free entry, insert it.
		 */
		if (be16_to_cpu(dup->freetag) == XFS_DIR2_DATA_FREE_TAG) {
			ASSERT((char *)dup - (char *)hdr ==
			       be16_to_cpu(*xfs_dir2_data_unused_tag_p(dup)));
			xfs_dir2_data_freeinsert(hdr, dup, loghead);
			p += be16_to_cpu(dup->length);
		}
		/*
		 * For active entries, check their tags and skip them.
		 */
		else {
			dep = (xfs_dir2_data_entry_t *)p;
			ASSERT((char *)dep - (char *)hdr ==
			       be16_to_cpu(*xfs_dir2_data_entry_tag_p(dep)));
			p += xfs_dir2_data_entsize(dep->namelen);
		}
	}
}
