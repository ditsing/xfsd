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
#include "xfs/xfs_bit.h"
#include "xfs/xfs_log.h"
#include "xfs/xfs_trans.h"
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
 * Local function declarations.
 */
#ifdef DEBUG
static void xfs_dir2_leaf_check(struct xfs_inode *dp, struct xfs_buf *bp);
#else
#define	xfs_dir2_leaf_check(dp, bp)
#endif
static int xfs_dir2_leaf_lookup_int(xfs_da_args_t *args, struct xfs_buf **lbpp,
				    int *indexp, struct xfs_buf **dbpp);
static void
xfs_dir2_leaf_verify(
	struct xfs_buf		*bp,
	__be16			magic)
{
	struct xfs_mount	*mp = bp->b_target->bt_mount;
	struct xfs_dir2_leaf_hdr *hdr = bp->b_addr;
	int			block_ok = 0;

	block_ok = hdr->info.magic == magic;
	if (!block_ok) {
		XFS_CORRUPTION_ERROR(__func__, XFS_ERRLEVEL_LOW, mp, hdr);
		xfs_buf_ioerror(bp, EFSCORRUPTED);
	}
}

static void
xfs_dir2_leaf1_read_verify(
	struct xfs_buf	*bp)
{
	xfs_dir2_leaf_verify(bp, cpu_to_be16(XFS_DIR2_LEAF1_MAGIC));
}

static void
xfs_dir2_leaf1_write_verify(
	struct xfs_buf	*bp)
{
	xfs_dir2_leaf_verify(bp, cpu_to_be16(XFS_DIR2_LEAF1_MAGIC));
}

void
xfs_dir2_leafn_read_verify(
	struct xfs_buf	*bp)
{
	xfs_dir2_leaf_verify(bp, cpu_to_be16(XFS_DIR2_LEAFN_MAGIC));
}

void
xfs_dir2_leafn_write_verify(
	struct xfs_buf	*bp)
{
	xfs_dir2_leaf_verify(bp, cpu_to_be16(XFS_DIR2_LEAFN_MAGIC));
}

static const struct xfs_buf_ops xfs_dir2_leaf1_buf_ops = {
#ifdef WIN32
	xfs_dir2_leaf1_read_verify,
	xfs_dir2_leaf1_write_verify
#else
	.verify_read = xfs_dir2_leaf1_read_verify,
	.verify_write = xfs_dir2_leaf1_write_verify,
#endif
};

const struct xfs_buf_ops xfs_dir2_leafn_buf_ops = {
#ifdef WIN32
	xfs_dir2_leafn_read_verify,
	xfs_dir2_leafn_write_verify
#else
	.verify_read = xfs_dir2_leafn_read_verify,
	.verify_write = xfs_dir2_leafn_write_verify,
#endif
};

static int
xfs_dir2_leaf_read(
	struct xfs_trans	*tp,
	struct xfs_inode	*dp,
	xfs_dablk_t		fbno,
	xfs_daddr_t		mappedbno,
	struct xfs_buf		**bpp)
{
	return xfs_da_read_buf(tp, dp, fbno, mappedbno, bpp,
				XFS_DATA_FORK, &xfs_dir2_leaf1_buf_ops);
}

int
xfs_dir2_leafn_read(
	struct xfs_trans	*tp,
	struct xfs_inode	*dp,
	xfs_dablk_t		fbno,
	xfs_daddr_t		mappedbno,
	struct xfs_buf		**bpp)
{
	return xfs_da_read_buf(tp, dp, fbno, mappedbno, bpp,
				XFS_DATA_FORK, &xfs_dir2_leafn_buf_ops);
}

STATIC void
xfs_dir2_leaf_find_stale(
	struct xfs_dir2_leaf	*leaf,
	int			index,
	int			*lowstale,
	int			*highstale)
{
	/*
	 * Find the first stale entry before our index, if any.
	 */
	for (*lowstale = index - 1; *lowstale >= 0; --*lowstale) {
		if (leaf->ents[*lowstale].address ==
		    cpu_to_be32(XFS_DIR2_NULL_DATAPTR))
			break;
	}

	/*
	 * Find the first stale entry at or after our index, if any.
	 * Stop if the result would require moving more entries than using
	 * lowstale.
	 */
	for (*highstale = index;
	     *highstale < be16_to_cpu(leaf->hdr.count);
	     ++*highstale) {
		if (leaf->ents[*highstale].address ==
		    cpu_to_be32(XFS_DIR2_NULL_DATAPTR))
			break;
		if (*lowstale >= 0 && index - *lowstale <= *highstale - index)
			break;
	}
}

struct xfs_dir2_leaf_entry *
xfs_dir2_leaf_find_entry(
	xfs_dir2_leaf_t		*leaf,		/* leaf structure */
	int			index,		/* leaf table position */
	int			compact,	/* need to compact leaves */
	int			lowstale,	/* index of prev stale leaf */
	int			highstale,	/* index of next stale leaf */
	int			*lfloglow,	/* low leaf logging index */
	int			*lfloghigh)	/* high leaf logging index */
{
	if (!leaf->hdr.stale) {
		xfs_dir2_leaf_entry_t	*lep;	/* leaf entry table pointer */

		/*
		 * Now we need to make room to insert the leaf entry.
		 *
		 * If there are no stale entries, just insert a hole at index.
		 */
		lep = &leaf->ents[index];
		if (index < be16_to_cpu(leaf->hdr.count))
			memmove(lep + 1, lep,
				(be16_to_cpu(leaf->hdr.count) - index) *
				 sizeof(*lep));

		/*
		 * Record low and high logging indices for the leaf.
		 */
		*lfloglow = index;
		*lfloghigh = be16_to_cpu(leaf->hdr.count);
		be16_add_cpu(&leaf->hdr.count, 1);
		return lep;
	}

	/*
	 * There are stale entries.
	 *
	 * We will use one of them for the new entry.  It's probably not at
	 * the right location, so we'll have to shift some up or down first.
	 *
	 * If we didn't compact before, we need to find the nearest stale
	 * entries before and after our insertion point.
	 */
	if (compact == 0)
		xfs_dir2_leaf_find_stale(leaf, index, &lowstale, &highstale);

	/*
	 * If the low one is better, use it.
	 */
	if (lowstale >= 0 &&
	    (highstale == be16_to_cpu(leaf->hdr.count) ||
	     index - lowstale - 1 < highstale - index)) {
		ASSERT(index - lowstale - 1 >= 0);
		ASSERT(leaf->ents[lowstale].address ==
		       cpu_to_be32(XFS_DIR2_NULL_DATAPTR));

		/*
		 * Copy entries up to cover the stale entry and make room
		 * for the new entry.
		 */
		if (index - lowstale - 1 > 0) {
			memmove(&leaf->ents[lowstale],
				&leaf->ents[lowstale + 1],
				(index - lowstale - 1) *
				sizeof(xfs_dir2_leaf_entry_t));
		}
		*lfloglow = MIN(lowstale, *lfloglow);
		*lfloghigh = MAX(index - 1, *lfloghigh);
		be16_add_cpu(&leaf->hdr.stale, -1);
		return &leaf->ents[index - 1];
	}

	/*
	 * The high one is better, so use that one.
	 */
	ASSERT(highstale - index >= 0);
	ASSERT(leaf->ents[highstale].address ==
	       cpu_to_be32(XFS_DIR2_NULL_DATAPTR));

	/*
	 * Copy entries down to cover the stale entry and make room for the
	 * new entry.
	 */
	if (highstale - index > 0) {
		memmove(&leaf->ents[index + 1],
			&leaf->ents[index],
			(highstale - index) * sizeof(xfs_dir2_leaf_entry_t));
	}
	*lfloglow = MIN(index, *lfloglow);
	*lfloghigh = MAX(highstale, *lfloghigh);
	be16_add_cpu(&leaf->hdr.stale, -1);
	return &leaf->ents[index];
}

#ifdef DEBUG
/*
 * Check the internal consistency of a leaf1 block.
 * Pop an assert if something is wrong.
 */
STATIC void
xfs_dir2_leaf_check(
	struct xfs_inode	*dp,		/* incore directory inode */
	struct xfs_buf		*bp)		/* leaf's buffer */
{
	int			i;		/* leaf index */
	xfs_dir2_leaf_t		*leaf;		/* leaf structure */
	xfs_dir2_leaf_tail_t	*ltp;		/* leaf tail pointer */
	xfs_mount_t		*mp;		/* filesystem mount point */
	int			stale;		/* count of stale leaves */

	leaf = bp->b_addr;
	mp = dp->i_mount;
	ASSERT(leaf->hdr.info.magic == cpu_to_be16(XFS_DIR2_LEAF1_MAGIC));
	/*
	 * This value is not restrictive enough.
	 * Should factor in the size of the bests table as well.
	 * We can deduce a value for that from di_size.
	 */
	ASSERT(be16_to_cpu(leaf->hdr.count) <= xfs_dir2_max_leaf_ents(mp));
	ltp = xfs_dir2_leaf_tail_p(mp, leaf);
	/*
	 * Leaves and bests don't overlap.
	 */
	ASSERT((char *)&leaf->ents[be16_to_cpu(leaf->hdr.count)] <=
	       (char *)xfs_dir2_leaf_bests_p(ltp));
	/*
	 * Check hash value order, count stale entries.
	 */
	for (i = stale = 0; i < be16_to_cpu(leaf->hdr.count); i++) {
		if (i + 1 < be16_to_cpu(leaf->hdr.count))
			ASSERT(be32_to_cpu(leaf->ents[i].hashval) <=
			       be32_to_cpu(leaf->ents[i + 1].hashval));
		if (leaf->ents[i].address == cpu_to_be32(XFS_DIR2_NULL_DATAPTR))
			stale++;
	}
	ASSERT(be16_to_cpu(leaf->hdr.stale) == stale);
}
#endif	/* DEBUG */


/*
 * Compact the leaf entries, removing stale ones.
 * Leave one stale entry behind - the one closest to our
 * insertion index - and the caller will shift that one to our insertion
 * point later.
 * Return new insertion index, where the remaining stale entry is,
 * and leaf logging indices.
 */
void
xfs_dir2_leaf_compact_x1(
	struct xfs_buf	*bp,		/* leaf buffer */
	int		*indexp,	/* insertion index */
	int		*lowstalep,	/* out: stale entry before us */
	int		*highstalep,	/* out: stale entry after us */
	int		*lowlogp,	/* out: low log index */
	int		*highlogp)	/* out: high log index */
{
	int		from;		/* source copy index */
	int		highstale;	/* stale entry at/after index */
	int		index;		/* insertion index */
	int		keepstale;	/* source index of kept stale */
	xfs_dir2_leaf_t	*leaf;		/* leaf structure */
	int		lowstale;	/* stale entry before index */
	int		newindex=0;	/* new insertion index */
	int		to;		/* destination copy index */

	leaf = bp->b_addr;
	ASSERT(be16_to_cpu(leaf->hdr.stale) > 1);
	index = *indexp;

	xfs_dir2_leaf_find_stale(leaf, index, &lowstale, &highstale);

	/*
	 * Pick the better of lowstale and highstale.
	 */
	if (lowstale >= 0 &&
	    (highstale == be16_to_cpu(leaf->hdr.count) ||
	     index - lowstale <= highstale - index))
		keepstale = lowstale;
	else
		keepstale = highstale;
	/*
	 * Copy the entries in place, removing all the stale entries
	 * except keepstale.
	 */
	for (from = to = 0; from < be16_to_cpu(leaf->hdr.count); from++) {
		/*
		 * Notice the new value of index.
		 */
		if (index == from)
			newindex = to;
		if (from != keepstale &&
		    leaf->ents[from].address ==
		    cpu_to_be32(XFS_DIR2_NULL_DATAPTR)) {
			if (from == to)
				*lowlogp = to;
			continue;
		}
		/*
		 * Record the new keepstale value for the insertion.
		 */
		if (from == keepstale)
			lowstale = highstale = to;
		/*
		 * Copy only the entries that have moved.
		 */
		if (from > to)
			leaf->ents[to] = leaf->ents[from];
		to++;
	}
	ASSERT(from > to);
	/*
	 * If the insertion point was past the last entry,
	 * set the new insertion point accordingly.
	 */
	if (index == from)
		newindex = to;
	*indexp = newindex;
	/*
	 * Adjust the leaf header values.
	 */
	be16_add_cpu(&leaf->hdr.count, -(from - to));
	leaf->hdr.stale = cpu_to_be16(1);
	/*
	 * Remember the low/high stale value only in the "right"
	 * direction.
	 */
	if (lowstale >= newindex)
		lowstale = -1;
	else
		highstale = be16_to_cpu(leaf->hdr.count);
	*highlogp = be16_to_cpu(leaf->hdr.count) - 1;
	*lowstalep = lowstale;
	*highstalep = highstale;
}

struct xfs_dir2_leaf_map_info {
	xfs_extlen_t	map_blocks;	/* number of fsbs in map */
	xfs_dablk_t	map_off;	/* last mapped file offset */
	int		map_size;	/* total entries in *map */
	int		map_valid;	/* valid entries in *map */
	int		nmap;		/* mappings to ask xfs_bmapi */
	xfs_dir2_db_t	curdb;		/* db for current block */
	int		ra_current;	/* number of read-ahead blks */
	int		ra_index;	/* *map index for read-ahead */
	int		ra_offset;	/* map entry offset for ra */
	int		ra_want;	/* readahead count wanted */
	struct xfs_bmbt_irec map[];	/* map vector for blocks */
};

STATIC int
xfs_dir2_leaf_readbuf(
	struct xfs_inode	*dp,
	size_t			bufsize,
	struct xfs_dir2_leaf_map_info *mip,
	xfs_dir2_off_t		*curoff,
	struct xfs_buf		**bpp)
{
	struct xfs_mount	*mp = dp->i_mount;
	struct xfs_buf		*bp = *bpp;
	struct xfs_bmbt_irec	*map = mip->map;
	int			error = 0;
	int			length;
	int			i;
	int			j;

	/*
	 * If we have a buffer, we need to release it and
	 * take it out of the mapping.
	 */

	if (bp) {
		xfs_trans_brelse(NULL, bp);
		bp = NULL;
		mip->map_blocks -= mp->m_dirblkfsbs;
		/*
		 * Loop to get rid of the extents for the
		 * directory block.
		 */
		for (i = mp->m_dirblkfsbs; i > 0; ) {
			j = min_t(int, map->br_blockcount, i);
			map->br_blockcount -= j;
			map->br_startblock += j;
			map->br_startoff += j;
			/*
			 * If mapping is done, pitch it from
			 * the table.
			 */
			if (!map->br_blockcount && --mip->map_valid)
				memmove(&map[0], &map[1],
					sizeof(map[0]) * mip->map_valid);
			i -= j;
		}
	}

	/*
	 * Recalculate the readahead blocks wanted.
	 */
	mip->ra_want = howmany(bufsize + mp->m_dirblksize,
			       mp->m_sb.sb_blocksize) - 1;
	ASSERT(mip->ra_want >= 0);

	/*
	 * If we don't have as many as we want, and we haven't
	 * run out of data blocks, get some more mappings.
	 */
	if (1 + mip->ra_want > mip->map_blocks &&
	    mip->map_off < xfs_dir2_byte_to_da(mp, XFS_DIR2_LEAF_OFFSET)) {
		/*
		 * Get more bmaps, fill in after the ones
		 * we already have in the table.
		 */
		mip->nmap = mip->map_size - mip->map_valid;
		error = xfs_bmapi_read(dp, mip->map_off,
				xfs_dir2_byte_to_da(mp, XFS_DIR2_LEAF_OFFSET) -
								mip->map_off,
				&map[mip->map_valid], &mip->nmap, 0);

		/*
		 * Don't know if we should ignore this or try to return an
		 * error.  The trouble with returning errors is that readdir
		 * will just stop without actually passing the error through.
		 */
		if (error)
			goto out;	/* XXX */

		/*
		 * If we got all the mappings we asked for, set the final map
		 * offset based on the last bmap value received.  Otherwise,
		 * we've reached the end.
		 */
		if (mip->nmap == mip->map_size - mip->map_valid) {
			i = mip->map_valid + mip->nmap - 1;
			mip->map_off = map[i].br_startoff + map[i].br_blockcount;
		} else
			mip->map_off = xfs_dir2_byte_to_da(mp,
							XFS_DIR2_LEAF_OFFSET);

		/*
		 * Look for holes in the mapping, and eliminate them.  Count up
		 * the valid blocks.
		 */
		for (i = mip->map_valid; i < mip->map_valid + mip->nmap; ) {
			if (map[i].br_startblock == HOLESTARTBLOCK) {
				mip->nmap--;
				length = mip->map_valid + mip->nmap - i;
				if (length)
					memmove(&map[i], &map[i + 1],
						sizeof(map[i]) * length);
			} else {
				mip->map_blocks += map[i].br_blockcount;
				i++;
			}
		}
		mip->map_valid += mip->nmap;
	}

	/*
	 * No valid mappings, so no more data blocks.
	 */
	if (!mip->map_valid) {
		*curoff = xfs_dir2_da_to_byte(mp, mip->map_off);
		goto out;
	}

	/*
	 * Read the directory block starting at the first mapping.
	 */
	mip->curdb = xfs_dir2_da_to_db(mp, map->br_startoff);
	error = xfs_dir2_data_read(NULL, dp, map->br_startoff,
			map->br_blockcount >= mp->m_dirblkfsbs ?
			    XFS_FSB_TO_DADDR(mp, map->br_startblock) : -1, &bp);

	/*
	 * Should just skip over the data block instead of giving up.
	 */
	if (error)
		goto out;	/* XXX */

	/*
	 * Adjust the current amount of read-ahead: we just read a block that
	 * was previously ra.
	 */
	if (mip->ra_current)
		mip->ra_current -= mp->m_dirblkfsbs;

	/*
	 * Do we need more readahead?
	 */
	for (mip->ra_index = mip->ra_offset = i = 0;
	     mip->ra_want > mip->ra_current && i < mip->map_blocks;
	     i += mp->m_dirblkfsbs) {
		ASSERT(mip->ra_index < mip->map_valid);
		/*
		 * Read-ahead a contiguous directory block.
		 */
		if (i > mip->ra_current &&
		    map[mip->ra_index].br_blockcount >= mp->m_dirblkfsbs) {
			xfs_dir2_data_readahead(NULL, dp,
				map[mip->ra_index].br_startoff + mip->ra_offset,
				XFS_FSB_TO_DADDR(mp,
					map[mip->ra_index].br_startblock +
							mip->ra_offset));
			mip->ra_current = i;
		}

		/*
		 * Read-ahead a non-contiguous directory block.  This doesn't
		 * use our mapping, but this is a very rare case.
		 */
		else if (i > mip->ra_current) {
			xfs_dir2_data_readahead(NULL, dp,
					map[mip->ra_index].br_startoff +
							mip->ra_offset, -1);
			mip->ra_current = i;
		}

		/*
		 * Advance offset through the mapping table.
		 */
		for (j = 0; j < mp->m_dirblkfsbs; j++) {
			/*
			 * The rest of this extent but not more than a dir
			 * block.
			 */
			length = min_t(int, mp->m_dirblkfsbs,
					map[mip->ra_index].br_blockcount -
							mip->ra_offset);
			j += length;
			mip->ra_offset += length;

			/*
			 * Advance to the next mapping if this one is used up.
			 */
			if (mip->ra_offset == map[mip->ra_index].br_blockcount) {
				mip->ra_offset = 0;
				mip->ra_index++;
			}
		}
	}

out:
	*bpp = bp;
	return error;
}

/*
 * Getdents (readdir) for leaf and node directories.
 * This reads the data blocks only, so is the same for both forms.
 */
int						/* error */
xfs_dir2_leaf_getdents(
	xfs_inode_t		*dp,		/* incore directory inode */
	void			*dirent,
	size_t			bufsize,
	xfs_off_t		*offset,
	filldir_t		filldir)
{
	struct xfs_buf		*bp = NULL;	/* data block buffer */
	xfs_dir2_data_hdr_t	*hdr;		/* data block header */
	xfs_dir2_data_entry_t	*dep;		/* data entry */
	xfs_dir2_data_unused_t	*dup;		/* unused entry */
	int			error = 0;	/* error return value */
	int			length;		/* temporary length value */
	xfs_mount_t		*mp;		/* filesystem mount point */
	int			byteoff;	/* offset in current block */
	xfs_dir2_off_t		curoff;		/* current overall offset */
	xfs_dir2_off_t		newoff;		/* new curoff after new blk */
	char			*ptr = NULL;	/* pointer to current data */
	struct xfs_dir2_leaf_map_info *map_info;

	/*
	 * If the offset is at or past the largest allowed value,
	 * give up right away.
	 */
	if (*offset >= XFS_DIR2_MAX_DATAPTR)
		return 0;

	mp = dp->i_mount;

	/*
	 * Set up to bmap a number of blocks based on the caller's
	 * buffer size, the directory block size, and the filesystem
	 * block size.
	 */
	length = howmany(bufsize + mp->m_dirblksize,
				     mp->m_sb.sb_blocksize);
	map_info = kmem_zalloc(offsetof(struct xfs_dir2_leaf_map_info, map) +
				(length * sizeof(struct xfs_bmbt_irec)),
			       KM_SLEEP);
	map_info->map_size = length;

	/*
	 * Inside the loop we keep the main offset value as a byte offset
	 * in the directory file.
	 */
	curoff = xfs_dir2_dataptr_to_byte(mp, *offset);

	/*
	 * Force this conversion through db so we truncate the offset
	 * down to get the start of the data block.
	 */
	map_info->map_off = xfs_dir2_db_to_da(mp,
					      xfs_dir2_byte_to_db(mp, curoff));

	/*
	 * Loop over directory entries until we reach the end offset.
	 * Get more blocks and readahead as necessary.
	 */
	while (curoff < XFS_DIR2_LEAF_OFFSET) {
		/*
		 * If we have no buffer, or we're off the end of the
		 * current buffer, need to get another one.
		 */
		if (!bp || ptr >= (char *)bp->b_addr + mp->m_dirblksize) {

			error = xfs_dir2_leaf_readbuf(dp, bufsize, map_info,
						      &curoff, &bp);
			if (error || !map_info->map_valid)
				break;

			/*
			 * Having done a read, we need to set a new offset.
			 */
			newoff = xfs_dir2_db_off_to_byte(mp, map_info->curdb, 0);
			/*
			 * Start of the current block.
			 */
			if (curoff < newoff)
				curoff = newoff;
			/*
			 * Make sure we're in the right block.
			 */
			else if (curoff > newoff)
				ASSERT(xfs_dir2_byte_to_db(mp, curoff) ==
				       map_info->curdb);
			hdr = bp->b_addr;
			xfs_dir2_data_check(dp, bp);
			/*
			 * Find our position in the block.
			 */
			ptr = (char *)(hdr + 1);
			byteoff = xfs_dir2_byte_to_off(mp, curoff);
			/*
			 * Skip past the header.
			 */
			if (byteoff == 0)
				curoff += (uint)sizeof(*hdr);
			/*
			 * Skip past entries until we reach our offset.
			 */
			else {
				while ((char *)ptr - (char *)hdr < byteoff) {
					dup = (xfs_dir2_data_unused_t *)ptr;

					if (be16_to_cpu(dup->freetag)
						  == XFS_DIR2_DATA_FREE_TAG) {

						length = be16_to_cpu(dup->length);
						ptr += length;
						continue;
					}
					dep = (xfs_dir2_data_entry_t *)ptr;
					length =
					   xfs_dir2_data_entsize(dep->namelen);
					ptr += length;
				}
				/*
				 * Now set our real offset.
				 */
				curoff =
					xfs_dir2_db_off_to_byte(mp,
					    xfs_dir2_byte_to_db(mp, curoff),
					    (char *)ptr - (char *)hdr);
				if (ptr >= (char *)hdr + mp->m_dirblksize) {
					continue;
				}
			}
		}
		/*
		 * We have a pointer to an entry.
		 * Is it a live one?
		 */
		dup = (xfs_dir2_data_unused_t *)ptr;
		/*
		 * No, it's unused, skip over it.
		 */
		if (be16_to_cpu(dup->freetag) == XFS_DIR2_DATA_FREE_TAG) {
			length = be16_to_cpu(dup->length);
			ptr += length;
			curoff += length;
			continue;
		}

		dep = (xfs_dir2_data_entry_t *)ptr;
		length = xfs_dir2_data_entsize(dep->namelen);

		if (filldir(dirent, (char *)dep->name, dep->namelen,
			    xfs_dir2_byte_to_dataptr(mp, curoff) & 0x7fffffff,
			    be64_to_cpu(dep->inumber), DT_UNKNOWN))
			break;

		/*
		 * Advance to next entry in the block.
		 */
		ptr += length;
		curoff += length;
		/* bufsize may have just been a guess; don't go negative */
		bufsize = bufsize > length ? bufsize - length : 0;
	}

	/*
	 * All done.  Set output offset value to current offset.
	 */
	if (curoff > xfs_dir2_dataptr_to_byte(mp, XFS_DIR2_MAX_DATAPTR))
		*offset = XFS_DIR2_MAX_DATAPTR & 0x7fffffff;
	else
		*offset = xfs_dir2_byte_to_dataptr(mp, curoff) & 0x7fffffff;
	kmem_free(map_info);
	if (bp)
		xfs_trans_brelse(NULL, bp);
	return error;
}

/*
 * Look up the entry referred to by args in the leaf format directory.
 * Most of the work is done by the xfs_dir2_leaf_lookup_int routine which
 * is also used by the node-format code.
 */
int
xfs_dir2_leaf_lookup(
	xfs_da_args_t		*args)		/* operation arguments */
{
	struct xfs_buf		*dbp;		/* data block buffer */
	xfs_dir2_data_entry_t	*dep;		/* data block entry */
	xfs_inode_t		*dp;		/* incore directory inode */
	int			error;		/* error return code */
	int			index;		/* found entry index */
	struct xfs_buf		*lbp;		/* leaf buffer */
	xfs_dir2_leaf_t		*leaf;		/* leaf structure */
	xfs_dir2_leaf_entry_t	*lep;		/* leaf entry */
	xfs_trans_t		*tp;		/* transaction pointer */

	trace_xfs_dir2_leaf_lookup(args);

	/*
	 * Look up name in the leaf block, returning both buffers and index.
	 */
	if ((error = xfs_dir2_leaf_lookup_int(args, &lbp, &index, &dbp))) {
		return error;
	}
	tp = args->trans;
	dp = args->dp;
	xfs_dir2_leaf_check(dp, lbp);
	leaf = lbp->b_addr;
	/*
	 * Get to the leaf entry and contained data entry address.
	 */
	lep = &leaf->ents[index];
	/*
	 * Point to the data entry.
	 */
	dep = (xfs_dir2_data_entry_t *)
	      ((char *)dbp->b_addr +
	       xfs_dir2_dataptr_to_off(dp->i_mount, be32_to_cpu(lep->address)));
	/*
	 * Return the found inode number & CI name if appropriate
	 */
	args->inumber = be64_to_cpu(dep->inumber);
	error = xfs_dir_cilookup_result(args, dep->name, dep->namelen);
	xfs_trans_brelse(tp, dbp);
	xfs_trans_brelse(tp, lbp);
	return XFS_ERROR(error);
}

/*
 * Look up name/hash in the leaf block.
 * Fill in indexp with the found index, and dbpp with the data buffer.
 * If not found dbpp will be NULL, and ENOENT comes back.
 * lbpp will always be filled in with the leaf buffer unless there's an error.
 */
static int					/* error */
xfs_dir2_leaf_lookup_int(
	xfs_da_args_t		*args,		/* operation arguments */
	struct xfs_buf		**lbpp,		/* out: leaf buffer */
	int			*indexp,	/* out: index in leaf block */
	struct xfs_buf		**dbpp)		/* out: data buffer */
{
	xfs_dir2_db_t		curdb = -1;	/* current data block number */
	struct xfs_buf		*dbp = NULL;	/* data buffer */
	xfs_dir2_data_entry_t	*dep;		/* data entry */
	xfs_inode_t		*dp;		/* incore directory inode */
	int			error;		/* error return code */
	int			index;		/* index in leaf block */
	struct xfs_buf		*lbp;		/* leaf buffer */
	xfs_dir2_leaf_entry_t	*lep;		/* leaf entry */
	xfs_dir2_leaf_t		*leaf;		/* leaf structure */
	xfs_mount_t		*mp;		/* filesystem mount point */
	xfs_dir2_db_t		newdb;		/* new data block number */
	xfs_trans_t		*tp;		/* transaction pointer */
	xfs_dir2_db_t		cidb = -1;	/* case match data block no. */
	enum xfs_dacmp		cmp;		/* name compare result */

	dp = args->dp;
	tp = args->trans;
	mp = dp->i_mount;

	error = xfs_dir2_leaf_read(tp, dp, mp->m_dirleafblk, -1, &lbp);
	if (error)
		return error;

	*lbpp = lbp;
	leaf = lbp->b_addr;
	xfs_dir2_leaf_check(dp, lbp);
	/*
	 * Look for the first leaf entry with our hash value.
	 */
	index = xfs_dir2_leaf_search_hash(args, lbp);
	/*
	 * Loop over all the entries with the right hash value
	 * looking to match the name.
	 */
	for (lep = &leaf->ents[index]; index < be16_to_cpu(leaf->hdr.count) &&
				be32_to_cpu(lep->hashval) == args->hashval;
				lep++, index++) {
		/*
		 * Skip over stale leaf entries.
		 */
		if (be32_to_cpu(lep->address) == XFS_DIR2_NULL_DATAPTR)
			continue;
		/*
		 * Get the new data block number.
		 */
		newdb = xfs_dir2_dataptr_to_db(mp, be32_to_cpu(lep->address));
		/*
		 * If it's not the same as the old data block number,
		 * need to pitch the old one and read the new one.
		 */
		if (newdb != curdb) {
			if (dbp)
				xfs_trans_brelse(tp, dbp);
			error = xfs_dir2_data_read(tp, dp,
						   xfs_dir2_db_to_da(mp, newdb),
						   -1, &dbp);
			if (error) {
				xfs_trans_brelse(tp, lbp);
				return error;
			}
			curdb = newdb;
		}
		/*
		 * Point to the data entry.
		 */
		dep = (xfs_dir2_data_entry_t *)((char *)dbp->b_addr +
			xfs_dir2_dataptr_to_off(mp, be32_to_cpu(lep->address)));
		/*
		 * Compare name and if it's an exact match, return the index
		 * and buffer. If it's the first case-insensitive match, store
		 * the index and buffer and continue looking for an exact match.
		 */
		cmp = mp->m_dirnameops->compname(args, dep->name, dep->namelen);
		if (cmp != XFS_CMP_DIFFERENT && cmp != args->cmpresult) {
			args->cmpresult = cmp;
			*indexp = index;
			/* case exact match: return the current buffer. */
			if (cmp == XFS_CMP_EXACT) {
				*dbpp = dbp;
				return 0;
			}
			cidb = curdb;
		}
	}
	ASSERT(args->op_flags & XFS_DA_OP_OKNOENT);
	/*
	 * Here, we can only be doing a lookup (not a rename or remove).
	 * If a case-insensitive match was found earlier, re-read the
	 * appropriate data block if required and return it.
	 */
	if (args->cmpresult == XFS_CMP_CASE) {
		ASSERT(cidb != -1);
		if (cidb != curdb) {
			xfs_trans_brelse(tp, dbp);
			error = xfs_dir2_data_read(tp, dp,
						   xfs_dir2_db_to_da(mp, cidb),
						   -1, &dbp);
			if (error) {
				xfs_trans_brelse(tp, lbp);
				return error;
			}
		}
		*dbpp = dbp;
		return 0;
	}
	/*
	 * No match found, return ENOENT.
	 */
	ASSERT(cidb == -1);
	if (dbp)
		xfs_trans_brelse(tp, dbp);
	xfs_trans_brelse(tp, lbp);
	return XFS_ERROR(ENOENT);
}

/*
 * Return index in the leaf block (lbp) which is either the first
 * one with this hash value, or if there are none, the insert point
 * for that hash value.
 */
int						/* index value */
xfs_dir2_leaf_search_hash(
	xfs_da_args_t		*args,		/* operation arguments */
	struct xfs_buf		*lbp)		/* leaf buffer */
{
	xfs_dahash_t		hash=0;		/* hash from this entry */
	xfs_dahash_t		hashwant;	/* hash value looking for */
	int			high;		/* high leaf index */
	int			low;		/* low leaf index */
	xfs_dir2_leaf_t		*leaf;		/* leaf structure */
	xfs_dir2_leaf_entry_t	*lep;		/* leaf entry */
	int			mid=0;		/* current leaf index */

	leaf = lbp->b_addr;
#ifndef __KERNEL__
	if (!leaf->hdr.count)
		return 0;
#endif
	/*
	 * Note, the table cannot be empty, so we have to go through the loop.
	 * Binary search the leaf entries looking for our hash value.
	 */
	for (lep = leaf->ents, low = 0, high = be16_to_cpu(leaf->hdr.count) - 1,
		hashwant = args->hashval;
	     low <= high; ) {
		mid = (low + high) >> 1;
		if ((hash = be32_to_cpu(lep[mid].hashval)) == hashwant)
			break;
		if (hash < hashwant)
			low = mid + 1;
		else
			high = mid - 1;
	}
	/*
	 * Found one, back up through all the equal hash values.
	 */
	if (hash == hashwant) {
		while (mid > 0 && be32_to_cpu(lep[mid - 1].hashval) == hashwant) {
			mid--;
		}
	}
	/*
	 * Need to point to an entry higher than ours.
	 */
	else if (hash < hashwant)
		mid++;
	return mid;
}

static inline size_t
xfs_dir2_leaf_size(
	struct xfs_dir2_leaf_hdr	*hdr,
	int				counts)
{
	int			entries;

	entries = be16_to_cpu(hdr->count) - be16_to_cpu(hdr->stale);
	return sizeof(xfs_dir2_leaf_hdr_t) +
	    entries * sizeof(xfs_dir2_leaf_entry_t) +
	    counts * sizeof(xfs_dir2_data_off_t) +
	    sizeof(xfs_dir2_leaf_tail_t);
}
