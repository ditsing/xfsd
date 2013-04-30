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
#include "xfs/xfs_trans.h"
#include "xfs/xfs_sb.h"
#include "xfs/xfs_ag.h"
#include "xfs/xfs_mount.h"
#include "xfs/xfs_da_btree.h"
#include "xfs/xfs_bmap_btree.h"
#include "xfs/xfs_dir2.h"
#include "xfs/xfs_dir2_format.h"
#include "xfs/xfs_dir2_priv.h"
#include "xfs/xfs_dinode.h"
#include "xfs/xfs_inode.h"
#include "xfs/xfs_inode_item.h"
#include "xfs/xfs_alloc.h"
#include "xfs/xfs_bmap.h"
#include "xfs/xfs_attr.h"
#include "xfs/xfs_attr_leaf.h"
#include "xfs/xfs_error.h"

#include "xfsd_trace.h"

/*
 * xfs_da_btree.c
 *
 * Routines to implement directories as Btrees of hashed names.
 */

/*========================================================================
 * Function prototypes for the kernel.
 *========================================================================*/

/*
 * Utility routines.
 */
STATIC void	xfs_da_state_kill_altpath(xfs_da_state_t *state);

static void
xfs_da_node_verify(
	struct xfs_buf		*bp)
{
	struct xfs_mount	*mp = bp->b_target->bt_mount;
	struct xfs_da_node_hdr *hdr = bp->b_addr;
	int			block_ok = 0;

	block_ok = hdr->info.magic == cpu_to_be16(XFS_DA_NODE_MAGIC);
	block_ok = block_ok &&
			be16_to_cpu(hdr->level) > 0 &&
			be16_to_cpu(hdr->count) > 0 ;
	if (!block_ok) {
		XFS_CORRUPTION_ERROR(__func__, XFS_ERRLEVEL_LOW, mp, hdr);
		xfs_buf_ioerror(bp, EFSCORRUPTED);
	}

}

static void
xfs_da_node_write_verify(
	struct xfs_buf	*bp)
{
	xfs_da_node_verify(bp);
}

/*
 * leaf/node format detection on trees is sketchy, so a node read can be done on
 * leaf level blocks when detection identifies the tree as a node format tree
 * incorrectly. In this case, we need to swap the verifier to match the correct
 * format of the block being read.
 */
static void
xfs_da_node_read_verify(
	struct xfs_buf		*bp)
{
	struct xfs_mount	*mp = bp->b_target->bt_mount;
	struct xfs_da_blkinfo	*info = bp->b_addr;

	switch (be16_to_cpu(info->magic)) {
		case XFS_DA_NODE_MAGIC:
			xfs_da_node_verify(bp);
			break;
		case XFS_ATTR_LEAF_MAGIC:
			bp->b_ops = &xfs_attr_leaf_buf_ops;
			bp->b_ops->verify_read(bp);
			return;
		case XFS_DIR2_LEAFN_MAGIC:
			bp->b_ops = &xfs_dir2_leafn_buf_ops;
			bp->b_ops->verify_read(bp);
			return;
		default:
			XFS_CORRUPTION_ERROR(__func__, XFS_ERRLEVEL_LOW,
					     mp, info);
			xfs_buf_ioerror(bp, EFSCORRUPTED);
			break;
	}
}

const struct xfs_buf_ops xfs_da_node_buf_ops = {
	.verify_read = xfs_da_node_read_verify,
	.verify_write = xfs_da_node_write_verify,
};


int
xfs_da_node_read(
	struct xfs_trans	*tp,
	struct xfs_inode	*dp,
	xfs_dablk_t		bno,
	xfs_daddr_t		mappedbno,
	struct xfs_buf		**bpp,
	int			which_fork)
{
	return xfs_da_read_buf(tp, dp, bno, mappedbno, bpp,
					which_fork, &xfs_da_node_buf_ops);
}

/*========================================================================
 * Routines used for growing the Btree.
 *========================================================================*/

/*========================================================================
 * Routines used for shrinking the Btree.
 *========================================================================*/

#ifdef	DEBUG
static void
xfs_da_blkinfo_onlychild_validate(struct xfs_da_blkinfo *blkinfo, __u16 level)
{
	__be16	magic = blkinfo->magic;

	if (level == 1) {
		ASSERT(magic == cpu_to_be16(XFS_DIR2_LEAFN_MAGIC) ||
		       magic == cpu_to_be16(XFS_ATTR_LEAF_MAGIC));
	} else
		ASSERT(magic == cpu_to_be16(XFS_DA_NODE_MAGIC));
	ASSERT(!blkinfo->forw);
	ASSERT(!blkinfo->back);
}
#else	/* !DEBUG */
#define	xfs_da_blkinfo_onlychild_validate(blkinfo, level)
#endif	/* !DEBUG */

/*========================================================================
 * Routines used for finding things in the Btree.
 *========================================================================*/

/*
 * Walk down the Btree looking for a particular filename, filling
 * in the state structure as we go.
 *
 * We will set the state structure to point to each of the elements
 * in each of the nodes where either the hashval is or should be.
 *
 * We support duplicate hashval's so for each entry in the current
 * node that could contain the desired hashval, descend.  This is a
 * pruned depth-first tree search.
 */
int							/* error */
xfs_da_node_lookup_int(xfs_da_state_t *state, int *result)
{
	xfs_da_state_blk_t *blk;
	xfs_da_blkinfo_t *curr;
	xfs_da_intnode_t *node;
	xfs_da_node_entry_t *btree;
	xfs_dablk_t blkno;
	int probe, span, max, error, retval;
	xfs_dahash_t hashval, btreehashval;
	xfs_da_args_t *args;

	args = state->args;

	/*
	 * Descend thru the B-tree searching each level for the right
	 * node to use, until the right hashval is found.
	 */
	blkno = (args->whichfork == XFS_DATA_FORK)? state->mp->m_dirleafblk : 0;
	for (blk = &state->path.blk[0], state->path.active = 1;
			 state->path.active <= XFS_DA_NODE_MAXDEPTH;
			 blk++, state->path.active++) {
		/*
		 * Read the next node down in the tree.
		 */
		blk->blkno = blkno;
		error = xfs_da_node_read(args->trans, args->dp, blkno,
					-1, &blk->bp, args->whichfork);
		if (error) {
			blk->blkno = 0;
			state->path.active--;
			return(error);
		}
		curr = blk->bp->b_addr;
		blk->magic = be16_to_cpu(curr->magic);
		ASSERT(blk->magic == XFS_DA_NODE_MAGIC ||
		       blk->magic == XFS_DIR2_LEAFN_MAGIC ||
		       blk->magic == XFS_ATTR_LEAF_MAGIC);

		/*
		 * Search an intermediate node for a match.
		 */
		if (blk->magic == XFS_DA_NODE_MAGIC) {
			node = blk->bp->b_addr;
			max = be16_to_cpu(node->hdr.count);
			blk->hashval = be32_to_cpu(node->btree[max-1].hashval);

			/*
			 * Binary search.  (note: small blocks will skip loop)
			 */
			probe = span = max / 2;
			hashval = args->hashval;
			for (btree = &node->btree[probe]; span > 4;
				   btree = &node->btree[probe]) {
				span /= 2;
				btreehashval = be32_to_cpu(btree->hashval);
				if (btreehashval < hashval)
					probe += span;
				else if (btreehashval > hashval)
					probe -= span;
				else
					break;
			}
			ASSERT((probe >= 0) && (probe < max));
			ASSERT((span <= 4) || (be32_to_cpu(btree->hashval) == hashval));

			/*
			 * Since we may have duplicate hashval's, find the first
			 * matching hashval in the node.
			 */
			while ((probe > 0) && (be32_to_cpu(btree->hashval) >= hashval)) {
				btree--;
				probe--;
			}
			while ((probe < max) && (be32_to_cpu(btree->hashval) < hashval)) {
				btree++;
				probe++;
			}

			/*
			 * Pick the right block to descend on.
			 */
			if (probe == max) {
				blk->index = max-1;
				blkno = be32_to_cpu(node->btree[max-1].before);
			} else {
				blk->index = probe;
				blkno = be32_to_cpu(btree->before);
			}
		} else if (blk->magic == XFS_ATTR_LEAF_MAGIC) {
			blk->hashval = xfs_attr_leaf_lasthash(blk->bp, NULL);
			break;
		} else if (blk->magic == XFS_DIR2_LEAFN_MAGIC) {
			blk->hashval = xfs_dir2_leafn_lasthash(blk->bp, NULL);
			break;
		}
	}

	/*
	 * A leaf block that ends in the hashval that we are interested in
	 * (final hashval == search hashval) means that the next block may
	 * contain more entries with the same hashval, shift upward to the
	 * next leaf and keep searching.
	 */
	for (;;) {
		if (blk->magic == XFS_DIR2_LEAFN_MAGIC) {
			retval = xfs_dir2_leafn_lookup_int(blk->bp, args,
							&blk->index, state);
		} else if (blk->magic == XFS_ATTR_LEAF_MAGIC) {
			retval = xfs_attr_leaf_lookup_int(blk->bp, args);
			blk->index = args->index;
			args->blkno = blk->blkno;
		} else {
			ASSERT(0);
			return XFS_ERROR(EFSCORRUPTED);
		}
		if (((retval == ENOENT) || (retval == ENOATTR)) &&
		    (blk->hashval == args->hashval)) {
			error = xfs_da_path_shift(state, &state->path, 1, 1,
							 &retval);
			if (error)
				return(error);
			if (retval == 0) {
				continue;
			} else if (blk->magic == XFS_ATTR_LEAF_MAGIC) {
				/* path_shift() gives ENOENT */
				retval = XFS_ERROR(ENOATTR);
			}
		}
		break;
	}
	*result = retval;
	return(0);
}

/*========================================================================
 * Utility routines.
 *========================================================================*/

/*
 * Move a path "forward" or "!forward" one block at the current level.
 *
 * This routine will adjust a "path" to point to the next block
 * "forward" (higher hashvalues) or "!forward" (lower hashvals) in the
 * Btree, including updating pointers to the intermediate nodes between
 * the new bottom and the root.
 */
int							/* error */
xfs_da_path_shift(xfs_da_state_t *state, xfs_da_state_path_t *path,
				 int forward, int release, int *result)
{
	xfs_da_state_blk_t *blk;
	xfs_da_blkinfo_t *info;
	xfs_da_intnode_t *node;
	xfs_da_args_t *args;
	xfs_dablk_t blkno=0;
	int level, error;

	trace_xfs_da_path_shift(state->args);

	/*
	 * Roll up the Btree looking for the first block where our
	 * current index is not at the edge of the block.  Note that
	 * we skip the bottom layer because we want the sibling block.
	 */
	args = state->args;
	ASSERT(args != NULL);
	ASSERT(path != NULL);
	ASSERT((path->active > 0) && (path->active < XFS_DA_NODE_MAXDEPTH));
	level = (path->active-1) - 1;	/* skip bottom layer in path */
	for (blk = &path->blk[level]; level >= 0; blk--, level--) {
		ASSERT(blk->bp != NULL);
		node = blk->bp->b_addr;
		ASSERT(node->hdr.info.magic == cpu_to_be16(XFS_DA_NODE_MAGIC));
		if (forward && (blk->index < be16_to_cpu(node->hdr.count)-1)) {
			blk->index++;
			blkno = be32_to_cpu(node->btree[blk->index].before);
			break;
		} else if (!forward && (blk->index > 0)) {
			blk->index--;
			blkno = be32_to_cpu(node->btree[blk->index].before);
			break;
		}
	}
	if (level < 0) {
		*result = XFS_ERROR(ENOENT);	/* we're out of our tree */
		ASSERT(args->op_flags & XFS_DA_OP_OKNOENT);
		return(0);
	}

	/*
	 * Roll down the edge of the subtree until we reach the
	 * same depth we were at originally.
	 */
	for (blk++, level++; level < path->active; blk++, level++) {
		/*
		 * Release the old block.
		 * (if it's dirty, trans won't actually let go)
		 */
		if (release)
			xfs_trans_brelse(args->trans, blk->bp);

		/*
		 * Read the next child block.
		 */
		blk->blkno = blkno;
		error = xfs_da_node_read(args->trans, args->dp, blkno, -1,
					&blk->bp, args->whichfork);
		if (error)
			return(error);
		ASSERT(blk->bp != NULL);
		info = blk->bp->b_addr;
		ASSERT(info->magic == cpu_to_be16(XFS_DA_NODE_MAGIC) ||
		       info->magic == cpu_to_be16(XFS_DIR2_LEAFN_MAGIC) ||
		       info->magic == cpu_to_be16(XFS_ATTR_LEAF_MAGIC));
		blk->magic = be16_to_cpu(info->magic);
		if (blk->magic == XFS_DA_NODE_MAGIC) {
			node = (xfs_da_intnode_t *)info;
			blk->hashval = be32_to_cpu(node->btree[be16_to_cpu(node->hdr.count)-1].hashval);
			if (forward)
				blk->index = 0;
			else
				blk->index = be16_to_cpu(node->hdr.count)-1;
			blkno = be32_to_cpu(node->btree[blk->index].before);
		} else {
			ASSERT(level == path->active-1);
			blk->index = 0;
			switch(blk->magic) {
			case XFS_ATTR_LEAF_MAGIC:
				blk->hashval = xfs_attr_leaf_lasthash(blk->bp,
								      NULL);
				break;
			case XFS_DIR2_LEAFN_MAGIC:
				blk->hashval = xfs_dir2_leafn_lasthash(blk->bp,
								       NULL);
				break;
			default:
				ASSERT(blk->magic == XFS_ATTR_LEAF_MAGIC ||
				       blk->magic == XFS_DIR2_LEAFN_MAGIC);
				break;
			}
		}
	}
	*result = 0;
	return(0);
}


/*========================================================================
 * Utility routines.
 *========================================================================*/

/*
 * Implement a simple hash on a character string.
 * Rotate the hash value by 7 bits, then XOR each character in.
 * This is implemented with some source-level loop unrolling.
 */
xfs_dahash_t
xfs_da_hashname(const __uint8_t *name, int namelen)
{
	xfs_dahash_t hash;

	/*
	 * Do four characters at a time as long as we can.
	 */
	for (hash = 0; namelen >= 4; namelen -= 4, name += 4)
		hash = (name[0] << 21) ^ (name[1] << 14) ^ (name[2] << 7) ^
		       (name[3] << 0) ^ rol32(hash, 7 * 4);

	/*
	 * Now do the rest of the characters.
	 */
	switch (namelen) {
	case 3:
		return (name[0] << 14) ^ (name[1] << 7) ^ (name[2] << 0) ^
		       rol32(hash, 7 * 3);
	case 2:
		return (name[0] << 7) ^ (name[1] << 0) ^ rol32(hash, 7 * 2);
	case 1:
		return (name[0] << 0) ^ rol32(hash, 7 * 1);
	default: /* case 0: */
		return hash;
	}
}

enum xfs_dacmp
xfs_da_compname(
	struct xfs_da_args *args,
	const unsigned char *name,
	int		len)
{
	return (args->namelen == len && memcmp(args->name, name, len) == 0) ?
					XFS_CMP_EXACT : XFS_CMP_DIFFERENT;
}

static xfs_dahash_t
xfs_default_hashname(
	struct xfs_name	*name)
{
	return xfs_da_hashname(name->name, name->len);
}

const struct xfs_nameops xfs_default_nameops = {
	.hashname	= xfs_default_hashname,
	.compname	= xfs_da_compname
};

/*
 * See if the mapping(s) for this btree block are valid, i.e.
 * don't contain holes, are logically contiguous, and cover the whole range.
 */
STATIC int
xfs_da_map_covers_blocks(
	int		nmap,
	xfs_bmbt_irec_t	*mapp,
	xfs_dablk_t	bno,
	int		count)
{
	int		i;
	xfs_fileoff_t	off;

	for (i = 0, off = bno; i < nmap; i++) {
		if (mapp[i].br_startblock == HOLESTARTBLOCK ||
		    mapp[i].br_startblock == DELAYSTARTBLOCK) {
			return 0;
		}
		if (off != mapp[i].br_startoff) {
			return 0;
		}
		off += mapp[i].br_blockcount;
	}
	return off == bno + count;
}

/*
 * Convert a struct xfs_bmbt_irec to a struct xfs_buf_map.
 *
 * For the single map case, it is assumed that the caller has provided a pointer
 * to a valid xfs_buf_map.  For the multiple map case, this function will
 * allocate the xfs_buf_map to hold all the maps and replace the caller's single
 * map pointer with the allocated map.
 */
static int
xfs_buf_map_from_irec(
	struct xfs_mount	*mp,
	struct xfs_buf_map	**mapp,
	unsigned int		*nmaps,
	struct xfs_bmbt_irec	*irecs,
	unsigned int		nirecs)
{
	struct xfs_buf_map	*map;
	int			i;

	ASSERT(*nmaps == 1);
	ASSERT(nirecs >= 1);

	if (nirecs > 1) {
		map = kmem_zalloc(nirecs * sizeof(struct xfs_buf_map), KM_SLEEP);
		if (!map)
			return ENOMEM;
		*mapp = map;
	}

	*nmaps = nirecs;
	map = *mapp;
	for (i = 0; i < *nmaps; i++) {
		ASSERT(irecs[i].br_startblock != DELAYSTARTBLOCK &&
		       irecs[i].br_startblock != HOLESTARTBLOCK);
		map[i].bm_bn = XFS_FSB_TO_DADDR(mp, irecs[i].br_startblock);
		map[i].bm_len = XFS_FSB_TO_BB(mp, irecs[i].br_blockcount);
	}
	return 0;
}

/*
 * Map the block we are given ready for reading. There are three possible return
 * values:
 *	-1 - will be returned if we land in a hole and mappedbno == -2 so the
 *	     caller knows not to execute a subsequent read.
 *	 0 - if we mapped the block successfully
 *	>0 - positive error number if there was an error.
 */
static int
xfs_dabuf_map(
	struct xfs_trans	*trans,
	struct xfs_inode	*dp,
	xfs_dablk_t		bno,
	xfs_daddr_t		mappedbno,
	int			whichfork,
	struct xfs_buf_map	**map,
	int			*nmaps)
{
	struct xfs_mount	*mp = dp->i_mount;
	int			nfsb;
	int			error = 0;
	struct xfs_bmbt_irec	irec;
	struct xfs_bmbt_irec	*irecs = &irec;
	int			nirecs;

	ASSERT(map && *map);
	ASSERT(*nmaps == 1);

	nfsb = (whichfork == XFS_DATA_FORK) ? mp->m_dirblkfsbs : 1;

	/*
	 * Caller doesn't have a mapping.  -2 means don't complain
	 * if we land in a hole.
	 */
	if (mappedbno == -1 || mappedbno == -2) {
		/*
		 * Optimize the one-block case.
		 */
		if (nfsb != 1)
			irecs = kmem_zalloc(sizeof(irec) * nfsb, KM_SLEEP);

		nirecs = nfsb;
		error = xfs_bmapi_read(dp, (xfs_fileoff_t)bno, nfsb, irecs,
				       &nirecs, xfs_bmapi_aflag(whichfork));
		if (error)
			goto out;
	} else {
		irecs->br_startblock = XFS_DADDR_TO_FSB(mp, mappedbno);
		irecs->br_startoff = (xfs_fileoff_t)bno;
		irecs->br_blockcount = nfsb;
		irecs->br_state = 0;
		nirecs = 1;
	}

	if (!xfs_da_map_covers_blocks(nirecs, irecs, bno, nfsb)) {
		error = mappedbno == -2 ? -1 : XFS_ERROR(EFSCORRUPTED);
		if (unlikely(error == EFSCORRUPTED)) {
			if (xfs_error_level >= XFS_ERRLEVEL_LOW) {
				int i;
				xfs_alert(mp, "%s: bno %lld dir: inode %lld",
					__func__, (long long)bno,
					(long long)dp->i_ino);
				for (i = 0; i < *nmaps; i++) {
					xfs_alert(mp,
"[%02d] br_startoff %lld br_startblock %lld br_blockcount %lld br_state %d",
						i,
						(long long)irecs[i].br_startoff,
						(long long)irecs[i].br_startblock,
						(long long)irecs[i].br_blockcount,
						irecs[i].br_state);
				}
			}
			XFS_ERROR_REPORT("xfs_da_do_buf(1)",
					 XFS_ERRLEVEL_LOW, mp);
		}
		goto out;
	}
	error = xfs_buf_map_from_irec(mp, map, nmaps, irecs, nirecs);
out:
	if (irecs != &irec)
		kmem_free(irecs);
	return error;
}

/*
 * Get a buffer for the dir/attr block.
 */
int
xfs_da_get_buf(
	struct xfs_trans	*trans,
	struct xfs_inode	*dp,
	xfs_dablk_t		bno,
	xfs_daddr_t		mappedbno,
	struct xfs_buf		**bpp,
	int			whichfork)
{
	struct xfs_buf		*bp;
	struct xfs_buf_map	map;
	struct xfs_buf_map	*mapp;
	int			nmap;
	int			error;

	*bpp = NULL;
	mapp = &map;
	nmap = 1;
	error = xfs_dabuf_map(trans, dp, bno, mappedbno, whichfork,
				&mapp, &nmap);
	if (error) {
		/* mapping a hole is not an error, but we don't continue */
		if (error == -1)
			error = 0;
		goto out_free;
	}

	bp = xfs_trans_get_buf_map(trans, dp->i_mount->m_ddev_targp,
				    mapp, nmap, 0);
	error = bp ? bp->b_error : XFS_ERROR(EIO);
	if (error) {
		xfs_trans_brelse(trans, bp);
		goto out_free;
	}

	*bpp = bp;

out_free:
	if (mapp != &map)
		kmem_free(mapp);

	return error;
}

/*
 * Get a buffer for the dir/attr block, fill in the contents.
 */
int
xfs_da_read_buf(
	struct xfs_trans	*trans,
	struct xfs_inode	*dp,
	xfs_dablk_t		bno,
	xfs_daddr_t		mappedbno,
	struct xfs_buf		**bpp,
	int			whichfork,
	const struct xfs_buf_ops *ops)
{
	struct xfs_buf		*bp;
	struct xfs_buf_map	map;
	struct xfs_buf_map	*mapp;
	int			nmap;
	int			error;

	*bpp = NULL;
	mapp = &map;
	nmap = 1;
	error = xfs_dabuf_map(trans, dp, bno, mappedbno, whichfork,
				&mapp, &nmap);
	if (error) {
		/* mapping a hole is not an error, but we don't continue */
		if (error == -1)
			error = 0;
		goto out_free;
	}

	error = xfs_trans_read_buf_map(dp->i_mount, trans,
					dp->i_mount->m_ddev_targp,
					mapp, nmap, 0, &bp, ops);
	if (error)
		goto out_free;

	if (whichfork == XFS_ATTR_FORK)
		xfs_buf_set_ref(bp, XFS_ATTR_BTREE_REF);
	else
		xfs_buf_set_ref(bp, XFS_DIR_BTREE_REF);

	/*
	 * This verification code will be moved to a CRC verification callback
	 * function so just leave it here unchanged until then.
	 */
	{
		xfs_dir2_data_hdr_t	*hdr = bp->b_addr;
		xfs_dir2_free_t		*free = bp->b_addr;
		xfs_da_blkinfo_t	*info = bp->b_addr;
		uint			magic, magic1;
		struct xfs_mount	*mp = dp->i_mount;

		magic = be16_to_cpu(info->magic);
		magic1 = be32_to_cpu(hdr->magic);
		if (unlikely(
		    XFS_TEST_ERROR((magic != XFS_DA_NODE_MAGIC) &&
				   (magic != XFS_ATTR_LEAF_MAGIC) &&
				   (magic != XFS_DIR2_LEAF1_MAGIC) &&
				   (magic != XFS_DIR2_LEAFN_MAGIC) &&
				   (magic1 != XFS_DIR2_BLOCK_MAGIC) &&
				   (magic1 != XFS_DIR2_DATA_MAGIC) &&
				   (free->hdr.magic != cpu_to_be32(XFS_DIR2_FREE_MAGIC)),
				mp, XFS_ERRTAG_DA_READ_BUF,
				XFS_RANDOM_DA_READ_BUF))) {
			trace_xfs_da_btree_corrupt(bp, _RET_IP_);
			XFS_CORRUPTION_ERROR("xfs_da_do_buf(2)",
					     XFS_ERRLEVEL_LOW, mp, info);
			error = XFS_ERROR(EFSCORRUPTED);
			xfs_trans_brelse(trans, bp);
			goto out_free;
		}
	}
	*bpp = bp;
out_free:
	if (mapp != &map)
		kmem_free(mapp);

	return error;
}

/*
 * Readahead the dir/attr block.
 */
xfs_daddr_t
xfs_da_reada_buf(
	struct xfs_trans	*trans,
	struct xfs_inode	*dp,
	xfs_dablk_t		bno,
	xfs_daddr_t		mappedbno,
	int			whichfork,
	const struct xfs_buf_ops *ops)
{
	struct xfs_buf_map	map;
	struct xfs_buf_map	*mapp;
	int			nmap;
	int			error;

	mapp = &map;
	nmap = 1;
	error = xfs_dabuf_map(trans, dp, bno, mappedbno, whichfork,
				&mapp, &nmap);
	if (error) {
		/* mapping a hole is not an error, but we don't continue */
		if (error == -1)
			error = 0;
		goto out_free;
	}

	mappedbno = mapp[0].bm_bn;
	xfs_buf_readahead_map(dp->i_mount->m_ddev_targp, mapp, nmap, ops);

out_free:
	if (mapp != &map)
		kmem_free(mapp);

	if (error)
		return -1;
	return mappedbno;
}

kmem_zone_t *xfs_da_state_zone;	/* anchor for state struct zone */

/*
 * Allocate a dir-state structure.
 * We don't put them on the stack since they're large.
 */
xfs_da_state_t *
xfs_da_state_alloc(void)
{
	return kmem_zone_zalloc(xfs_da_state_zone, KM_NOFS);
}

/*
 * Kill the altpath contents of a da-state structure.
 */
STATIC void
xfs_da_state_kill_altpath(xfs_da_state_t *state)
{
	int	i;

	for (i = 0; i < state->altpath.active; i++)
		state->altpath.blk[i].bp = NULL;
	state->altpath.active = 0;
}

/*
 * Free a da-state structure.
 */
void
xfs_da_state_free(xfs_da_state_t *state)
{
	xfs_da_state_kill_altpath(state);
#ifdef DEBUG
	memset((char *)state, 0, sizeof(*state));
#endif /* DEBUG */
	kmem_zone_free(xfs_da_state_zone, state);
}
