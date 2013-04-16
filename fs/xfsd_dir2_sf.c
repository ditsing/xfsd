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
#include "xfs/xfs_inode_item.h"
#include "xfs/xfs_error.h"
#include "xfs/xfs_dir2.h"
#include "xfs/xfs_dir2_format.h"
#include "xfs/xfs_dir2_priv.h"

#include "xfsd_trace.h"


/*
 * Prototypes for internal functions.
 */
static void xfs_dir2_sf_addname_easy(xfs_da_args_t *args,
				     xfs_dir2_sf_entry_t *sfep,
				     xfs_dir2_data_aoff_t offset,
				     int new_isize);
static void xfs_dir2_sf_addname_hard(xfs_da_args_t *args, int objchange,
				     int new_isize);
static int xfs_dir2_sf_addname_pick(xfs_da_args_t *args, int objchange,
				    xfs_dir2_sf_entry_t **sfepp,
				    xfs_dir2_data_aoff_t *offsetp);
#ifdef DEBUG
static void xfs_dir2_sf_check(xfs_da_args_t *args);
#else
#define	xfs_dir2_sf_check(args)
#endif /* DEBUG */
#if XFS_BIG_INUMS
static void xfs_dir2_sf_toino4(xfs_da_args_t *args);
static void xfs_dir2_sf_toino8(xfs_da_args_t *args);
#endif /* XFS_BIG_INUMS */

/*
 * Inode numbers in short-form directories can come in two versions,
 * either 4 bytes or 8 bytes wide.  These helpers deal with the
 * two forms transparently by looking at the headers i8count field.
 *
 * For 64-bit inode number the most significant byte must be zero.
 */
static xfs_ino_t
xfs_dir2_sf_get_ino(
	struct xfs_dir2_sf_hdr	*hdr,
	xfs_dir2_inou_t		*from)
{
	if (hdr->i8count)
		return get_unaligned_be64(&from->i8.i) & 0x00ffffffffffffffULL;
	else
		return get_unaligned_be32(&from->i4.i);
}

static void
xfs_dir2_sf_put_ino(
	struct xfs_dir2_sf_hdr	*hdr,
	xfs_dir2_inou_t		*to,
	xfs_ino_t		ino)
{
	ASSERT((ino & 0xff00000000000000ULL) == 0);

	if (hdr->i8count)
		put_unaligned_be64(ino, &to->i8.i);
	else
		put_unaligned_be32(ino, &to->i4.i);
}

xfs_ino_t
xfs_dir2_sf_get_parent_ino(
	struct xfs_dir2_sf_hdr	*hdr)
{
	return xfs_dir2_sf_get_ino(hdr, &hdr->parent);
}

static void
xfs_dir2_sf_put_parent_ino(
	struct xfs_dir2_sf_hdr	*hdr,
	xfs_ino_t		ino)
{
	xfs_dir2_sf_put_ino(hdr, &hdr->parent, ino);
}

/*
 * In short-form directory entries the inode numbers are stored at variable
 * offset behind the entry name.  The inode numbers may only be accessed
 * through the helpers below.
 */
static xfs_dir2_inou_t *
xfs_dir2_sfe_inop(
	struct xfs_dir2_sf_entry *sfep)
{
	return (xfs_dir2_inou_t *)&sfep->name[sfep->namelen];
}

xfs_ino_t
xfs_dir2_sfe_get_ino(
	struct xfs_dir2_sf_hdr	*hdr,
	struct xfs_dir2_sf_entry *sfep)
{
	return xfs_dir2_sf_get_ino(hdr, xfs_dir2_sfe_inop(sfep));
}

static void
xfs_dir2_sfe_put_ino(
	struct xfs_dir2_sf_hdr	*hdr,
	struct xfs_dir2_sf_entry *sfep,
	xfs_ino_t		ino)
{
	xfs_dir2_sf_put_ino(hdr, xfs_dir2_sfe_inop(sfep), ino);
}

/*
 * Given a block directory (dp/block), calculate its size as a shortform (sf)
 * directory and a header for the sf directory, if it will fit it the
 * space currently present in the inode.  If it won't fit, the output
 * size is too big (but not accurate).
 */
int						/* size for sf form */
xfs_dir2_block_sfsize(
	xfs_inode_t		*dp,		/* incore inode pointer */
	xfs_dir2_data_hdr_t	*hdr,		/* block directory data */
	xfs_dir2_sf_hdr_t	*sfhp)		/* output: header for sf form */
{
	xfs_dir2_dataptr_t	addr;		/* data entry address */
	xfs_dir2_leaf_entry_t	*blp;		/* leaf area of the block */
	xfs_dir2_block_tail_t	*btp;		/* tail area of the block */
	int			count;		/* shortform entry count */
	xfs_dir2_data_entry_t	*dep;		/* data entry in the block */
	int			i;		/* block entry index */
	int			i8count;	/* count of big-inode entries */
	int			isdot;		/* entry is "." */
	int			isdotdot;	/* entry is ".." */
	xfs_mount_t		*mp;		/* mount structure pointer */
	int			namelen;	/* total name bytes */
	xfs_ino_t		parent = 0;	/* parent inode number */
	int			size=0;		/* total computed size */

	mp = dp->i_mount;

	count = i8count = namelen = 0;
	btp = xfs_dir2_block_tail_p(mp, hdr);
	blp = xfs_dir2_block_leaf_p(btp);

	/*
	 * Iterate over the block's data entries by using the leaf pointers.
	 */
	for (i = 0; i < be32_to_cpu(btp->count); i++) {
		if ((addr = be32_to_cpu(blp[i].address)) == XFS_DIR2_NULL_DATAPTR)
			continue;
		/*
		 * Calculate the pointer to the entry at hand.
		 */
		dep = (xfs_dir2_data_entry_t *)
		      ((char *)hdr + xfs_dir2_dataptr_to_off(mp, addr));
		/*
		 * Detect . and .., so we can special-case them.
		 * . is not included in sf directories.
		 * .. is included by just the parent inode number.
		 */
		isdot = dep->namelen == 1 && dep->name[0] == '.';
		isdotdot =
			dep->namelen == 2 &&
			dep->name[0] == '.' && dep->name[1] == '.';
#if XFS_BIG_INUMS
		if (!isdot)
			i8count += be64_to_cpu(dep->inumber) > XFS_DIR2_MAX_SHORT_INUM;
#endif
		if (!isdot && !isdotdot) {
			count++;
			namelen += dep->namelen;
		} else if (isdotdot)
			parent = be64_to_cpu(dep->inumber);
		/*
		 * Calculate the new size, see if we should give up yet.
		 */
		size = xfs_dir2_sf_hdr_size(i8count) +		/* header */
		       count +					/* namelen */
		       count * (uint)sizeof(xfs_dir2_sf_off_t) + /* offset */
		       namelen +				/* name */
		       (i8count ?				/* inumber */
				(uint)sizeof(xfs_dir2_ino8_t) * count :
				(uint)sizeof(xfs_dir2_ino4_t) * count);
		if (size > XFS_IFORK_DSIZE(dp))
			return size;		/* size value is a failure */
	}
	/*
	 * Create the output header, if it worked.
	 */
	sfhp->count = count;
	sfhp->i8count = i8count;
	xfs_dir2_sf_put_parent_ino(sfhp, parent);
	return size;
}

/*
 * Add the new entry the "easy" way.
 * This is copying the old directory and adding the new entry at the end.
 * Since it's sorted by "offset" we need room after the last offset
 * that's already there, and then room to convert to a block directory.
 * This is already checked by the pick routine.
 */
static void
xfs_dir2_sf_addname_easy(
	xfs_da_args_t		*args,		/* operation arguments */
	xfs_dir2_sf_entry_t	*sfep,		/* pointer to new entry */
	xfs_dir2_data_aoff_t	offset,		/* offset to use for new ent */
	int			new_isize)	/* new directory size */
{
	int			byteoff;	/* byte offset in sf dir */
	xfs_inode_t		*dp;		/* incore directory inode */
	xfs_dir2_sf_hdr_t	*sfp;		/* shortform structure */

	dp = args->dp;

	sfp = (xfs_dir2_sf_hdr_t *)dp->i_df.if_u1.if_data;
	byteoff = (int)((char *)sfep - (char *)sfp);
	/*
	 * Grow the in-inode space.
	 */
	xfs_idata_realloc(dp, xfs_dir2_sf_entsize(sfp, args->namelen),
		XFS_DATA_FORK);
	/*
	 * Need to set up again due to realloc of the inode data.
	 */
	sfp = (xfs_dir2_sf_hdr_t *)dp->i_df.if_u1.if_data;
	sfep = (xfs_dir2_sf_entry_t *)((char *)sfp + byteoff);
	/*
	 * Fill in the new entry.
	 */
	sfep->namelen = args->namelen;
	xfs_dir2_sf_put_offset(sfep, offset);
	memcpy(sfep->name, args->name, sfep->namelen);
	xfs_dir2_sfe_put_ino(sfp, sfep, args->inumber);
	/*
	 * Update the header and inode.
	 */
	sfp->count++;
#if XFS_BIG_INUMS
	if (args->inumber > XFS_DIR2_MAX_SHORT_INUM)
		sfp->i8count++;
#endif
	dp->i_d.di_size = new_isize;
	xfs_dir2_sf_check(args);
}

/*
 * Add the new entry the "hard" way.
 * The caller has already converted to 8 byte inode numbers if necessary,
 * in which case we need to leave the i8count at 1.
 * Find a hole that the new entry will fit into, and copy
 * the first part of the entries, the new entry, and the last part of
 * the entries.
 */
/* ARGSUSED */
static void
xfs_dir2_sf_addname_hard(
	xfs_da_args_t		*args,		/* operation arguments */
	int			objchange,	/* changing inode number size */
	int			new_isize)	/* new directory size */
{
	int			add_datasize;	/* data size need for new ent */
	char			*buf;		/* buffer for old */
	xfs_inode_t		*dp;		/* incore directory inode */
	int			eof;		/* reached end of old dir */
	int			nbytes;		/* temp for byte copies */
	xfs_dir2_data_aoff_t	new_offset;	/* next offset value */
	xfs_dir2_data_aoff_t	offset;		/* current offset value */
	int			old_isize;	/* previous di_size */
	xfs_dir2_sf_entry_t	*oldsfep;	/* entry in original dir */
	xfs_dir2_sf_hdr_t	*oldsfp;	/* original shortform dir */
	xfs_dir2_sf_entry_t	*sfep;		/* entry in new dir */
	xfs_dir2_sf_hdr_t	*sfp;		/* new shortform dir */

	/*
	 * Copy the old directory to the stack buffer.
	 */
	dp = args->dp;

	sfp = (xfs_dir2_sf_hdr_t *)dp->i_df.if_u1.if_data;
	old_isize = (int)dp->i_d.di_size;
	buf = kmem_alloc(old_isize, KM_SLEEP);
	oldsfp = (xfs_dir2_sf_hdr_t *)buf;
	memcpy(oldsfp, sfp, old_isize);
	/*
	 * Loop over the old directory finding the place we're going
	 * to insert the new entry.
	 * If it's going to end up at the end then oldsfep will point there.
	 */
	for (offset = XFS_DIR2_DATA_FIRST_OFFSET,
	      oldsfep = xfs_dir2_sf_firstentry(oldsfp),
	      add_datasize = xfs_dir2_data_entsize(args->namelen),
	      eof = (char *)oldsfep == &buf[old_isize];
	     !eof;
	     offset = new_offset + xfs_dir2_data_entsize(oldsfep->namelen),
	      oldsfep = xfs_dir2_sf_nextentry(oldsfp, oldsfep),
	      eof = (char *)oldsfep == &buf[old_isize]) {
		new_offset = xfs_dir2_sf_get_offset(oldsfep);
		if (offset + add_datasize <= new_offset)
			break;
	}
	/*
	 * Get rid of the old directory, then allocate space for
	 * the new one.  We do this so xfs_idata_realloc won't copy
	 * the data.
	 */
	xfs_idata_realloc(dp, -old_isize, XFS_DATA_FORK);
	xfs_idata_realloc(dp, new_isize, XFS_DATA_FORK);
	/*
	 * Reset the pointer since the buffer was reallocated.
	 */
	sfp = (xfs_dir2_sf_hdr_t *)dp->i_df.if_u1.if_data;
	/*
	 * Copy the first part of the directory, including the header.
	 */
	nbytes = (int)((char *)oldsfep - (char *)oldsfp);
	memcpy(sfp, oldsfp, nbytes);
	sfep = (xfs_dir2_sf_entry_t *)((char *)sfp + nbytes);
	/*
	 * Fill in the new entry, and update the header counts.
	 */
	sfep->namelen = args->namelen;
	xfs_dir2_sf_put_offset(sfep, offset);
	memcpy(sfep->name, args->name, sfep->namelen);
	xfs_dir2_sfe_put_ino(sfp, sfep, args->inumber);
	sfp->count++;
#if XFS_BIG_INUMS
	if (args->inumber > XFS_DIR2_MAX_SHORT_INUM && !objchange)
		sfp->i8count++;
#endif
	/*
	 * If there's more left to copy, do that.
	 */
	if (!eof) {
		sfep = xfs_dir2_sf_nextentry(sfp, sfep);
		memcpy(sfep, oldsfep, old_isize - nbytes);
	}
	kmem_free(buf);
	dp->i_d.di_size = new_isize;
	xfs_dir2_sf_check(args);
}

/*
 * Decide if the new entry will fit at all.
 * If it will fit, pick between adding the new entry to the end (easy)
 * or somewhere else (hard).
 * Return 0 (won't fit), 1 (easy), 2 (hard).
 */
/*ARGSUSED*/
static int					/* pick result */
xfs_dir2_sf_addname_pick(
	xfs_da_args_t		*args,		/* operation arguments */
	int			objchange,	/* inode # size changes */
	xfs_dir2_sf_entry_t	**sfepp,	/* out(1): new entry ptr */
	xfs_dir2_data_aoff_t	*offsetp)	/* out(1): new offset */
{
	xfs_inode_t		*dp;		/* incore directory inode */
	int			holefit;	/* found hole it will fit in */
	int			i;		/* entry number */
	xfs_mount_t		*mp;		/* filesystem mount point */
	xfs_dir2_data_aoff_t	offset;		/* data block offset */
	xfs_dir2_sf_entry_t	*sfep;		/* shortform entry */
	xfs_dir2_sf_hdr_t	*sfp;		/* shortform structure */
	int			size;		/* entry's data size */
	int			used;		/* data bytes used */

	dp = args->dp;
	mp = dp->i_mount;

	sfp = (xfs_dir2_sf_hdr_t *)dp->i_df.if_u1.if_data;
	size = xfs_dir2_data_entsize(args->namelen);
	offset = XFS_DIR2_DATA_FIRST_OFFSET;
	sfep = xfs_dir2_sf_firstentry(sfp);
	holefit = 0;
	/*
	 * Loop over sf entries.
	 * Keep track of data offset and whether we've seen a place
	 * to insert the new entry.
	 */
	for (i = 0; i < sfp->count; i++) {
		if (!holefit)
			holefit = offset + size <= xfs_dir2_sf_get_offset(sfep);
		offset = xfs_dir2_sf_get_offset(sfep) +
			 xfs_dir2_data_entsize(sfep->namelen);
		sfep = xfs_dir2_sf_nextentry(sfp, sfep);
	}
	/*
	 * Calculate data bytes used excluding the new entry, if this
	 * was a data block (block form directory).
	 */
	used = offset +
	       (sfp->count + 3) * (uint)sizeof(xfs_dir2_leaf_entry_t) +
	       (uint)sizeof(xfs_dir2_block_tail_t);
	/*
	 * If it won't fit in a block form then we can't insert it,
	 * we'll go back, convert to block, then try the insert and convert
	 * to leaf.
	 */
	if (used + (holefit ? 0 : size) > mp->m_dirblksize)
		return 0;
	/*
	 * If changing the inode number size, do it the hard way.
	 */
#if XFS_BIG_INUMS
	if (objchange) {
		return 2;
	}
#else
	ASSERT(objchange == 0);
#endif
	/*
	 * If it won't fit at the end then do it the hard way (use the hole).
	 */
	if (used + size > mp->m_dirblksize)
		return 2;
	/*
	 * Do it the easy way.
	 */
	*sfepp = sfep;
	*offsetp = offset;
	return 1;
}

#ifdef DEBUG
/*
 * Check consistency of shortform directory, assert if bad.
 */
static void
xfs_dir2_sf_check(
	xfs_da_args_t		*args)		/* operation arguments */
{
	xfs_inode_t		*dp;		/* incore directory inode */
	int			i;		/* entry number */
	int			i8count;	/* number of big inode#s */
	xfs_ino_t		ino;		/* entry inode number */
	int			offset;		/* data offset */
	xfs_dir2_sf_entry_t	*sfep;		/* shortform dir entry */
	xfs_dir2_sf_hdr_t	*sfp;		/* shortform structure */

	dp = args->dp;

	sfp = (xfs_dir2_sf_hdr_t *)dp->i_df.if_u1.if_data;
	offset = XFS_DIR2_DATA_FIRST_OFFSET;
	ino = xfs_dir2_sf_get_parent_ino(sfp);
	i8count = ino > XFS_DIR2_MAX_SHORT_INUM;

	for (i = 0, sfep = xfs_dir2_sf_firstentry(sfp);
	     i < sfp->count;
	     i++, sfep = xfs_dir2_sf_nextentry(sfp, sfep)) {
		ASSERT(xfs_dir2_sf_get_offset(sfep) >= offset);
		ino = xfs_dir2_sfe_get_ino(sfp, sfep);
		i8count += ino > XFS_DIR2_MAX_SHORT_INUM;
		offset =
			xfs_dir2_sf_get_offset(sfep) +
			xfs_dir2_data_entsize(sfep->namelen);
	}
	ASSERT(i8count == sfp->i8count);
	ASSERT(XFS_BIG_INUMS || i8count == 0);
	ASSERT((char *)sfep - (char *)sfp == dp->i_d.di_size);
	ASSERT(offset +
	       (sfp->count + 2) * (uint)sizeof(xfs_dir2_leaf_entry_t) +
	       (uint)sizeof(xfs_dir2_block_tail_t) <=
	       dp->i_mount->m_dirblksize);
}
#endif	/* DEBUG */

int						/* error */
xfs_dir2_sf_getdents(
	xfs_inode_t		*dp,		/* incore directory inode */
	void			*dirent,
	xfs_off_t		*offset,
	filldir_t		filldir)
{
	int			i;		/* shortform entry number */
	xfs_mount_t		*mp;		/* filesystem mount point */
	xfs_dir2_dataptr_t	off;		/* current entry's offset */
	xfs_dir2_sf_entry_t	*sfep;		/* shortform directory entry */
	xfs_dir2_sf_hdr_t	*sfp;		/* shortform structure */
	xfs_dir2_dataptr_t	dot_offset;
	xfs_dir2_dataptr_t	dotdot_offset;
	xfs_ino_t		ino;

	mp = dp->i_mount;

	ASSERT(dp->i_df.if_flags & XFS_IFINLINE);
	/*
	 * Give up if the directory is way too short.
	 */
	if (dp->i_d.di_size < offsetof(xfs_dir2_sf_hdr_t, parent)) {
		ASSERT(XFS_FORCED_SHUTDOWN(mp));
		return XFS_ERROR(EIO);
	}

	ASSERT(dp->i_df.if_bytes == dp->i_d.di_size);
	ASSERT(dp->i_df.if_u1.if_data != NULL);

	sfp = (xfs_dir2_sf_hdr_t *)dp->i_df.if_u1.if_data;

	ASSERT(dp->i_d.di_size >= xfs_dir2_sf_hdr_size(sfp->i8count));

	/*
	 * If the block number in the offset is out of range, we're done.
	 */
	if (xfs_dir2_dataptr_to_db(mp, *offset) > mp->m_dirdatablk)
		return 0;

	/*
	 * Precalculate offsets for . and .. as we will always need them.
	 *
	 * XXX(hch): the second argument is sometimes 0 and sometimes
	 * mp->m_dirdatablk.
	 */
	dot_offset = xfs_dir2_db_off_to_dataptr(mp, mp->m_dirdatablk,
					     XFS_DIR2_DATA_DOT_OFFSET);
	dotdot_offset = xfs_dir2_db_off_to_dataptr(mp, mp->m_dirdatablk,
						XFS_DIR2_DATA_DOTDOT_OFFSET);

	/*
	 * Put . entry unless we're starting past it.
	 */
	if (*offset <= dot_offset) {
		if (filldir(dirent, ".", 1, dot_offset & 0x7fffffff, dp->i_ino, DT_DIR)) {
			*offset = dot_offset & 0x7fffffff;
			return 0;
		}
	}

	/*
	 * Put .. entry unless we're starting past it.
	 */
	if (*offset <= dotdot_offset) {
		ino = xfs_dir2_sf_get_parent_ino(sfp);
		if (filldir(dirent, "..", 2, dotdot_offset & 0x7fffffff, ino, DT_DIR)) {
			*offset = dotdot_offset & 0x7fffffff;
			return 0;
		}
	}

	/*
	 * Loop while there are more entries and put'ing works.
	 */
	sfep = xfs_dir2_sf_firstentry(sfp);
	for (i = 0; i < sfp->count; i++) {
		off = xfs_dir2_db_off_to_dataptr(mp, mp->m_dirdatablk,
				xfs_dir2_sf_get_offset(sfep));

		if (*offset > off) {
			sfep = xfs_dir2_sf_nextentry(sfp, sfep);
			continue;
		}

		ino = xfs_dir2_sfe_get_ino(sfp, sfep);
		if (filldir(dirent, (char *)sfep->name, sfep->namelen,
			    off & 0x7fffffff, ino, DT_UNKNOWN)) {
			*offset = off & 0x7fffffff;
			return 0;
		}
		sfep = xfs_dir2_sf_nextentry(sfp, sfep);
	}

	*offset = xfs_dir2_db_off_to_dataptr(mp, mp->m_dirdatablk + 1, 0) &
			0x7fffffff;
	return 0;
}

/*
 * Lookup an entry in a shortform directory.
 * Returns EEXIST if found, ENOENT if not found.
 */
int						/* error */
xfs_dir2_sf_lookup(
	xfs_da_args_t		*args)		/* operation arguments */
{
	xfs_inode_t		*dp;		/* incore directory inode */
	int			i;		/* entry index */
	int			error;
	xfs_dir2_sf_entry_t	*sfep;		/* shortform directory entry */
	xfs_dir2_sf_hdr_t	*sfp;		/* shortform structure */
	enum xfs_dacmp		cmp;		/* comparison result */
	xfs_dir2_sf_entry_t	*ci_sfep;	/* case-insens. entry */

	trace_xfs_dir2_sf_lookup(args);

	xfs_dir2_sf_check(args);
	dp = args->dp;

	ASSERT(dp->i_df.if_flags & XFS_IFINLINE);
	/*
	 * Bail out if the directory is way too short.
	 */
	if (dp->i_d.di_size < offsetof(xfs_dir2_sf_hdr_t, parent)) {
		ASSERT(XFS_FORCED_SHUTDOWN(dp->i_mount));
		return XFS_ERROR(EIO);
	}
	ASSERT(dp->i_df.if_bytes == dp->i_d.di_size);
	ASSERT(dp->i_df.if_u1.if_data != NULL);
	sfp = (xfs_dir2_sf_hdr_t *)dp->i_df.if_u1.if_data;
	ASSERT(dp->i_d.di_size >= xfs_dir2_sf_hdr_size(sfp->i8count));
	/*
	 * Special case for .
	 */
	if (args->namelen == 1 && args->name[0] == '.') {
		args->inumber = dp->i_ino;
		args->cmpresult = XFS_CMP_EXACT;
		return XFS_ERROR(EEXIST);
	}
	/*
	 * Special case for ..
	 */
	if (args->namelen == 2 &&
	    args->name[0] == '.' && args->name[1] == '.') {
		args->inumber = xfs_dir2_sf_get_parent_ino(sfp);
		args->cmpresult = XFS_CMP_EXACT;
		return XFS_ERROR(EEXIST);
	}
	/*
	 * Loop over all the entries trying to match ours.
	 */
	ci_sfep = NULL;
	for (i = 0, sfep = xfs_dir2_sf_firstentry(sfp); i < sfp->count;
				i++, sfep = xfs_dir2_sf_nextentry(sfp, sfep)) {
		/*
		 * Compare name and if it's an exact match, return the inode
		 * number. If it's the first case-insensitive match, store the
		 * inode number and continue looking for an exact match.
		 */
		cmp = dp->i_mount->m_dirnameops->compname(args, sfep->name,
								sfep->namelen);
		if (cmp != XFS_CMP_DIFFERENT && cmp != args->cmpresult) {
			args->cmpresult = cmp;
			args->inumber = xfs_dir2_sfe_get_ino(sfp, sfep);
			if (cmp == XFS_CMP_EXACT)
				return XFS_ERROR(EEXIST);
			ci_sfep = sfep;
		}
	}
	ASSERT(args->op_flags & XFS_DA_OP_OKNOENT);
	/*
	 * Here, we can only be doing a lookup (not a rename or replace).
	 * If a case-insensitive match was not found, return ENOENT.
	 */
	if (!ci_sfep)
		return XFS_ERROR(ENOENT);
	/* otherwise process the CI match as required by the caller */
	error = xfs_dir_cilookup_result(args, ci_sfep->name, ci_sfep->namelen);
	return XFS_ERROR(error);
}
