/*
 * Copyright (c) 2000-2006 Silicon Graphics, Inc.
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
#include "linux/log2.h"

#include "xfs/xfs_fs.h"
#include "xfs/xfs_types.h"
#include "xfs/xfs_log.h"
#include "xfs/xfs_inum.h"
#include "xfs/xfs_trans.h"
#include "xfs/xfs_trans_priv.h"
#include "xfs/xfs_sb.h"
#include "xfs/xfs_ag.h"
#include "xfs/xfs_mount.h"
#include "xfs/xfs_bmap_btree.h"
#include "xfs/xfs_alloc_btree.h"
#include "xfs/xfs_ialloc_btree.h"
#include "xfs/xfs_attr_sf.h"
#include "xfs/xfs_dinode.h"
#include "xfs/xfs_inode.h"
#include "xfs/xfs_buf_item.h"
#include "xfs/xfs_inode_item.h"
#include "xfs/xfs_btree.h"
#include "xfs/xfs_alloc.h"
#include "xfs/xfs_ialloc.h"
#include "xfs/xfs_bmap.h"
#include "xfs/xfs_error.h"
#include "xfs/xfs_utils.h"
#include "xfs/xfs_quota.h"
#include "xfs/xfs_filestream.h"
#include "xfs/xfs_vnodeops.h"

#include "xfsd_trace.h"
#include "xfs/xfs_icache.h"

kmem_zone_t *xfs_ifork_zone;
kmem_zone_t *xfs_inode_zone;

/*
 * Used in xfs_itruncate_extents().  This is the maximum number of extents
 * freed from a file in a single transaction.
 */
#define	XFS_ITRUNC_MAX_EXTENTS	2

STATIC int xfs_iformat_local(xfs_inode_t *, xfs_dinode_t *, int, int);
STATIC int xfs_iformat_extents(xfs_inode_t *, xfs_dinode_t *, int);
STATIC int xfs_iformat_btree(xfs_inode_t *, xfs_dinode_t *, int);

/*
 * helper function to extract extent size hint from inode
 */
xfs_extlen_t
xfs_get_extsz_hint(
	struct xfs_inode	*ip)
{
	if ((ip->i_d.di_flags & XFS_DIFLAG_EXTSIZE) && ip->i_d.di_extsize)
		return ip->i_d.di_extsize;
	if (XFS_IS_REALTIME_INODE(ip))
		return ip->i_mount->m_sb.sb_rextsize;
	return 0;
}

/*
 * This is a wrapper routine around the xfs_ilock() routine used to centralize
 * some grungy code.  It is used in places that wish to lock the inode solely
 * for reading the extents.  The reason these places can't just call
 * xfs_ilock(SHARED) is that the inode lock also guards to bringing in of the
 * extents from disk for a file in b-tree format.  If the inode is in b-tree
 * format, then we need to lock the inode exclusively until the extents are read
 * in.  Locking it exclusively all the time would limit our parallelism
 * unnecessarily, though.  What we do instead is check to see if the extents
 * have been read in yet, and only lock the inode exclusively if they have not.
 *
 * The function returns a value which should be given to the corresponding
 * xfs_iunlock_map_shared().  This value is the mode in which the lock was
 * actually taken.
 */
uint
xfs_ilock_map_shared(
	xfs_inode_t	*ip)
{
	uint	lock_mode;

	if ((ip->i_d.di_format == XFS_DINODE_FMT_BTREE) &&
	    ((ip->i_df.if_flags & XFS_IFEXTENTS) == 0)) {
		lock_mode = XFS_ILOCK_EXCL;
	} else {
		lock_mode = XFS_ILOCK_SHARED;
	}

	xfs_ilock(ip, lock_mode);

	return lock_mode;
}

/*
 * This is simply the unlock routine to go with xfs_ilock_map_shared().
 * All it does is call xfs_iunlock() with the given lock_mode.
 */
void
xfs_iunlock_map_shared(
	xfs_inode_t	*ip,
	unsigned int	lock_mode)
{
	xfs_iunlock(ip, lock_mode);
}

/*
 * The xfs inode contains 2 locks: a multi-reader lock called the
 * i_iolock and a multi-reader lock called the i_lock.  This routine
 * allows either or both of the locks to be obtained.
 *
 * The 2 locks should always be ordered so that the IO lock is
 * obtained first in order to prevent deadlock.
 *
 * ip -- the inode being locked
 * lock_flags -- this parameter indicates the inode's locks
 *       to be locked.  It can be:
 *		XFS_IOLOCK_SHARED,
 *		XFS_IOLOCK_EXCL,
 *		XFS_ILOCK_SHARED,
 *		XFS_ILOCK_EXCL,
 *		XFS_IOLOCK_SHARED | XFS_ILOCK_SHARED,
 *		XFS_IOLOCK_SHARED | XFS_ILOCK_EXCL,
 *		XFS_IOLOCK_EXCL | XFS_ILOCK_SHARED,
 *		XFS_IOLOCK_EXCL | XFS_ILOCK_EXCL
 */
void
xfs_ilock(
	xfs_inode_t		*ip,
	uint			lock_flags)
{
	trace_xfs_ilock(ip, lock_flags, _RET_IP_);

	/*
	 * You can't set both SHARED and EXCL for the same lock,
	 * and only XFS_IOLOCK_SHARED, XFS_IOLOCK_EXCL, XFS_ILOCK_SHARED,
	 * and XFS_ILOCK_EXCL are valid values to set in lock_flags.
	 */
	ASSERT((lock_flags & (XFS_IOLOCK_SHARED | XFS_IOLOCK_EXCL)) !=
	       (XFS_IOLOCK_SHARED | XFS_IOLOCK_EXCL));
	ASSERT((lock_flags & (XFS_ILOCK_SHARED | XFS_ILOCK_EXCL)) !=
	       (XFS_ILOCK_SHARED | XFS_ILOCK_EXCL));
	ASSERT((lock_flags & ~(XFS_LOCK_MASK | XFS_LOCK_DEP_MASK)) == 0);

	if (lock_flags & XFS_IOLOCK_EXCL)
		mrupdate_nested(&ip->i_iolock, XFS_IOLOCK_DEP(lock_flags));
	else if (lock_flags & XFS_IOLOCK_SHARED)
		mraccess_nested(&ip->i_iolock, XFS_IOLOCK_DEP(lock_flags));

	if (lock_flags & XFS_ILOCK_EXCL)
		mrupdate_nested(&ip->i_lock, XFS_ILOCK_DEP(lock_flags));
	else if (lock_flags & XFS_ILOCK_SHARED)
		mraccess_nested(&ip->i_lock, XFS_ILOCK_DEP(lock_flags));
}

/*
 * This is just like xfs_ilock(), except that the caller
 * is guaranteed not to sleep.  It returns 1 if it gets
 * the requested locks and 0 otherwise.  If the IO lock is
 * obtained but the inode lock cannot be, then the IO lock
 * is dropped before returning.
 *
 * ip -- the inode being locked
 * lock_flags -- this parameter indicates the inode's locks to be
 *       to be locked.  See the comment for xfs_ilock() for a list
 *	 of valid values.
 */
int
xfs_ilock_nowait(
	xfs_inode_t		*ip,
	uint			lock_flags)
{
	trace_xfs_ilock_nowait(ip, lock_flags, _RET_IP_);

	/*
	 * You can't set both SHARED and EXCL for the same lock,
	 * and only XFS_IOLOCK_SHARED, XFS_IOLOCK_EXCL, XFS_ILOCK_SHARED,
	 * and XFS_ILOCK_EXCL are valid values to set in lock_flags.
	 */
	ASSERT((lock_flags & (XFS_IOLOCK_SHARED | XFS_IOLOCK_EXCL)) !=
	       (XFS_IOLOCK_SHARED | XFS_IOLOCK_EXCL));
	ASSERT((lock_flags & (XFS_ILOCK_SHARED | XFS_ILOCK_EXCL)) !=
	       (XFS_ILOCK_SHARED | XFS_ILOCK_EXCL));
	ASSERT((lock_flags & ~(XFS_LOCK_MASK | XFS_LOCK_DEP_MASK)) == 0);

	if (lock_flags & XFS_IOLOCK_EXCL) {
		if (!mrtryupdate(&ip->i_iolock))
			goto out;
	} else if (lock_flags & XFS_IOLOCK_SHARED) {
		if (!mrtryaccess(&ip->i_iolock))
			goto out;
	}
	if (lock_flags & XFS_ILOCK_EXCL) {
		if (!mrtryupdate(&ip->i_lock))
			goto out_undo_iolock;
	} else if (lock_flags & XFS_ILOCK_SHARED) {
		if (!mrtryaccess(&ip->i_lock))
			goto out_undo_iolock;
	}
	return 1;

 out_undo_iolock:
	if (lock_flags & XFS_IOLOCK_EXCL)
		mrunlock_excl(&ip->i_iolock);
	else if (lock_flags & XFS_IOLOCK_SHARED)
		mrunlock_shared(&ip->i_iolock);
 out:
	return 0;
}

/*
 * xfs_iunlock() is used to drop the inode locks acquired with
 * xfs_ilock() and xfs_ilock_nowait().  The caller must pass
 * in the flags given to xfs_ilock() or xfs_ilock_nowait() so
 * that we know which locks to drop.
 *
 * ip -- the inode being unlocked
 * lock_flags -- this parameter indicates the inode's locks to be
 *       to be unlocked.  See the comment for xfs_ilock() for a list
 *	 of valid values for this parameter.
 *
 */
void
xfs_iunlock(
	xfs_inode_t		*ip,
	uint			lock_flags)
{
	/*
	 * You can't set both SHARED and EXCL for the same lock,
	 * and only XFS_IOLOCK_SHARED, XFS_IOLOCK_EXCL, XFS_ILOCK_SHARED,
	 * and XFS_ILOCK_EXCL are valid values to set in lock_flags.
	 */
	ASSERT((lock_flags & (XFS_IOLOCK_SHARED | XFS_IOLOCK_EXCL)) !=
	       (XFS_IOLOCK_SHARED | XFS_IOLOCK_EXCL));
	ASSERT((lock_flags & (XFS_ILOCK_SHARED | XFS_ILOCK_EXCL)) !=
	       (XFS_ILOCK_SHARED | XFS_ILOCK_EXCL));
	ASSERT((lock_flags & ~(XFS_LOCK_MASK | XFS_LOCK_DEP_MASK)) == 0);
	ASSERT(lock_flags != 0);

	if (lock_flags & XFS_IOLOCK_EXCL)
		mrunlock_excl(&ip->i_iolock);
	else if (lock_flags & XFS_IOLOCK_SHARED)
		mrunlock_shared(&ip->i_iolock);

	if (lock_flags & XFS_ILOCK_EXCL)
		mrunlock_excl(&ip->i_lock);
	else if (lock_flags & XFS_ILOCK_SHARED)
		mrunlock_shared(&ip->i_lock);

	trace_xfs_iunlock(ip, lock_flags, _RET_IP_);
}

/*
 * give up write locks.  the i/o lock cannot be held nested
 * if it is being demoted.
 */
void
xfs_ilock_demote(
	xfs_inode_t		*ip,
	uint			lock_flags)
{
	ASSERT(lock_flags & (XFS_IOLOCK_EXCL|XFS_ILOCK_EXCL));
	ASSERT((lock_flags & ~(XFS_IOLOCK_EXCL|XFS_ILOCK_EXCL)) == 0);

	if (lock_flags & XFS_ILOCK_EXCL)
		mrdemote(&ip->i_lock);
	if (lock_flags & XFS_IOLOCK_EXCL)
		mrdemote(&ip->i_iolock);

	trace_xfs_ilock_demote(ip, lock_flags, _RET_IP_);
}

#ifdef DEBUG
int
xfs_isilocked(
	xfs_inode_t		*ip,
	uint			lock_flags)
{
	if (lock_flags & (XFS_ILOCK_EXCL|XFS_ILOCK_SHARED)) {
		if (!(lock_flags & XFS_ILOCK_SHARED))
			return !!ip->i_lock.mr_writer;
		return rwsem_is_locked(&ip->i_lock.mr_lock);
	}

	if (lock_flags & (XFS_IOLOCK_EXCL|XFS_IOLOCK_SHARED)) {
		if (!(lock_flags & XFS_IOLOCK_SHARED))
			return !!ip->i_iolock.mr_writer;
		return rwsem_is_locked(&ip->i_iolock.mr_lock);
	}

	ASSERT(0);
	return 0;
}
#endif

#ifdef DEBUG
/*
 * Make sure that the extents in the given memory buffer
 * are valid.
 */
STATIC void
xfs_validate_extents(
	xfs_ifork_t		*ifp,
	int			nrecs,
	xfs_exntfmt_t		fmt)
{
	xfs_bmbt_irec_t		irec;
	xfs_bmbt_rec_host_t	rec;
	int			i;

	for (i = 0; i < nrecs; i++) {
		xfs_bmbt_rec_host_t *ep = xfs_iext_get_ext(ifp, i);
		rec.l0 = get_unaligned(&ep->l0);
		rec.l1 = get_unaligned(&ep->l1);
		xfs_bmbt_get_all(&rec, &irec);
		if (fmt == XFS_EXTFMT_NOSTATE)
			ASSERT(irec.br_state == XFS_EXT_NORM);
	}
}
#else /* DEBUG */
#define xfs_validate_extents(ifp, nrecs, fmt)
#endif /* DEBUG */

/*
 * Check that none of the inode's in the buffer have a next
 * unlinked field of 0.
 */
#if defined(DEBUG)
void
xfs_inobp_check(
	xfs_mount_t	*mp,
	xfs_buf_t	*bp)
{
	int		i;
	int		j;
	xfs_dinode_t	*dip;

	j = mp->m_inode_cluster_size >> mp->m_sb.sb_inodelog;

	for (i = 0; i < j; i++) {
		dip = (xfs_dinode_t *)xfs_buf_offset(bp,
					i * mp->m_sb.sb_inodesize);
		if (!dip->di_next_unlinked)  {
			xfs_alert(mp,
	"Detected bogus zero next_unlinked field in incore inode buffer 0x%p.",
				bp);
			ASSERT(dip->di_next_unlinked);
		}
	}
}
#endif

static void
xfs_inode_buf_verify(
	struct xfs_buf	*bp)
{
	struct xfs_mount *mp = bp->b_target->bt_mount;
	int		i;
	int		ni;

	/*
	 * Validate the magic number and version of every inode in the buffer
	 */
	ni = XFS_BB_TO_FSB(mp, bp->b_length) * mp->m_sb.sb_inopblock;
	for (i = 0; i < ni; i++) {
		int		di_ok;
		xfs_dinode_t	*dip;

		dip = (struct xfs_dinode *)xfs_buf_offset(bp,
					(i << mp->m_sb.sb_inodelog));
		di_ok = dip->di_magic == cpu_to_be16(XFS_DINODE_MAGIC) &&
			    XFS_DINODE_GOOD_VERSION(dip->di_version);
		if (unlikely(XFS_TEST_ERROR(!di_ok, mp,
						XFS_ERRTAG_ITOBP_INOTOBP,
						XFS_RANDOM_ITOBP_INOTOBP))) {
			xfs_buf_ioerror(bp, EFSCORRUPTED);
			XFS_CORRUPTION_ERROR(__func__, XFS_ERRLEVEL_HIGH,
					     mp, dip);
#ifdef DEBUG
			xfs_emerg(mp,
				"bad inode magic/vsn daddr %lld #%d (magic=%x)",
				(unsigned long long)bp->b_bn, i,
				be16_to_cpu(dip->di_magic));
			ASSERT(0);
#endif
		}
	}
	xfs_inobp_check(mp, bp);
}


static void
xfs_inode_buf_read_verify(
	struct xfs_buf	*bp)
{
	xfs_inode_buf_verify(bp);
}

static void
xfs_inode_buf_write_verify(
	struct xfs_buf	*bp)
{
	xfs_inode_buf_verify(bp);
}

const struct xfs_buf_ops xfs_inode_buf_ops = {
#ifdef WIN32
	xfs_inode_buf_read_verify,
	xfs_inode_buf_write_verify
#else
	.verify_read = xfs_inode_buf_read_verify,
	.verify_write = xfs_inode_buf_write_verify,
#endif
};


/*
 * This routine is called to map an inode to the buffer containing the on-disk
 * version of the inode.  It returns a pointer to the buffer containing the
 * on-disk inode in the bpp parameter, and in the dipp parameter it returns a
 * pointer to the on-disk inode within that buffer.
 *
 * If a non-zero error is returned, then the contents of bpp and dipp are
 * undefined.
 */
int
xfs_imap_to_bp(
	struct xfs_mount	*mp,
	struct xfs_trans	*tp,
	struct xfs_imap		*imap,
	struct xfs_dinode       **dipp,
	struct xfs_buf		**bpp,
	uint			buf_flags,
	uint			iget_flags)
{
	struct xfs_buf		*bp;
	int			error;

	buf_flags |= XBF_UNMAPPED;
	error = xfs_trans_read_buf(mp, tp, mp->m_ddev_targp, imap->im_blkno,
				   (int)imap->im_len, buf_flags, &bp,
				   &xfs_inode_buf_ops);
	if (error) {
		if (error == EAGAIN) {
			ASSERT(buf_flags & XBF_TRYLOCK);
			return error;
		}

		if (error == EFSCORRUPTED &&
		    (iget_flags & XFS_IGET_UNTRUSTED))
			return XFS_ERROR(EINVAL);

		xfs_warn(mp, "%s: xfs_trans_read_buf() returned error %d.",
			__func__, error);
		return error;
	}

	*bpp = bp;
	*dipp = (struct xfs_dinode *)xfs_buf_offset(bp, imap->im_boffset);
	return 0;
}

/*
 * Move inode type and inode format specific information from the
 * on-disk inode to the in-core inode.  For fifos, devs, and sockets
 * this means set if_rdev to the proper value.  For files, directories,
 * and symlinks this means to bring in the in-line data or extent
 * pointers.  For a file in B-tree format, only the root is immediately
 * brought in-core.  The rest will be in-lined in if_extents when it
 * is first referenced (see xfs_iread_extents()).
 */
STATIC int
xfs_iformat(
	xfs_inode_t		*ip,
	xfs_dinode_t		*dip)
{
	xfs_attr_shortform_t	*atp;
	int			size;
	int			error = 0;
	xfs_fsize_t             di_size;

	if (unlikely(be32_to_cpu(dip->di_nextents) +
		     be16_to_cpu(dip->di_anextents) >
		     be64_to_cpu(dip->di_nblocks))) {
		xfs_warn(ip->i_mount,
			"corrupt dinode %Lu, extent total = %d, nblocks = %Lu.",
			(unsigned long long)ip->i_ino,
			(int)(be32_to_cpu(dip->di_nextents) +
			      be16_to_cpu(dip->di_anextents)),
			(unsigned long long)
				be64_to_cpu(dip->di_nblocks));
		XFS_CORRUPTION_ERROR("xfs_iformat(1)", XFS_ERRLEVEL_LOW,
				     ip->i_mount, dip);
		return XFS_ERROR(EFSCORRUPTED);
	}

	if (unlikely(dip->di_forkoff > ip->i_mount->m_sb.sb_inodesize)) {
		xfs_warn(ip->i_mount, "corrupt dinode %Lu, forkoff = 0x%x.",
			(unsigned long long)ip->i_ino,
			dip->di_forkoff);
		XFS_CORRUPTION_ERROR("xfs_iformat(2)", XFS_ERRLEVEL_LOW,
				     ip->i_mount, dip);
		return XFS_ERROR(EFSCORRUPTED);
	}

	if (unlikely((ip->i_d.di_flags & XFS_DIFLAG_REALTIME) &&
		     !ip->i_mount->m_rtdev_targp)) {
		xfs_warn(ip->i_mount,
			"corrupt dinode %Lu, has realtime flag set.",
			ip->i_ino);
		XFS_CORRUPTION_ERROR("xfs_iformat(realtime)",
				     XFS_ERRLEVEL_LOW, ip->i_mount, dip);
		return XFS_ERROR(EFSCORRUPTED);
	}

	switch (ip->i_d.di_mode & S_IFMT) {
	case S_IFIFO:
	case S_IFCHR:
	case S_IFBLK:
	case S_IFSOCK:
		if (unlikely(dip->di_format != XFS_DINODE_FMT_DEV)) {
			XFS_CORRUPTION_ERROR("xfs_iformat(3)", XFS_ERRLEVEL_LOW,
					      ip->i_mount, dip);
			return XFS_ERROR(EFSCORRUPTED);
		}
		ip->i_d.di_size = 0;
		ip->i_df.if_u2.if_rdev = xfs_dinode_get_rdev(dip);
		break;

	case S_IFREG:
	case S_IFLNK:
	case S_IFDIR:
		switch (dip->di_format) {
		case XFS_DINODE_FMT_LOCAL:
			/*
			 * no local regular files yet
			 */
			if (unlikely(S_ISREG(be16_to_cpu(dip->di_mode)))) {
				xfs_warn(ip->i_mount,
			"corrupt inode %Lu (local format for regular file).",
					(unsigned long long) ip->i_ino);
				XFS_CORRUPTION_ERROR("xfs_iformat(4)",
						     XFS_ERRLEVEL_LOW,
						     ip->i_mount, dip);
				return XFS_ERROR(EFSCORRUPTED);
			}

			di_size = be64_to_cpu(dip->di_size);
			if (unlikely(di_size > XFS_DFORK_DSIZE(dip, ip->i_mount))) {
				xfs_warn(ip->i_mount,
			"corrupt inode %Lu (bad size %Ld for local inode).",
					(unsigned long long) ip->i_ino,
					(long long) di_size);
				XFS_CORRUPTION_ERROR("xfs_iformat(5)",
						     XFS_ERRLEVEL_LOW,
						     ip->i_mount, dip);
				return XFS_ERROR(EFSCORRUPTED);
			}

			size = (int)di_size;
			error = xfs_iformat_local(ip, dip, XFS_DATA_FORK, size);
			break;
		case XFS_DINODE_FMT_EXTENTS:
			error = xfs_iformat_extents(ip, dip, XFS_DATA_FORK);
			break;
		case XFS_DINODE_FMT_BTREE:
			error = xfs_iformat_btree(ip, dip, XFS_DATA_FORK);
			break;
		default:
			XFS_ERROR_REPORT("xfs_iformat(6)", XFS_ERRLEVEL_LOW,
					 ip->i_mount);
			return XFS_ERROR(EFSCORRUPTED);
		}
		break;

	default:
		XFS_ERROR_REPORT("xfs_iformat(7)", XFS_ERRLEVEL_LOW, ip->i_mount);
		return XFS_ERROR(EFSCORRUPTED);
	}
	if (error) {
		return error;
	}
	if (!XFS_DFORK_Q(dip))
		return 0;

	ASSERT(ip->i_afp == NULL);
	ip->i_afp = kmem_zone_zalloc(xfs_ifork_zone, KM_SLEEP | KM_NOFS);

	switch (dip->di_aformat) {
	case XFS_DINODE_FMT_LOCAL:
		atp = (xfs_attr_shortform_t *)XFS_DFORK_APTR(dip);
		size = be16_to_cpu(atp->hdr.totsize);

		if (unlikely(size < sizeof(struct xfs_attr_sf_hdr))) {
			xfs_warn(ip->i_mount,
				"corrupt inode %Lu (bad attr fork size %Ld).",
				(unsigned long long) ip->i_ino,
				(long long) size);
			XFS_CORRUPTION_ERROR("xfs_iformat(8)",
					     XFS_ERRLEVEL_LOW,
					     ip->i_mount, dip);
			return XFS_ERROR(EFSCORRUPTED);
		}

		error = xfs_iformat_local(ip, dip, XFS_ATTR_FORK, size);
		break;
	case XFS_DINODE_FMT_EXTENTS:
		error = xfs_iformat_extents(ip, dip, XFS_ATTR_FORK);
		break;
	case XFS_DINODE_FMT_BTREE:
		error = xfs_iformat_btree(ip, dip, XFS_ATTR_FORK);
		break;
	default:
		error = XFS_ERROR(EFSCORRUPTED);
		break;
	}
	if (error) {
		kmem_zone_free(xfs_ifork_zone, ip->i_afp);
		ip->i_afp = NULL;
		xfs_idestroy_fork(ip, XFS_DATA_FORK);
	}
	return error;
}

/*
 * The file is in-lined in the on-disk inode.
 * If it fits into if_inline_data, then copy
 * it there, otherwise allocate a buffer for it
 * and copy the data there.  Either way, set
 * if_data to point at the data.
 * If we allocate a buffer for the data, make
 * sure that its size is a multiple of 4 and
 * record the real size in i_real_bytes.
 */
STATIC int
xfs_iformat_local(
	xfs_inode_t	*ip,
	xfs_dinode_t	*dip,
	int		whichfork,
	int		size)
{
	xfs_ifork_t	*ifp;
	int		real_size;

	/*
	 * If the size is unreasonable, then something
	 * is wrong and we just bail out rather than crash in
	 * kmem_alloc() or memcpy() below.
	 */
	if (unlikely(size > XFS_DFORK_SIZE(dip, ip->i_mount, whichfork))) {
		xfs_warn(ip->i_mount,
	"corrupt inode %Lu (bad size %d for local fork, size = %d).",
			(unsigned long long) ip->i_ino, size,
			XFS_DFORK_SIZE(dip, ip->i_mount, whichfork));
		XFS_CORRUPTION_ERROR("xfs_iformat_local", XFS_ERRLEVEL_LOW,
				     ip->i_mount, dip);
		return XFS_ERROR(EFSCORRUPTED);
	}
	ifp = XFS_IFORK_PTR(ip, whichfork);
	real_size = 0;
	if (size == 0)
		ifp->if_u1.if_data = NULL;
	else if (size <= sizeof(ifp->if_u2.if_inline_data))
		ifp->if_u1.if_data = ifp->if_u2.if_inline_data;
	else {
		real_size = roundup(size, 4);
		ifp->if_u1.if_data = kmem_alloc(real_size, KM_SLEEP | KM_NOFS);
	}
	ifp->if_bytes = size;
	ifp->if_real_bytes = real_size;
	if (size)
		memcpy(ifp->if_u1.if_data, XFS_DFORK_PTR(dip, whichfork), size);
	ifp->if_flags &= ~XFS_IFEXTENTS;
	ifp->if_flags |= XFS_IFINLINE;
	return 0;
}

/*
 * The file consists of a set of extents all
 * of which fit into the on-disk inode.
 * If there are few enough extents to fit into
 * the if_inline_ext, then copy them there.
 * Otherwise allocate a buffer for them and copy
 * them into it.  Either way, set if_extents
 * to point at the extents.
 */
STATIC int
xfs_iformat_extents(
	xfs_inode_t	*ip,
	xfs_dinode_t	*dip,
	int		whichfork)
{
	xfs_bmbt_rec_t	*dp;
	xfs_ifork_t	*ifp;
	int		nex;
	int		size;
	int		i;

	ifp = XFS_IFORK_PTR(ip, whichfork);
	nex = XFS_DFORK_NEXTENTS(dip, whichfork);
	size = nex * (uint)sizeof(xfs_bmbt_rec_t);

	/*
	 * If the number of extents is unreasonable, then something
	 * is wrong and we just bail out rather than crash in
	 * kmem_alloc() or memcpy() below.
	 */
	if (unlikely(size < 0 || size > XFS_DFORK_SIZE(dip, ip->i_mount, whichfork))) {
		xfs_warn(ip->i_mount, "corrupt inode %Lu ((a)extents = %d).",
			(unsigned long long) ip->i_ino, nex);
		XFS_CORRUPTION_ERROR("xfs_iformat_extents(1)", XFS_ERRLEVEL_LOW,
				     ip->i_mount, dip);
		return XFS_ERROR(EFSCORRUPTED);
	}

	ifp->if_real_bytes = 0;
	if (nex == 0)
		ifp->if_u1.if_extents = NULL;
	else if (nex <= XFS_INLINE_EXTS)
		ifp->if_u1.if_extents = ifp->if_u2.if_inline_ext;
	else
		xfs_iext_add(ifp, 0, nex);

	ifp->if_bytes = size;
	if (size) {
		dp = (xfs_bmbt_rec_t *) XFS_DFORK_PTR(dip, whichfork);
		xfs_validate_extents(ifp, nex, XFS_EXTFMT_INODE(ip));
		for (i = 0; i < nex; i++, dp++) {
			xfs_bmbt_rec_host_t *ep = xfs_iext_get_ext(ifp, i);
			ep->l0 = get_unaligned_be64(&dp->l0);
			ep->l1 = get_unaligned_be64(&dp->l1);
		}
		XFS_BMAP_TRACE_EXLIST(ip, nex, whichfork);
		if (whichfork != XFS_DATA_FORK ||
			XFS_EXTFMT_INODE(ip) == XFS_EXTFMT_NOSTATE)
				if (unlikely(xfs_check_nostate_extents(
				    ifp, 0, nex))) {
					XFS_ERROR_REPORT("xfs_iformat_extents(2)",
							 XFS_ERRLEVEL_LOW,
							 ip->i_mount);
					return XFS_ERROR(EFSCORRUPTED);
				}
	}
	ifp->if_flags |= XFS_IFEXTENTS;
	return 0;
}

/*
 * The file has too many extents to fit into
 * the inode, so they are in B-tree format.
 * Allocate a buffer for the root of the B-tree
 * and copy the root into it.  The i_extents
 * field will remain NULL until all of the
 * extents are read in (when they are needed).
 */
STATIC int
xfs_iformat_btree(
	xfs_inode_t		*ip,
	xfs_dinode_t		*dip,
	int			whichfork)
{
	xfs_bmdr_block_t	*dfp;
	xfs_ifork_t		*ifp;
	/* REFERENCED */
	int			nrecs;
	int			size;

	ifp = XFS_IFORK_PTR(ip, whichfork);
	dfp = (xfs_bmdr_block_t *)XFS_DFORK_PTR(dip, whichfork);
	size = XFS_BMAP_BROOT_SPACE(dfp);
	nrecs = be16_to_cpu(dfp->bb_numrecs);

	/*
	 * blow out if -- fork has less extents than can fit in
	 * fork (fork shouldn't be a btree format), root btree
	 * block has more records than can fit into the fork,
	 * or the number of extents is greater than the number of
	 * blocks.
	 */
	if (unlikely(XFS_IFORK_NEXTENTS(ip, whichfork) <=
			XFS_IFORK_MAXEXT(ip, whichfork) ||
		     XFS_BMDR_SPACE_CALC(nrecs) >
			XFS_DFORK_SIZE(dip, ip->i_mount, whichfork) ||
		     XFS_IFORK_NEXTENTS(ip, whichfork) > ip->i_d.di_nblocks)) {
		xfs_warn(ip->i_mount, "corrupt inode %Lu (btree).",
			(unsigned long long) ip->i_ino);
		XFS_CORRUPTION_ERROR("xfs_iformat_btree", XFS_ERRLEVEL_LOW,
				 ip->i_mount, dip);
		return XFS_ERROR(EFSCORRUPTED);
	}

	ifp->if_broot_bytes = size;
	ifp->if_broot = kmem_alloc(size, KM_SLEEP | KM_NOFS);
	ASSERT(ifp->if_broot != NULL);
	/*
	 * Copy and convert from the on-disk structure
	 * to the in-memory structure.
	 */
	xfs_bmdr_to_bmbt(ip->i_mount, dfp,
			 XFS_DFORK_SIZE(dip, ip->i_mount, whichfork),
			 ifp->if_broot, size);
	ifp->if_flags &= ~XFS_IFEXTENTS;
	ifp->if_flags |= XFS_IFBROOT;

	return 0;
}

STATIC void
xfs_dinode_from_disk(
	xfs_icdinode_t		*to,
	xfs_dinode_t		*from)
{
	to->di_magic = be16_to_cpu(from->di_magic);
	to->di_mode = be16_to_cpu(from->di_mode);
	to->di_version = from ->di_version;
	to->di_format = from->di_format;
	to->di_onlink = be16_to_cpu(from->di_onlink);
	to->di_uid = be32_to_cpu(from->di_uid);
	to->di_gid = be32_to_cpu(from->di_gid);
	to->di_nlink = be32_to_cpu(from->di_nlink);
	to->di_projid_lo = be16_to_cpu(from->di_projid_lo);
	to->di_projid_hi = be16_to_cpu(from->di_projid_hi);
	memcpy(to->di_pad, from->di_pad, sizeof(to->di_pad));
	to->di_flushiter = be16_to_cpu(from->di_flushiter);
	to->di_atime.t_sec = be32_to_cpu(from->di_atime.t_sec);
	to->di_atime.t_nsec = be32_to_cpu(from->di_atime.t_nsec);
	to->di_mtime.t_sec = be32_to_cpu(from->di_mtime.t_sec);
	to->di_mtime.t_nsec = be32_to_cpu(from->di_mtime.t_nsec);
	to->di_ctime.t_sec = be32_to_cpu(from->di_ctime.t_sec);
	to->di_ctime.t_nsec = be32_to_cpu(from->di_ctime.t_nsec);
	to->di_size = be64_to_cpu(from->di_size);
	to->di_nblocks = be64_to_cpu(from->di_nblocks);
	to->di_extsize = be32_to_cpu(from->di_extsize);
	to->di_nextents = be32_to_cpu(from->di_nextents);
	to->di_anextents = be16_to_cpu(from->di_anextents);
	to->di_forkoff = from->di_forkoff;
	to->di_aformat	= from->di_aformat;
	to->di_dmevmask	= be32_to_cpu(from->di_dmevmask);
	to->di_dmstate	= be16_to_cpu(from->di_dmstate);
	to->di_flags	= be16_to_cpu(from->di_flags);
	to->di_gen	= be32_to_cpu(from->di_gen);
}

void
xfs_dinode_to_disk(
	xfs_dinode_t		*to,
	xfs_icdinode_t		*from)
{
	to->di_magic = cpu_to_be16(from->di_magic);
	to->di_mode = cpu_to_be16(from->di_mode);
	to->di_version = from ->di_version;
	to->di_format = from->di_format;
	to->di_onlink = cpu_to_be16(from->di_onlink);
	to->di_uid = cpu_to_be32(from->di_uid);
	to->di_gid = cpu_to_be32(from->di_gid);
	to->di_nlink = cpu_to_be32(from->di_nlink);
	to->di_projid_lo = cpu_to_be16(from->di_projid_lo);
	to->di_projid_hi = cpu_to_be16(from->di_projid_hi);
	memcpy(to->di_pad, from->di_pad, sizeof(to->di_pad));
	to->di_flushiter = cpu_to_be16(from->di_flushiter);
	to->di_atime.t_sec = cpu_to_be32(from->di_atime.t_sec);
	to->di_atime.t_nsec = cpu_to_be32(from->di_atime.t_nsec);
	to->di_mtime.t_sec = cpu_to_be32(from->di_mtime.t_sec);
	to->di_mtime.t_nsec = cpu_to_be32(from->di_mtime.t_nsec);
	to->di_ctime.t_sec = cpu_to_be32(from->di_ctime.t_sec);
	to->di_ctime.t_nsec = cpu_to_be32(from->di_ctime.t_nsec);
	to->di_size = cpu_to_be64(from->di_size);
	to->di_nblocks = cpu_to_be64(from->di_nblocks);
	to->di_extsize = cpu_to_be32(from->di_extsize);
	to->di_nextents = cpu_to_be32(from->di_nextents);
	to->di_anextents = cpu_to_be16(from->di_anextents);
	to->di_forkoff = from->di_forkoff;
	to->di_aformat = from->di_aformat;
	to->di_dmevmask = cpu_to_be32(from->di_dmevmask);
	to->di_dmstate = cpu_to_be16(from->di_dmstate);
	to->di_flags = cpu_to_be16(from->di_flags);
	to->di_gen = cpu_to_be32(from->di_gen);
}

STATIC uint
_xfs_dic2xflags(
	__uint16_t		di_flags)
{
	uint			flags = 0;

	if (di_flags & XFS_DIFLAG_ANY) {
		if (di_flags & XFS_DIFLAG_REALTIME)
			flags |= XFS_XFLAG_REALTIME;
		if (di_flags & XFS_DIFLAG_PREALLOC)
			flags |= XFS_XFLAG_PREALLOC;
		if (di_flags & XFS_DIFLAG_IMMUTABLE)
			flags |= XFS_XFLAG_IMMUTABLE;
		if (di_flags & XFS_DIFLAG_APPEND)
			flags |= XFS_XFLAG_APPEND;
		if (di_flags & XFS_DIFLAG_SYNC)
			flags |= XFS_XFLAG_SYNC;
		if (di_flags & XFS_DIFLAG_NOATIME)
			flags |= XFS_XFLAG_NOATIME;
		if (di_flags & XFS_DIFLAG_NODUMP)
			flags |= XFS_XFLAG_NODUMP;
		if (di_flags & XFS_DIFLAG_RTINHERIT)
			flags |= XFS_XFLAG_RTINHERIT;
		if (di_flags & XFS_DIFLAG_PROJINHERIT)
			flags |= XFS_XFLAG_PROJINHERIT;
		if (di_flags & XFS_DIFLAG_NOSYMLINKS)
			flags |= XFS_XFLAG_NOSYMLINKS;
		if (di_flags & XFS_DIFLAG_EXTSIZE)
			flags |= XFS_XFLAG_EXTSIZE;
		if (di_flags & XFS_DIFLAG_EXTSZINHERIT)
			flags |= XFS_XFLAG_EXTSZINHERIT;
		if (di_flags & XFS_DIFLAG_NODEFRAG)
			flags |= XFS_XFLAG_NODEFRAG;
		if (di_flags & XFS_DIFLAG_FILESTREAM)
			flags |= XFS_XFLAG_FILESTREAM;
	}

	return flags;
}

uint
xfs_ip2xflags(
	xfs_inode_t		*ip)
{
	xfs_icdinode_t		*dic = &ip->i_d;

	return _xfs_dic2xflags(dic->di_flags) |
				(XFS_IFORK_Q(ip) ? XFS_XFLAG_HASATTR : 0);
}

uint
xfs_dic2xflags(
	xfs_dinode_t		*dip)
{
	return _xfs_dic2xflags(be16_to_cpu(dip->di_flags)) |
				(XFS_DFORK_Q(dip) ? XFS_XFLAG_HASATTR : 0);
}

/*
 * Read the disk inode attributes into the in-core inode structure.
 */
int
xfs_iread(
	xfs_mount_t	*mp,
	xfs_trans_t	*tp,
	xfs_inode_t	*ip,
	uint		iget_flags)
{
	xfs_buf_t	*bp;
	xfs_dinode_t	*dip;
	int		error;

	/*
	 * Fill in the location information in the in-core inode.
	 */
	error = xfs_imap(mp, tp, ip->i_ino, &ip->i_imap, iget_flags);
	if (error)
		return error;

	/*
	 * Get pointers to the on-disk inode and the buffer containing it.
	 */
	error = xfs_imap_to_bp(mp, tp, &ip->i_imap, &dip, &bp, 0, iget_flags);
	if (error)
		return error;

	/*
	 * If we got something that isn't an inode it means someone
	 * (nfs or dmi) has a stale handle.
	 */
	if (dip->di_magic != cpu_to_be16(XFS_DINODE_MAGIC)) {
#ifdef DEBUG
		xfs_alert(mp,
			"%s: dip->di_magic (0x%x) != XFS_DINODE_MAGIC (0x%x)",
			__func__, be16_to_cpu(dip->di_magic), XFS_DINODE_MAGIC);
#endif /* DEBUG */
		error = XFS_ERROR(EINVAL);
		goto out_brelse;
	}

	/*
	 * If the on-disk inode is already linked to a directory
	 * entry, copy all of the inode into the in-core inode.
	 * xfs_iformat() handles copying in the inode format
	 * specific information.
	 * Otherwise, just get the truly permanent information.
	 */
	if (dip->di_mode) {
		xfs_dinode_from_disk(&ip->i_d, dip);
		error = xfs_iformat(ip, dip);
		if (error)  {
#ifdef DEBUG
			xfs_alert(mp, "%s: xfs_iformat() returned error %d",
				__func__, error);
#endif /* DEBUG */
			goto out_brelse;
		}
	} else {
		ip->i_d.di_magic = be16_to_cpu(dip->di_magic);
		ip->i_d.di_version = dip->di_version;
		ip->i_d.di_gen = be32_to_cpu(dip->di_gen);
		ip->i_d.di_flushiter = be16_to_cpu(dip->di_flushiter);
		/*
		 * Make sure to pull in the mode here as well in
		 * case the inode is released without being used.
		 * This ensures that xfs_inactive() will see that
		 * the inode is already free and not try to mess
		 * with the uninitialized part of it.
		 */
		ip->i_d.di_mode = 0;
	}

	/*
	 * The inode format changed when we moved the link count and
	 * made it 32 bits long.  If this is an old format inode,
	 * convert it in memory to look like a new one.  If it gets
	 * flushed to disk we will convert back before flushing or
	 * logging it.  We zero out the new projid field and the old link
	 * count field.  We'll handle clearing the pad field (the remains
	 * of the old uuid field) when we actually convert the inode to
	 * the new format. We don't change the version number so that we
	 * can distinguish this from a real new format inode.
	 */
	if (ip->i_d.di_version == 1) {
		ip->i_d.di_nlink = ip->i_d.di_onlink;
		ip->i_d.di_onlink = 0;
		xfs_set_projid(ip, 0);
	}

	ip->i_delayed_blks = 0;

	/*
	 * Mark the buffer containing the inode as something to keep
	 * around for a while.  This helps to keep recently accessed
	 * meta-data in-core longer.
	 */
	xfs_buf_set_ref(bp, XFS_INO_REF);

	/*
	 * Use xfs_trans_brelse() to release the buffer containing the
	 * on-disk inode, because it was acquired with xfs_trans_read_buf()
	 * in xfs_imap_to_bp() above.  If tp is NULL, this is just a normal
	 * brelse().  If we're within a transaction, then xfs_trans_brelse()
	 * will only release the buffer if it is not dirty within the
	 * transaction.  It will be OK to release the buffer in this case,
	 * because inodes on disk are never destroyed and we will be
	 * locking the new in-core inode before putting it in the hash
	 * table where other processes can find it.  Thus we don't have
	 * to worry about the inode being changed just because we released
	 * the buffer.
	 */
 out_brelse:
	xfs_trans_brelse(tp, bp);
	return error;
}

/*
 * Read in extents from a btree-format inode.
 * Allocate and fill in if_extents.  Real work is done in xfs_bmap.c.
 */
int
xfs_iread_extents(
	xfs_trans_t	*tp,
	xfs_inode_t	*ip,
	int		whichfork)
{
	int		error;
	xfs_ifork_t	*ifp;
	xfs_extnum_t	nextents;

	if (unlikely(XFS_IFORK_FORMAT(ip, whichfork) != XFS_DINODE_FMT_BTREE)) {
		XFS_ERROR_REPORT("xfs_iread_extents", XFS_ERRLEVEL_LOW,
				 ip->i_mount);
		return XFS_ERROR(EFSCORRUPTED);
	}
	nextents = XFS_IFORK_NEXTENTS(ip, whichfork);
	ifp = XFS_IFORK_PTR(ip, whichfork);

	/*
	 * We know that the size is valid (it's checked in iformat_btree)
	 */
	ifp->if_bytes = ifp->if_real_bytes = 0;
	ifp->if_flags |= XFS_IFEXTENTS;
	xfs_iext_add(ifp, 0, nextents);
	error = xfs_bmap_read_extents(tp, ip, whichfork);
	if (error) {
		xfs_iext_destroy(ifp);
		ifp->if_flags &= ~XFS_IFEXTENTS;
		return error;
	}
	xfs_validate_extents(ifp, nextents, XFS_EXTFMT_INODE(ip));
	return 0;
}

/*
 * Reallocate the space for if_broot based on the number of records
 * being added or deleted as indicated in rec_diff.  Move the records
 * and pointers in if_broot to fit the new size.  When shrinking this
 * will eliminate holes between the records and pointers created by
 * the caller.  When growing this will create holes to be filled in
 * by the caller.
 *
 * The caller must not request to add more records than would fit in
 * the on-disk inode root.  If the if_broot is currently NULL, then
 * if we adding records one will be allocated.  The caller must also
 * not request that the number of records go below zero, although
 * it can go to zero.
 *
 * ip -- the inode whose if_broot area is changing
 * ext_diff -- the change in the number of records, positive or negative,
 *	 requested for the if_broot array.
 */
void
xfs_iroot_realloc(
	xfs_inode_t		*ip,
	int			rec_diff,
	int			whichfork)
{
	struct xfs_mount	*mp = ip->i_mount;
	int			cur_max;
	xfs_ifork_t		*ifp;
	struct xfs_btree_block	*new_broot;
	int			new_max;
	size_t			new_size;
	char			*np;
	char			*op;

	/*
	 * Handle the degenerate case quietly.
	 */
	if (rec_diff == 0) {
		return;
	}

	ifp = XFS_IFORK_PTR(ip, whichfork);
	if (rec_diff > 0) {
		/*
		 * If there wasn't any memory allocated before, just
		 * allocate it now and get out.
		 */
		if (ifp->if_broot_bytes == 0) {
			new_size = (size_t)XFS_BMAP_BROOT_SPACE_CALC(rec_diff);
			ifp->if_broot = kmem_alloc(new_size, KM_SLEEP | KM_NOFS);
			ifp->if_broot_bytes = (int)new_size;
			return;
		}

		/*
		 * If there is already an existing if_broot, then we need
		 * to realloc() it and shift the pointers to their new
		 * location.  The records don't change location because
		 * they are kept butted up against the btree block header.
		 */
		cur_max = xfs_bmbt_maxrecs(mp, ifp->if_broot_bytes, 0);
		new_max = cur_max + rec_diff;
		new_size = (size_t)XFS_BMAP_BROOT_SPACE_CALC(new_max);
		ifp->if_broot = kmem_realloc(ifp->if_broot, new_size,
				(size_t)XFS_BMAP_BROOT_SPACE_CALC(cur_max), /* old size */
				KM_SLEEP | KM_NOFS);
		op = (char *)XFS_BMAP_BROOT_PTR_ADDR(mp, ifp->if_broot, 1,
						     ifp->if_broot_bytes);
		np = (char *)XFS_BMAP_BROOT_PTR_ADDR(mp, ifp->if_broot, 1,
						     (int)new_size);
		ifp->if_broot_bytes = (int)new_size;
		ASSERT(ifp->if_broot_bytes <=
			XFS_IFORK_SIZE(ip, whichfork) + XFS_BROOT_SIZE_ADJ);
		memmove(np, op, cur_max * (uint)sizeof(xfs_dfsbno_t));
		return;
	}

	/*
	 * rec_diff is less than 0.  In this case, we are shrinking the
	 * if_broot buffer.  It must already exist.  If we go to zero
	 * records, just get rid of the root and clear the status bit.
	 */
	ASSERT((ifp->if_broot != NULL) && (ifp->if_broot_bytes > 0));
	cur_max = xfs_bmbt_maxrecs(mp, ifp->if_broot_bytes, 0);
	new_max = cur_max + rec_diff;
	ASSERT(new_max >= 0);
	if (new_max > 0)
		new_size = (size_t)XFS_BMAP_BROOT_SPACE_CALC(new_max);
	else
		new_size = 0;
	if (new_size > 0) {
		new_broot = kmem_alloc(new_size, KM_SLEEP | KM_NOFS);
		/*
		 * First copy over the btree block header.
		 */
		memcpy(new_broot, ifp->if_broot, XFS_BTREE_LBLOCK_LEN);
	} else {
		new_broot = NULL;
		ifp->if_flags &= ~XFS_IFBROOT;
	}

	/*
	 * Only copy the records and pointers if there are any.
	 */
	if (new_max > 0) {
		/*
		 * First copy the records.
		 */
		op = (char *)XFS_BMBT_REC_ADDR(mp, ifp->if_broot, 1);
		np = (char *)XFS_BMBT_REC_ADDR(mp, new_broot, 1);
		memcpy(np, op, new_max * (uint)sizeof(xfs_bmbt_rec_t));

		/*
		 * Then copy the pointers.
		 */
		op = (char *)XFS_BMAP_BROOT_PTR_ADDR(mp, ifp->if_broot, 1,
						     ifp->if_broot_bytes);
		np = (char *)XFS_BMAP_BROOT_PTR_ADDR(mp, new_broot, 1,
						     (int)new_size);
		memcpy(np, op, new_max * (uint)sizeof(xfs_dfsbno_t));
	}
	kmem_free(ifp->if_broot);
	ifp->if_broot = new_broot;
	ifp->if_broot_bytes = (int)new_size;
	ASSERT(ifp->if_broot_bytes <=
		XFS_IFORK_SIZE(ip, whichfork) + XFS_BROOT_SIZE_ADJ);
	return;
}


/*
 * This is called when the amount of space needed for if_data
 * is increased or decreased.  The change in size is indicated by
 * the number of bytes that need to be added or deleted in the
 * byte_diff parameter.
 *
 * If the amount of space needed has decreased below the size of the
 * inline buffer, then switch to using the inline buffer.  Otherwise,
 * use kmem_realloc() or kmem_alloc() to adjust the size of the buffer
 * to what is needed.
 *
 * ip -- the inode whose if_data area is changing
 * byte_diff -- the change in the number of bytes, positive or negative,
 *	 requested for the if_data array.
 */
void
xfs_idata_realloc(
	xfs_inode_t	*ip,
	int		byte_diff,
	int		whichfork)
{
	xfs_ifork_t	*ifp;
	int		new_size;
	int		real_size;

	if (byte_diff == 0) {
		return;
	}

	ifp = XFS_IFORK_PTR(ip, whichfork);
	new_size = (int)ifp->if_bytes + byte_diff;
	ASSERT(new_size >= 0);

	if (new_size == 0) {
		if (ifp->if_u1.if_data != ifp->if_u2.if_inline_data) {
			kmem_free(ifp->if_u1.if_data);
		}
		ifp->if_u1.if_data = NULL;
		real_size = 0;
	} else if (new_size <= sizeof(ifp->if_u2.if_inline_data)) {
		/*
		 * If the valid extents/data can fit in if_inline_ext/data,
		 * copy them from the malloc'd vector and free it.
		 */
		if (ifp->if_u1.if_data == NULL) {
			ifp->if_u1.if_data = ifp->if_u2.if_inline_data;
		} else if (ifp->if_u1.if_data != ifp->if_u2.if_inline_data) {
			ASSERT(ifp->if_real_bytes != 0);
			memcpy(ifp->if_u2.if_inline_data, ifp->if_u1.if_data,
			      new_size);
			kmem_free(ifp->if_u1.if_data);
			ifp->if_u1.if_data = ifp->if_u2.if_inline_data;
		}
		real_size = 0;
	} else {
		/*
		 * Stuck with malloc/realloc.
		 * For inline data, the underlying buffer must be
		 * a multiple of 4 bytes in size so that it can be
		 * logged and stay on word boundaries.  We enforce
		 * that here.
		 */
		real_size = roundup(new_size, 4);
		if (ifp->if_u1.if_data == NULL) {
			ASSERT(ifp->if_real_bytes == 0);
			ifp->if_u1.if_data = kmem_alloc(real_size,
							KM_SLEEP | KM_NOFS);
		} else if (ifp->if_u1.if_data != ifp->if_u2.if_inline_data) {
			/*
			 * Only do the realloc if the underlying size
			 * is really changing.
			 */
			if (ifp->if_real_bytes != real_size) {
				ifp->if_u1.if_data =
					kmem_realloc(ifp->if_u1.if_data,
							real_size,
							ifp->if_real_bytes,
							KM_SLEEP | KM_NOFS);
			}
		} else {
			ASSERT(ifp->if_real_bytes == 0);
			ifp->if_u1.if_data = kmem_alloc(real_size,
							KM_SLEEP | KM_NOFS);
			memcpy(ifp->if_u1.if_data, ifp->if_u2.if_inline_data,
				ifp->if_bytes);
		}
	}
	ifp->if_real_bytes = real_size;
	ifp->if_bytes = new_size;
	ASSERT(ifp->if_bytes <= XFS_IFORK_SIZE(ip, whichfork));
}

void
xfs_idestroy_fork(
	xfs_inode_t	*ip,
	int		whichfork)
{
	xfs_ifork_t	*ifp;

	ifp = XFS_IFORK_PTR(ip, whichfork);
	if (ifp->if_broot != NULL) {
		kmem_free(ifp->if_broot);
		ifp->if_broot = NULL;
	}

	/*
	 * If the format is local, then we can't have an extents
	 * array so just look for an inline data array.  If we're
	 * not local then we may or may not have an extents list,
	 * so check and free it up if we do.
	 */
	if (XFS_IFORK_FORMAT(ip, whichfork) == XFS_DINODE_FMT_LOCAL) {
		if ((ifp->if_u1.if_data != ifp->if_u2.if_inline_data) &&
		    (ifp->if_u1.if_data != NULL)) {
			ASSERT(ifp->if_real_bytes != 0);
			kmem_free(ifp->if_u1.if_data);
			ifp->if_u1.if_data = NULL;
			ifp->if_real_bytes = 0;
		}
	} else if ((ifp->if_flags & XFS_IFEXTENTS) &&
		   ((ifp->if_flags & XFS_IFEXTIREC) ||
		    ((ifp->if_u1.if_extents != NULL) &&
		     (ifp->if_u1.if_extents != ifp->if_u2.if_inline_ext)))) {
		ASSERT(ifp->if_real_bytes != 0);
		xfs_iext_destroy(ifp);
	}
	ASSERT(ifp->if_u1.if_extents == NULL ||
	       ifp->if_u1.if_extents == ifp->if_u2.if_inline_ext);
	ASSERT(ifp->if_real_bytes == 0);
	if (whichfork == XFS_ATTR_FORK) {
		kmem_zone_free(xfs_ifork_zone, ip->i_afp);
		ip->i_afp = NULL;
	}
}

/*
 * Return a pointer to the extent record at file index idx.
 */
xfs_bmbt_rec_host_t *
xfs_iext_get_ext(
	xfs_ifork_t	*ifp,		/* inode fork pointer */
	xfs_extnum_t	idx)		/* index of target extent */
{
	ASSERT(idx >= 0);
	ASSERT(idx < ifp->if_bytes / sizeof(xfs_bmbt_rec_t));

	if ((ifp->if_flags & XFS_IFEXTIREC) && (idx == 0)) {
		return ifp->if_u1.if_ext_irec->er_extbuf;
	} else if (ifp->if_flags & XFS_IFEXTIREC) {
		xfs_ext_irec_t	*erp;		/* irec pointer */
		int		erp_idx = 0;	/* irec index */
		xfs_extnum_t	page_idx = idx;	/* ext index in target list */

		erp = xfs_iext_idx_to_irec(ifp, &page_idx, &erp_idx, 0);
		return &erp->er_extbuf[page_idx];
	} else if (ifp->if_bytes) {
		return &ifp->if_u1.if_extents[idx];
	} else {
		return NULL;
	}
}

/*
 * Insert new item(s) into the extent records for incore inode
 * fork 'ifp'.  'count' new items are inserted at index 'idx'.
 */
void
xfs_iext_insert(
	xfs_inode_t	*ip,		/* incore inode pointer */
	xfs_extnum_t	idx,		/* starting index of new items */
	xfs_extnum_t	count,		/* number of inserted items */
	xfs_bmbt_irec_t	*new,		/* items to insert */
	int		state)		/* type of extent conversion */
{
	xfs_ifork_t	*ifp = (state & BMAP_ATTRFORK) ? ip->i_afp : &ip->i_df;
	xfs_extnum_t	i;		/* extent record index */

	trace_xfs_iext_insert(ip, idx, new, state, _RET_IP_);

	ASSERT(ifp->if_flags & XFS_IFEXTENTS);
	xfs_iext_add(ifp, idx, count);
	for (i = idx; i < idx + count; i++, new++)
		xfs_bmbt_set_all(xfs_iext_get_ext(ifp, i), new);
}

/*
 * This is called when the amount of space required for incore file
 * extents needs to be increased. The ext_diff parameter stores the
 * number of new extents being added and the idx parameter contains
 * the extent index where the new extents will be added. If the new
 * extents are being appended, then we just need to (re)allocate and
 * initialize the space. Otherwise, if the new extents are being
 * inserted into the middle of the existing entries, a bit more work
 * is required to make room for the new extents to be inserted. The
 * caller is responsible for filling in the new extent entries upon
 * return.
 */
void
xfs_iext_add(
	xfs_ifork_t	*ifp,		/* inode fork pointer */
	xfs_extnum_t	idx,		/* index to begin adding exts */
	int		ext_diff)	/* number of extents to add */
{
	int		byte_diff;	/* new bytes being added */
	int		new_size;	/* size of extents after adding */
	xfs_extnum_t	nextents;	/* number of extents in file */

	nextents = ifp->if_bytes / (uint)sizeof(xfs_bmbt_rec_t);
	ASSERT((idx >= 0) && (idx <= nextents));
	byte_diff = ext_diff * sizeof(xfs_bmbt_rec_t);
	new_size = ifp->if_bytes + byte_diff;
	/*
	 * If the new number of extents (nextents + ext_diff)
	 * fits inside the inode, then continue to use the inline
	 * extent buffer.
	 */
	if (nextents + ext_diff <= XFS_INLINE_EXTS) {
		if (idx < nextents) {
			memmove(&ifp->if_u2.if_inline_ext[idx + ext_diff],
				&ifp->if_u2.if_inline_ext[idx],
				(nextents - idx) * sizeof(xfs_bmbt_rec_t));
			memset(&ifp->if_u2.if_inline_ext[idx], 0, byte_diff);
		}
		ifp->if_u1.if_extents = ifp->if_u2.if_inline_ext;
		ifp->if_real_bytes = 0;
	}
	/*
	 * Otherwise use a linear (direct) extent list.
	 * If the extents are currently inside the inode,
	 * xfs_iext_realloc_direct will switch us from
	 * inline to direct extent allocation mode.
	 */
	else if (nextents + ext_diff <= XFS_LINEAR_EXTS) {
		xfs_iext_realloc_direct(ifp, new_size);
		if (idx < nextents) {
			memmove(&ifp->if_u1.if_extents[idx + ext_diff],
				&ifp->if_u1.if_extents[idx],
				(nextents - idx) * sizeof(xfs_bmbt_rec_t));
			memset(&ifp->if_u1.if_extents[idx], 0, byte_diff);
		}
	}
	/* Indirection array */
	else {
		xfs_ext_irec_t	*erp;
		int		erp_idx = 0;
		int		page_idx = idx;

		ASSERT(nextents + ext_diff > XFS_LINEAR_EXTS);
		if (ifp->if_flags & XFS_IFEXTIREC) {
			erp = xfs_iext_idx_to_irec(ifp, &page_idx, &erp_idx, 1);
		} else {
			xfs_iext_irec_init(ifp);
			ASSERT(ifp->if_flags & XFS_IFEXTIREC);
			erp = ifp->if_u1.if_ext_irec;
		}
		/* Extents fit in target extent page */
		if (erp && erp->er_extcount + ext_diff <= XFS_LINEAR_EXTS) {
			if (page_idx < erp->er_extcount) {
				memmove(&erp->er_extbuf[page_idx + ext_diff],
					&erp->er_extbuf[page_idx],
					(erp->er_extcount - page_idx) *
					sizeof(xfs_bmbt_rec_t));
				memset(&erp->er_extbuf[page_idx], 0, byte_diff);
			}
			erp->er_extcount += ext_diff;
			xfs_iext_irec_update_extoffs(ifp, erp_idx + 1, ext_diff);
		}
		/* Insert a new extent page */
		else if (erp) {
			xfs_iext_add_indirect_multi(ifp,
				erp_idx, page_idx, ext_diff);
		}
		/*
		 * If extent(s) are being appended to the last page in
		 * the indirection array and the new extent(s) don't fit
		 * in the page, then erp is NULL and erp_idx is set to
		 * the next index needed in the indirection array.
		 */
		else {
			int	count = ext_diff;

			while (count) {
				erp = xfs_iext_irec_new(ifp, erp_idx);
				erp->er_extcount = count;
				count -= MIN(count, (int)XFS_LINEAR_EXTS);
				if (count) {
					erp_idx++;
				}
			}
		}
	}
	ifp->if_bytes = new_size;
}

/*
 * This is called when incore extents are being added to the indirection
 * array and the new extents do not fit in the target extent list. The
 * erp_idx parameter contains the irec index for the target extent list
 * in the indirection array, and the idx parameter contains the extent
 * index within the list. The number of extents being added is stored
 * in the count parameter.
 *
 *    |-------|   |-------|
 *    |       |   |       |    idx - number of extents before idx
 *    |  idx  |   | count |
 *    |       |   |       |    count - number of extents being inserted at idx
 *    |-------|   |-------|
 *    | count |   | nex2  |    nex2 - number of extents after idx + count
 *    |-------|   |-------|
 */
void
xfs_iext_add_indirect_multi(
	xfs_ifork_t	*ifp,			/* inode fork pointer */
	int		erp_idx,		/* target extent irec index */
	xfs_extnum_t	idx,			/* index within target list */
	int		count)			/* new extents being added */
{
	int		byte_diff;		/* new bytes being added */
	xfs_ext_irec_t	*erp;			/* pointer to irec entry */
	xfs_extnum_t	ext_diff;		/* number of extents to add */
	xfs_extnum_t	ext_cnt;		/* new extents still needed */
	xfs_extnum_t	nex2;			/* extents after idx + count */
	xfs_bmbt_rec_t	*nex2_ep = NULL;	/* temp list for nex2 extents */
	int		nlists;			/* number of irec's (lists) */

	ASSERT(ifp->if_flags & XFS_IFEXTIREC);
	erp = &ifp->if_u1.if_ext_irec[erp_idx];
	nex2 = erp->er_extcount - idx;
	nlists = ifp->if_real_bytes / XFS_IEXT_BUFSZ;

	/*
	 * Save second part of target extent list
	 * (all extents past */
	if (nex2) {
		byte_diff = nex2 * sizeof(xfs_bmbt_rec_t);
		nex2_ep = (xfs_bmbt_rec_t *) kmem_alloc(byte_diff, KM_NOFS);
		memmove(nex2_ep, &erp->er_extbuf[idx], byte_diff);
		erp->er_extcount -= nex2;
		xfs_iext_irec_update_extoffs(ifp, erp_idx + 1, -nex2);
		memset(&erp->er_extbuf[idx], 0, byte_diff);
	}

	/*
	 * Add the new extents to the end of the target
	 * list, then allocate new irec record(s) and
	 * extent buffer(s) as needed to store the rest
	 * of the new extents.
	 */
	ext_cnt = count;
	ext_diff = MIN(ext_cnt, (int)XFS_LINEAR_EXTS - erp->er_extcount);
	if (ext_diff) {
		erp->er_extcount += ext_diff;
		xfs_iext_irec_update_extoffs(ifp, erp_idx + 1, ext_diff);
		ext_cnt -= ext_diff;
	}
	while (ext_cnt) {
		erp_idx++;
		erp = xfs_iext_irec_new(ifp, erp_idx);
		ext_diff = MIN(ext_cnt, (int)XFS_LINEAR_EXTS);
		erp->er_extcount = ext_diff;
		xfs_iext_irec_update_extoffs(ifp, erp_idx + 1, ext_diff);
		ext_cnt -= ext_diff;
	}

	/* Add nex2 extents back to indirection array */
	if (nex2) {
		xfs_extnum_t	ext_avail;
		int		i;

		byte_diff = nex2 * sizeof(xfs_bmbt_rec_t);
		ext_avail = XFS_LINEAR_EXTS - erp->er_extcount;
		i = 0;
		/*
		 * If nex2 extents fit in the current page, append
		 * nex2_ep after the new extents.
		 */
		if (nex2 <= ext_avail) {
			i = erp->er_extcount;
		}
		/*
		 * Otherwise, check if space is available in the
		 * next page.
		 */
		else if ((erp_idx < nlists - 1) &&
			 (nex2 <= (ext_avail = XFS_LINEAR_EXTS -
			  ifp->if_u1.if_ext_irec[erp_idx+1].er_extcount))) {
			erp_idx++;
			erp++;
			/* Create a hole for nex2 extents */
			memmove(&erp->er_extbuf[nex2], erp->er_extbuf,
				erp->er_extcount * sizeof(xfs_bmbt_rec_t));
		}
		/*
		 * Final choice, create a new extent page for
		 * nex2 extents.
		 */
		else {
			erp_idx++;
			erp = xfs_iext_irec_new(ifp, erp_idx);
		}
		memmove(&erp->er_extbuf[i], nex2_ep, byte_diff);
		kmem_free(nex2_ep);
		erp->er_extcount += nex2;
		xfs_iext_irec_update_extoffs(ifp, erp_idx + 1, nex2);
	}
}

/*
 * This is called when the amount of space required for incore file
 * extents needs to be decreased. The ext_diff parameter stores the
 * number of extents to be removed and the idx parameter contains
 * the extent index where the extents will be removed from.
 *
 * If the amount of space needed has decreased below the linear
 * limit, XFS_IEXT_BUFSZ, then switch to using the contiguous
 * extent array.  Otherwise, use kmem_realloc() to adjust the
 * size to what is needed.
 */
void
xfs_iext_remove(
	xfs_inode_t	*ip,		/* incore inode pointer */
	xfs_extnum_t	idx,		/* index to begin removing exts */
	int		ext_diff,	/* number of extents to remove */
	int		state)		/* type of extent conversion */
{
	xfs_ifork_t	*ifp = (state & BMAP_ATTRFORK) ? ip->i_afp : &ip->i_df;
	xfs_extnum_t	nextents;	/* number of extents in file */
	int		new_size;	/* size of extents after removal */

	trace_xfs_iext_remove(ip, idx, state, _RET_IP_);

	ASSERT(ext_diff > 0);
	nextents = ifp->if_bytes / (uint)sizeof(xfs_bmbt_rec_t);
	new_size = (nextents - ext_diff) * sizeof(xfs_bmbt_rec_t);

	if (new_size == 0) {
		xfs_iext_destroy(ifp);
	} else if (ifp->if_flags & XFS_IFEXTIREC) {
		xfs_iext_remove_indirect(ifp, idx, ext_diff);
	} else if (ifp->if_real_bytes) {
		xfs_iext_remove_direct(ifp, idx, ext_diff);
	} else {
		xfs_iext_remove_inline(ifp, idx, ext_diff);
	}
	ifp->if_bytes = new_size;
}

/*
 * This removes ext_diff extents from the inline buffer, beginning
 * at extent index idx.
 */
void
xfs_iext_remove_inline(
	xfs_ifork_t	*ifp,		/* inode fork pointer */
	xfs_extnum_t	idx,		/* index to begin removing exts */
	int		ext_diff)	/* number of extents to remove */
{
	int		nextents;	/* number of extents in file */

	ASSERT(!(ifp->if_flags & XFS_IFEXTIREC));
	ASSERT(idx < XFS_INLINE_EXTS);
	nextents = ifp->if_bytes / (uint)sizeof(xfs_bmbt_rec_t);
	ASSERT(((nextents - ext_diff) > 0) &&
		(nextents - ext_diff) < XFS_INLINE_EXTS);

	if (idx + ext_diff < nextents) {
		memmove(&ifp->if_u2.if_inline_ext[idx],
			&ifp->if_u2.if_inline_ext[idx + ext_diff],
			(nextents - (idx + ext_diff)) *
			 sizeof(xfs_bmbt_rec_t));
		memset(&ifp->if_u2.if_inline_ext[nextents - ext_diff],
			0, ext_diff * sizeof(xfs_bmbt_rec_t));
	} else {
		memset(&ifp->if_u2.if_inline_ext[idx], 0,
			ext_diff * sizeof(xfs_bmbt_rec_t));
	}
}

/*
 * This removes ext_diff extents from a linear (direct) extent list,
 * beginning at extent index idx. If the extents are being removed
 * from the end of the list (ie. truncate) then we just need to re-
 * allocate the list to remove the extra space. Otherwise, if the
 * extents are being removed from the middle of the existing extent
 * entries, then we first need to move the extent records beginning
 * at idx + ext_diff up in the list to overwrite the records being
 * removed, then remove the extra space via kmem_realloc.
 */
void
xfs_iext_remove_direct(
	xfs_ifork_t	*ifp,		/* inode fork pointer */
	xfs_extnum_t	idx,		/* index to begin removing exts */
	int		ext_diff)	/* number of extents to remove */
{
	xfs_extnum_t	nextents;	/* number of extents in file */
	int		new_size;	/* size of extents after removal */

	ASSERT(!(ifp->if_flags & XFS_IFEXTIREC));
	new_size = ifp->if_bytes -
		(ext_diff * sizeof(xfs_bmbt_rec_t));
	nextents = ifp->if_bytes / (uint)sizeof(xfs_bmbt_rec_t);

	if (new_size == 0) {
		xfs_iext_destroy(ifp);
		return;
	}
	/* Move extents up in the list (if needed) */
	if (idx + ext_diff < nextents) {
		memmove(&ifp->if_u1.if_extents[idx],
			&ifp->if_u1.if_extents[idx + ext_diff],
			(nextents - (idx + ext_diff)) *
			 sizeof(xfs_bmbt_rec_t));
	}
	memset(&ifp->if_u1.if_extents[nextents - ext_diff],
		0, ext_diff * sizeof(xfs_bmbt_rec_t));
	/*
	 * Reallocate the direct extent list. If the extents
	 * will fit inside the inode then xfs_iext_realloc_direct
	 * will switch from direct to inline extent allocation
	 * mode for us.
	 */
	xfs_iext_realloc_direct(ifp, new_size);
	ifp->if_bytes = new_size;
}

/*
 * This is called when incore extents are being removed from the
 * indirection array and the extents being removed span multiple extent
 * buffers. The idx parameter contains the file extent index where we
 * want to begin removing extents, and the count parameter contains
 * how many extents need to be removed.
 *
 *    |-------|   |-------|
 *    | nex1  |   |       |    nex1 - number of extents before idx
 *    |-------|   | count |
 *    |       |   |       |    count - number of extents being removed at idx
 *    | count |   |-------|
 *    |       |   | nex2  |    nex2 - number of extents after idx + count
 *    |-------|   |-------|
 */
void
xfs_iext_remove_indirect(
	xfs_ifork_t	*ifp,		/* inode fork pointer */
	xfs_extnum_t	idx,		/* index to begin removing extents */
	int		count)		/* number of extents to remove */
{
	xfs_ext_irec_t	*erp;		/* indirection array pointer */
	int		erp_idx = 0;	/* indirection array index */
	xfs_extnum_t	ext_cnt;	/* extents left to remove */
	xfs_extnum_t	ext_diff;	/* extents to remove in current list */
	xfs_extnum_t	nex1;		/* number of extents before idx */
	xfs_extnum_t	nex2;		/* extents after idx + count */
	int		page_idx = idx;	/* index in target extent list */

	ASSERT(ifp->if_flags & XFS_IFEXTIREC);
	erp = xfs_iext_idx_to_irec(ifp,  &page_idx, &erp_idx, 0);
	ASSERT(erp != NULL);
	nex1 = page_idx;
	ext_cnt = count;
	while (ext_cnt) {
		nex2 = MAX((erp->er_extcount - (nex1 + ext_cnt)), 0);
		ext_diff = MIN(ext_cnt, (erp->er_extcount - nex1));
		/*
		 * Check for deletion of entire list;
		 * xfs_iext_irec_remove() updates extent offsets.
		 */
		if (ext_diff == erp->er_extcount) {
			xfs_iext_irec_remove(ifp, erp_idx);
			ext_cnt -= ext_diff;
			nex1 = 0;
			if (ext_cnt) {
				ASSERT(erp_idx < ifp->if_real_bytes /
					XFS_IEXT_BUFSZ);
				erp = &ifp->if_u1.if_ext_irec[erp_idx];
				nex1 = 0;
				continue;
			} else {
				break;
			}
		}
		/* Move extents up (if needed) */
		if (nex2) {
			memmove(&erp->er_extbuf[nex1],
				&erp->er_extbuf[nex1 + ext_diff],
				nex2 * sizeof(xfs_bmbt_rec_t));
		}
		/* Zero out rest of page */
		memset(&erp->er_extbuf[nex1 + nex2], 0, (XFS_IEXT_BUFSZ -
			((nex1 + nex2) * sizeof(xfs_bmbt_rec_t))));
		/* Update remaining counters */
		erp->er_extcount -= ext_diff;
		xfs_iext_irec_update_extoffs(ifp, erp_idx + 1, -ext_diff);
		ext_cnt -= ext_diff;
		nex1 = 0;
		erp_idx++;
		erp++;
	}
	ifp->if_bytes -= count * sizeof(xfs_bmbt_rec_t);
	xfs_iext_irec_compact(ifp);
}

/*
 * Create, destroy, or resize a linear (direct) block of extents.
 */
void
xfs_iext_realloc_direct(
	xfs_ifork_t	*ifp,		/* inode fork pointer */
	int		new_size)	/* new size of extents */
{
	int		rnew_size;	/* real new size of extents */

	rnew_size = new_size;

	ASSERT(!(ifp->if_flags & XFS_IFEXTIREC) ||
		((new_size >= 0) && (new_size <= XFS_IEXT_BUFSZ) &&
		 (new_size != ifp->if_real_bytes)));

	/* Free extent records */
	if (new_size == 0) {
		xfs_iext_destroy(ifp);
	}
	/* Resize direct extent list and zero any new bytes */
	else if (ifp->if_real_bytes) {
		/* Check if extents will fit inside the inode */
		if (new_size <= XFS_INLINE_EXTS * sizeof(xfs_bmbt_rec_t)) {
			xfs_iext_direct_to_inline(ifp, new_size /
				(uint)sizeof(xfs_bmbt_rec_t));
			ifp->if_bytes = new_size;
			return;
		}
		if (!is_power_of_2(new_size)){
			rnew_size = roundup_pow_of_two(new_size);
		}
		if (rnew_size != ifp->if_real_bytes) {
			ifp->if_u1.if_extents =
				kmem_realloc(ifp->if_u1.if_extents,
						rnew_size,
						ifp->if_real_bytes, KM_NOFS);
		}
		if (rnew_size > ifp->if_real_bytes) {
			memset(&ifp->if_u1.if_extents[ifp->if_bytes /
				(uint)sizeof(xfs_bmbt_rec_t)], 0,
				rnew_size - ifp->if_real_bytes);
		}
	}
	/*
	 * Switch from the inline extent buffer to a direct
	 * extent list. Be sure to include the inline extent
	 * bytes in new_size.
	 */
	else {
		new_size += ifp->if_bytes;
		if (!is_power_of_2(new_size)) {
			rnew_size = roundup_pow_of_two(new_size);
		}
		xfs_iext_inline_to_direct(ifp, rnew_size);
	}
	ifp->if_real_bytes = rnew_size;
	ifp->if_bytes = new_size;
}

/*
 * Switch from linear (direct) extent records to inline buffer.
 */
void
xfs_iext_direct_to_inline(
	xfs_ifork_t	*ifp,		/* inode fork pointer */
	xfs_extnum_t	nextents)	/* number of extents in file */
{
	ASSERT(ifp->if_flags & XFS_IFEXTENTS);
	ASSERT(nextents <= XFS_INLINE_EXTS);
	/*
	 * The inline buffer was zeroed when we switched
	 * from inline to direct extent allocation mode,
	 * so we don't need to clear it here.
	 */
	memcpy(ifp->if_u2.if_inline_ext, ifp->if_u1.if_extents,
		nextents * sizeof(xfs_bmbt_rec_t));
	kmem_free(ifp->if_u1.if_extents);
	ifp->if_u1.if_extents = ifp->if_u2.if_inline_ext;
	ifp->if_real_bytes = 0;
}

/*
 * Switch from inline buffer to linear (direct) extent records.
 * new_size should already be rounded up to the next power of 2
 * by the caller (when appropriate), so use new_size as it is.
 * However, since new_size may be rounded up, we can't update
 * if_bytes here. It is the caller's responsibility to update
 * if_bytes upon return.
 */
void
xfs_iext_inline_to_direct(
	xfs_ifork_t	*ifp,		/* inode fork pointer */
	int		new_size)	/* number of extents in file */
{
	ifp->if_u1.if_extents = kmem_alloc(new_size, KM_NOFS);
	memset(ifp->if_u1.if_extents, 0, new_size);
	if (ifp->if_bytes) {
		memcpy(ifp->if_u1.if_extents, ifp->if_u2.if_inline_ext,
			ifp->if_bytes);
		memset(ifp->if_u2.if_inline_ext, 0, XFS_INLINE_EXTS *
			sizeof(xfs_bmbt_rec_t));
	}
	ifp->if_real_bytes = new_size;
}

/*
 * Resize an extent indirection array to new_size bytes.
 */
STATIC void
xfs_iext_realloc_indirect(
	xfs_ifork_t	*ifp,		/* inode fork pointer */
	int		new_size)	/* new indirection array size */
{
	int		nlists;		/* number of irec's (ex lists) */
	int		size;		/* current indirection array size */

	ASSERT(ifp->if_flags & XFS_IFEXTIREC);
	nlists = ifp->if_real_bytes / XFS_IEXT_BUFSZ;
	size = nlists * sizeof(xfs_ext_irec_t);
	ASSERT(ifp->if_real_bytes);
	ASSERT((new_size >= 0) && (new_size != size));
	if (new_size == 0) {
		xfs_iext_destroy(ifp);
	} else {
		ifp->if_u1.if_ext_irec = (xfs_ext_irec_t *)
			kmem_realloc(ifp->if_u1.if_ext_irec,
				new_size, size, KM_NOFS);
	}
}

/*
 * Switch from indirection array to linear (direct) extent allocations.
 */
STATIC void
xfs_iext_indirect_to_direct(
	 xfs_ifork_t	*ifp)		/* inode fork pointer */
{
	xfs_bmbt_rec_host_t *ep;	/* extent record pointer */
	xfs_extnum_t	nextents;	/* number of extents in file */
	int		size;		/* size of file extents */

	ASSERT(ifp->if_flags & XFS_IFEXTIREC);
	nextents = ifp->if_bytes / (uint)sizeof(xfs_bmbt_rec_t);
	ASSERT(nextents <= XFS_LINEAR_EXTS);
	size = nextents * sizeof(xfs_bmbt_rec_t);

	xfs_iext_irec_compact_pages(ifp);
	ASSERT(ifp->if_real_bytes == XFS_IEXT_BUFSZ);

	ep = ifp->if_u1.if_ext_irec->er_extbuf;
	kmem_free(ifp->if_u1.if_ext_irec);
	ifp->if_flags &= ~XFS_IFEXTIREC;
	ifp->if_u1.if_extents = ep;
	ifp->if_bytes = size;
	if (nextents < XFS_LINEAR_EXTS) {
		xfs_iext_realloc_direct(ifp, size);
	}
}

/*
 * Free incore file extents.
 */
void
xfs_iext_destroy(
	xfs_ifork_t	*ifp)		/* inode fork pointer */
{
	if (ifp->if_flags & XFS_IFEXTIREC) {
		int	erp_idx;
		int	nlists;

		nlists = ifp->if_real_bytes / XFS_IEXT_BUFSZ;
		for (erp_idx = nlists - 1; erp_idx >= 0 ; erp_idx--) {
			xfs_iext_irec_remove(ifp, erp_idx);
		}
		ifp->if_flags &= ~XFS_IFEXTIREC;
	} else if (ifp->if_real_bytes) {
		kmem_free(ifp->if_u1.if_extents);
	} else if (ifp->if_bytes) {
		memset(ifp->if_u2.if_inline_ext, 0, XFS_INLINE_EXTS *
			sizeof(xfs_bmbt_rec_t));
	}
	ifp->if_u1.if_extents = NULL;
	ifp->if_real_bytes = 0;
	ifp->if_bytes = 0;
}

/*
 * Return a pointer to the extent record for file system block bno.
 */
xfs_bmbt_rec_host_t *			/* pointer to found extent record */
xfs_iext_bno_to_ext(
	xfs_ifork_t	*ifp,		/* inode fork pointer */
	xfs_fileoff_t	bno,		/* block number to search for */
	xfs_extnum_t	*idxp)		/* index of target extent */
{
	xfs_bmbt_rec_host_t *base;	/* pointer to first extent */
	xfs_filblks_t	blockcount = 0;	/* number of blocks in extent */
	xfs_bmbt_rec_host_t *ep = NULL;	/* pointer to target extent */
	xfs_ext_irec_t	*erp = NULL;	/* indirection array pointer */
	int		high;		/* upper boundary in search */
	xfs_extnum_t	idx = 0;	/* index of target extent */
	int		low;		/* lower boundary in search */
	xfs_extnum_t	nextents;	/* number of file extents */
	xfs_fileoff_t	startoff = 0;	/* start offset of extent */

	nextents = ifp->if_bytes / (uint)sizeof(xfs_bmbt_rec_t);
	if (nextents == 0) {
		*idxp = 0;
		return NULL;
	}
	low = 0;
	if (ifp->if_flags & XFS_IFEXTIREC) {
		/* Find target extent list */
		int	erp_idx = 0;
		erp = xfs_iext_bno_to_irec(ifp, bno, &erp_idx);
		base = erp->er_extbuf;
		high = erp->er_extcount - 1;
	} else {
		base = ifp->if_u1.if_extents;
		high = nextents - 1;
	}
	/* Binary search extent records */
	while (low <= high) {
		idx = (low + high) >> 1;
		ep = base + idx;
		startoff = xfs_bmbt_get_startoff(ep);
		blockcount = xfs_bmbt_get_blockcount(ep);
		if (bno < startoff) {
			high = idx - 1;
		} else if (bno >= startoff + blockcount) {
			low = idx + 1;
		} else {
			/* Convert back to file-based extent index */
			if (ifp->if_flags & XFS_IFEXTIREC) {
				idx += erp->er_extoff;
			}
			*idxp = idx;
			return ep;
		}
	}
	/* Convert back to file-based extent index */
	if (ifp->if_flags & XFS_IFEXTIREC) {
		idx += erp->er_extoff;
	}
	if (bno >= startoff + blockcount) {
		if (++idx == nextents) {
			ep = NULL;
		} else {
			ep = xfs_iext_get_ext(ifp, idx);
		}
	}
	*idxp = idx;
	return ep;
}

/*
 * Return a pointer to the indirection array entry containing the
 * extent record for filesystem block bno. Store the index of the
 * target irec in *erp_idxp.
 */
xfs_ext_irec_t *			/* pointer to found extent record */
xfs_iext_bno_to_irec(
	xfs_ifork_t	*ifp,		/* inode fork pointer */
	xfs_fileoff_t	bno,		/* block number to search for */
	int		*erp_idxp)	/* irec index of target ext list */
{
	xfs_ext_irec_t	*erp = NULL;	/* indirection array pointer */
	xfs_ext_irec_t	*erp_next;	/* next indirection array entry */
	int		erp_idx;	/* indirection array index */
	int		nlists;		/* number of extent irec's (lists) */
	int		high;		/* binary search upper limit */
	int		low;		/* binary search lower limit */

	ASSERT(ifp->if_flags & XFS_IFEXTIREC);
	nlists = ifp->if_real_bytes / XFS_IEXT_BUFSZ;
	erp_idx = 0;
	low = 0;
	high = nlists - 1;
	while (low <= high) {
		erp_idx = (low + high) >> 1;
		erp = &ifp->if_u1.if_ext_irec[erp_idx];
		erp_next = erp_idx < nlists - 1 ? erp + 1 : NULL;
		if (bno < xfs_bmbt_get_startoff(erp->er_extbuf)) {
			high = erp_idx - 1;
		} else if (erp_next && bno >=
			   xfs_bmbt_get_startoff(erp_next->er_extbuf)) {
			low = erp_idx + 1;
		} else {
			break;
		}
	}
	*erp_idxp = erp_idx;
	return erp;
}

/*
 * Return a pointer to the indirection array entry containing the
 * extent record at file extent index *idxp. Store the index of the
 * target irec in *erp_idxp and store the page index of the target
 * extent record in *idxp.
 */
xfs_ext_irec_t *
xfs_iext_idx_to_irec(
	xfs_ifork_t	*ifp,		/* inode fork pointer */
	xfs_extnum_t	*idxp,		/* extent index (file -> page) */
	int		*erp_idxp,	/* pointer to target irec */
	int		realloc)	/* new bytes were just added */
{
	xfs_ext_irec_t	*prev;		/* pointer to previous irec */
	xfs_ext_irec_t	*erp = NULL;	/* pointer to current irec */
	int		erp_idx;	/* indirection array index */
	int		nlists;		/* number of irec's (ex lists) */
	int		high;		/* binary search upper limit */
	int		low;		/* binary search lower limit */
	xfs_extnum_t	page_idx = *idxp; /* extent index in target list */

	ASSERT(ifp->if_flags & XFS_IFEXTIREC);
	ASSERT(page_idx >= 0);
	ASSERT(page_idx <= ifp->if_bytes / sizeof(xfs_bmbt_rec_t));
	ASSERT(page_idx < ifp->if_bytes / sizeof(xfs_bmbt_rec_t) || realloc);

	nlists = ifp->if_real_bytes / XFS_IEXT_BUFSZ;
	erp_idx = 0;
	low = 0;
	high = nlists - 1;

	/* Binary search extent irec's */
	while (low <= high) {
		erp_idx = (low + high) >> 1;
		erp = &ifp->if_u1.if_ext_irec[erp_idx];
		prev = erp_idx > 0 ? erp - 1 : NULL;
		if (page_idx < erp->er_extoff || (page_idx == erp->er_extoff &&
		     realloc && prev && prev->er_extcount < XFS_LINEAR_EXTS)) {
			high = erp_idx - 1;
		} else if (page_idx > erp->er_extoff + erp->er_extcount ||
			   (page_idx == erp->er_extoff + erp->er_extcount &&
			    !realloc)) {
			low = erp_idx + 1;
		} else if (page_idx == erp->er_extoff + erp->er_extcount &&
			   erp->er_extcount == XFS_LINEAR_EXTS) {
			ASSERT(realloc);
			page_idx = 0;
			erp_idx++;
			erp = erp_idx < nlists ? erp + 1 : NULL;
			break;
		} else {
			page_idx -= erp->er_extoff;
			break;
		}
	}
	*idxp = page_idx;
	*erp_idxp = erp_idx;
	return(erp);
}

/*
 * Allocate and initialize an indirection array once the space needed
 * for incore extents increases above XFS_IEXT_BUFSZ.
 */
void
xfs_iext_irec_init(
	xfs_ifork_t	*ifp)		/* inode fork pointer */
{
	xfs_ext_irec_t	*erp;		/* indirection array pointer */
	xfs_extnum_t	nextents;	/* number of extents in file */

	ASSERT(!(ifp->if_flags & XFS_IFEXTIREC));
	nextents = ifp->if_bytes / (uint)sizeof(xfs_bmbt_rec_t);
	ASSERT(nextents <= XFS_LINEAR_EXTS);

	erp = kmem_alloc(sizeof(xfs_ext_irec_t), KM_NOFS);

	if (nextents == 0) {
		ifp->if_u1.if_extents = kmem_alloc(XFS_IEXT_BUFSZ, KM_NOFS);
	} else if (!ifp->if_real_bytes) {
		xfs_iext_inline_to_direct(ifp, XFS_IEXT_BUFSZ);
	} else if (ifp->if_real_bytes < XFS_IEXT_BUFSZ) {
		xfs_iext_realloc_direct(ifp, XFS_IEXT_BUFSZ);
	}
	erp->er_extbuf = ifp->if_u1.if_extents;
	erp->er_extcount = nextents;
	erp->er_extoff = 0;

	ifp->if_flags |= XFS_IFEXTIREC;
	ifp->if_real_bytes = XFS_IEXT_BUFSZ;
	ifp->if_bytes = nextents * sizeof(xfs_bmbt_rec_t);
	ifp->if_u1.if_ext_irec = erp;

	return;
}

/*
 * Allocate and initialize a new entry in the indirection array.
 */
xfs_ext_irec_t *
xfs_iext_irec_new(
	xfs_ifork_t	*ifp,		/* inode fork pointer */
	int		erp_idx)	/* index for new irec */
{
	xfs_ext_irec_t	*erp;		/* indirection array pointer */
	int		i;		/* loop counter */
	int		nlists;		/* number of irec's (ex lists) */

	ASSERT(ifp->if_flags & XFS_IFEXTIREC);
	nlists = ifp->if_real_bytes / XFS_IEXT_BUFSZ;

	/* Resize indirection array */
	xfs_iext_realloc_indirect(ifp, ++nlists *
				  sizeof(xfs_ext_irec_t));
	/*
	 * Move records down in the array so the
	 * new page can use erp_idx.
	 */
	erp = ifp->if_u1.if_ext_irec;
	for (i = nlists - 1; i > erp_idx; i--) {
		memmove(&erp[i], &erp[i-1], sizeof(xfs_ext_irec_t));
	}
	ASSERT(i == erp_idx);

	/* Initialize new extent record */
	erp = ifp->if_u1.if_ext_irec;
	erp[erp_idx].er_extbuf = kmem_alloc(XFS_IEXT_BUFSZ, KM_NOFS);
	ifp->if_real_bytes = nlists * XFS_IEXT_BUFSZ;
	memset(erp[erp_idx].er_extbuf, 0, XFS_IEXT_BUFSZ);
	erp[erp_idx].er_extcount = 0;
	erp[erp_idx].er_extoff = erp_idx > 0 ?
		erp[erp_idx-1].er_extoff + erp[erp_idx-1].er_extcount : 0;
	return (&erp[erp_idx]);
}

/*
 * Remove a record from the indirection array.
 */
void
xfs_iext_irec_remove(
	xfs_ifork_t	*ifp,		/* inode fork pointer */
	int		erp_idx)	/* irec index to remove */
{
	xfs_ext_irec_t	*erp;		/* indirection array pointer */
	int		i;		/* loop counter */
	int		nlists;		/* number of irec's (ex lists) */

	ASSERT(ifp->if_flags & XFS_IFEXTIREC);
	nlists = ifp->if_real_bytes / XFS_IEXT_BUFSZ;
	erp = &ifp->if_u1.if_ext_irec[erp_idx];
	if (erp->er_extbuf) {
		xfs_iext_irec_update_extoffs(ifp, erp_idx + 1,
			-erp->er_extcount);
		kmem_free(erp->er_extbuf);
	}
	/* Compact extent records */
	erp = ifp->if_u1.if_ext_irec;
	for (i = erp_idx; i < nlists - 1; i++) {
		memmove(&erp[i], &erp[i+1], sizeof(xfs_ext_irec_t));
	}
	/*
	 * Manually free the last extent record from the indirection
	 * array.  A call to xfs_iext_realloc_indirect() with a size
	 * of zero would result in a call to xfs_iext_destroy() which
	 * would in turn call this function again, creating a nasty
	 * infinite loop.
	 */
	if (--nlists) {
		xfs_iext_realloc_indirect(ifp,
			nlists * sizeof(xfs_ext_irec_t));
	} else {
		kmem_free(ifp->if_u1.if_ext_irec);
	}
	ifp->if_real_bytes = nlists * XFS_IEXT_BUFSZ;
}

/*
 * This is called to clean up large amounts of unused memory allocated
 * by the indirection array.  Before compacting anything though, verify
 * that the indirection array is still needed and switch back to the
 * linear extent list (or even the inline buffer) if possible.  The
 * compaction policy is as follows:
 *
 *    Full Compaction: Extents fit into a single page (or inline buffer)
 * Partial Compaction: Extents occupy less than 50% of allocated space
 *      No Compaction: Extents occupy at least 50% of allocated space
 */
void
xfs_iext_irec_compact(
	xfs_ifork_t	*ifp)		/* inode fork pointer */
{
	xfs_extnum_t	nextents;	/* number of extents in file */
	int		nlists;		/* number of irec's (ex lists) */

	ASSERT(ifp->if_flags & XFS_IFEXTIREC);
	nlists = ifp->if_real_bytes / XFS_IEXT_BUFSZ;
	nextents = ifp->if_bytes / (uint)sizeof(xfs_bmbt_rec_t);

	if (nextents == 0) {
		xfs_iext_destroy(ifp);
	} else if (nextents <= XFS_INLINE_EXTS) {
		xfs_iext_indirect_to_direct(ifp);
		xfs_iext_direct_to_inline(ifp, nextents);
	} else if (nextents <= XFS_LINEAR_EXTS) {
		xfs_iext_indirect_to_direct(ifp);
	} else if (nextents < (nlists * XFS_LINEAR_EXTS) >> 1) {
		xfs_iext_irec_compact_pages(ifp);
	}
}

/*
 * Combine extents from neighboring extent pages.
 */
void
xfs_iext_irec_compact_pages(
	xfs_ifork_t	*ifp)		/* inode fork pointer */
{
	xfs_ext_irec_t	*erp, *erp_next;/* pointers to irec entries */
	int		erp_idx = 0;	/* indirection array index */
	int		nlists;		/* number of irec's (ex lists) */

	ASSERT(ifp->if_flags & XFS_IFEXTIREC);
	nlists = ifp->if_real_bytes / XFS_IEXT_BUFSZ;
	while (erp_idx < nlists - 1) {
		erp = &ifp->if_u1.if_ext_irec[erp_idx];
		erp_next = erp + 1;
		if (erp_next->er_extcount <=
		    (XFS_LINEAR_EXTS - erp->er_extcount)) {
			memcpy(&erp->er_extbuf[erp->er_extcount],
				erp_next->er_extbuf, erp_next->er_extcount *
				sizeof(xfs_bmbt_rec_t));
			erp->er_extcount += erp_next->er_extcount;
			/*
			 * Free page before removing extent record
			 * so er_extoffs don't get modified in
			 * xfs_iext_irec_remove.
			 */
			kmem_free(erp_next->er_extbuf);
			erp_next->er_extbuf = NULL;
			xfs_iext_irec_remove(ifp, erp_idx + 1);
			nlists = ifp->if_real_bytes / XFS_IEXT_BUFSZ;
		} else {
			erp_idx++;
		}
	}
}

/*
 * This is called to update the er_extoff field in the indirection
 * array when extents have been added or removed from one of the
 * extent lists. erp_idx contains the irec index to begin updating
 * at and ext_diff contains the number of extents that were added
 * or removed.
 */
void
xfs_iext_irec_update_extoffs(
	xfs_ifork_t	*ifp,		/* inode fork pointer */
	int		erp_idx,	/* irec index to update */
	int		ext_diff)	/* number of new extents */
{
	int		i;		/* loop counter */
	int		nlists;		/* number of irec's (ex lists */

	ASSERT(ifp->if_flags & XFS_IFEXTIREC);
	nlists = ifp->if_real_bytes / XFS_IEXT_BUFSZ;
	for (i = erp_idx; i < nlists; i++) {
		ifp->if_u1.if_ext_irec[i].er_extoff += ext_diff;
	}
}

