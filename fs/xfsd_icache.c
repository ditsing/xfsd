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
#include "xfs/xfs_log.h"
#include "xfs/xfs_inum.h"
#include "xfs/xfs_trans.h"
#include "xfs/xfs_trans_priv.h"
#include "xfs/xfs_sb.h"
#include "xfs/xfs_ag.h"
#include "xfs/xfs_mount.h"
#include "xfs/xfs_bmap_btree.h"
#include "xfs/xfs_inode.h"
#include "xfs/xfs_dinode.h"
#include "xfs/xfs_error.h"
#include "xfs/xfs_filestream.h"
#include "xfs/xfs_vnodeops.h"
#include "xfs/xfs_inode_item.h"
#include "xfs/xfs_quota.h"

#include "xfsd_trace.h"
#include "xfs/xfs_fsops.h"
#include "xfs/xfs_icache.h"

/*
 * Allocate and initialise an xfs_inode.
 */
STATIC struct xfs_inode *
xfs_inode_alloc(
	struct xfs_mount	*mp,
	xfs_ino_t		ino)
{
	struct xfs_inode	*ip;

	/*
	 * if this didn't occur in transactions, we could use
	 * KM_MAYFAIL and return NULL here on ENOMEM. Set the
	 * code up to do this anyway.
	 */
	ip = kmem_zone_alloc(xfs_inode_zone, KM_SLEEP);
	if (!ip)
		return NULL;
	/*
	 * Comment out.
	 * Wo do not use kernel inode.
	 */
	/*
	if (inode_init_always(mp->m_super, VFS_I(ip))) {
		kmem_zone_free(xfs_inode_zone, ip);
		return NULL;
	}
	*/

	ASSERT(atomic_read(&ip->i_pincount) == 0);
	ASSERT(!spin_is_locked(&ip->i_flags_lock));
	ASSERT(!xfs_isiflocked(ip));
	ASSERT(ip->i_ino == 0);

	mrlock_init(&ip->i_iolock, MRLOCK_BARRIER, "xfsio", ip->i_ino);

	/* initialise the xfs inode */
	ip->i_ino = ino;
	ip->i_mount = mp;
	memset(&ip->i_imap, 0, sizeof(struct xfs_imap));
	ip->i_afp = NULL;
	memset(&ip->i_df, 0, sizeof(xfs_ifork_t));
	ip->i_flags = 0;
	ip->i_delayed_blks = 0;
	memset(&ip->i_d, 0, sizeof(xfs_icdinode_t));

	return ip;
}

STATIC void
xfs_inode_free_callback(
	struct rcu_head		*head)
{
	struct inode		*inode = container_of(head, struct inode, i_rcu);
	struct xfs_inode	*ip = XFS_I(inode);

	kmem_zone_free(xfs_inode_zone, ip);
}

STATIC void
xfs_inode_free(
	struct xfs_inode	*ip)
{
	switch (ip->i_d.di_mode & S_IFMT) {
	case S_IFREG:
	case S_IFDIR:
	case S_IFLNK:
		xfs_idestroy_fork(ip, XFS_DATA_FORK);
		break;
	}

	if (ip->i_afp)
		xfs_idestroy_fork(ip, XFS_ATTR_FORK);

	/*
	 * Comment out.
	 * Could be no item on any inode.
	 */
	/*
	if (ip->i_itemp) {
		ASSERT(!(ip->i_itemp->ili_item.li_flags & XFS_LI_IN_AIL));
		xfs_inode_item_destroy(ip);
		ip->i_itemp = NULL;
	}
	*/

	/* asserts to verify all state is correct here */
	ASSERT(atomic_read(&ip->i_pincount) == 0);
	ASSERT(!spin_is_locked(&ip->i_flags_lock));
	ASSERT(!xfs_isiflocked(ip));

	/*
	 * Because we use RCU freeing we need to ensure the inode always
	 * appears to be reclaimed with an invalid inode number when in the
	 * free state. The ip->i_flags_lock provides the barrier against lookup
	 * races.
	 */
	spin_lock(&ip->i_flags_lock);
	ip->i_flags = XFS_IRECLAIM;
	ip->i_ino = 0;
	spin_unlock(&ip->i_flags_lock);

	call_rcu(&VFS_I(ip)->i_rcu, xfs_inode_free_callback);
}

/*
 * See xfs_inode_setup in xfs_iops.c to find out how
 * to extract information from ip->i_d
 */
int
xfs_iget(
	struct xfs_mount	*mp,
	xfs_trans_t		*tp,
	xfs_ino_t		ino,
	uint			flags,
	uint			lock_flags,
	xfs_inode_t **ipp)
{
	struct xfs_inode	*ip;
	int			error;
	xfs_agino_t		agino = XFS_INO_TO_AGINO(mp, ino);
	int			iflags;

	ip = xfs_inode_alloc(mp, ino);
	if (!ip)
		return ENOMEM;

	error = xfs_iread(mp, tp, ip, flags);
	if (error)
		goto out_destroy;

	trace_xfs_iget_miss(ip);

	if ((ip->i_d.di_mode == 0) && !(flags & XFS_IGET_CREATE)) {
		error = ENOENT;
		goto out_destroy;
	}

	iflags = XFS_INEW;
	if (flags & XFS_IGET_DONTCACHE)
		iflags |= XFS_IDONTCACHE;
	ip->i_udquot = ip->i_gdquot = NULL;
	xfs_iflags_set(ip, iflags);

	*ipp = ip;
	return 0;

out_destroy:
	xfs_inode_free(ip);
	return error;
}

int xfs_iput(
	struct xfs_inode	*ip)
{
	// There's something wrong here.
	xfs_inode_free(ip);
	return 1;
}

