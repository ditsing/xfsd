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

#include "xfs/xfs_types.h"
#include "xfs/xfs_fs.h"
#include "xfs/xfs_log.h"
#include "xfs/xfs_inum.h"
#include "xfs/xfs_trans.h"
#include "xfs/xfs_sb.h"
#include "xfs/xfs_ag.h"
#include "xfs/xfs_dir2.h"
#include "xfs/xfs_alloc.h"
#include "xfs/xfs_quota.h"
#include "xfs/xfs_mount.h"
#include "xfs/xfs_bmap_btree.h"
#include "xfs/xfs_alloc_btree.h"
#include "xfs/xfs_ialloc_btree.h"
#include "xfs/xfs_dinode.h"
#include "xfs/xfs_inode.h"
#include "xfs/xfs_btree.h"
#include "xfs/xfs_ialloc.h"
#include "xfs/xfs_bmap.h"
#include "xfs/xfs_rtalloc.h"
#include "xfs/xfs_error.h"
#include "xfs/xfs_attr.h"
#include "xfs/xfs_buf_item.h"
#include "xfs/xfs_utils.h"
#include "xfs/xfs_filestream.h"
#include "xfs/xfs_da_btree.h"
#include "xfs/xfs_mru_cache.h"
#include "xfs/xfs_inode_item.h"

#include "xfsd_trace.h"

xfs_agnumber_t
xfs_set_inode32(struct xfs_mount *mp)
{
	xfs_agnumber_t	index = 0;
	xfs_agnumber_t	maxagi = 0;
	xfs_sb_t	*sbp = &mp->m_sb;
	xfs_agnumber_t	max_metadata;
	xfs_agino_t	agino =	XFS_OFFBNO_TO_AGINO(mp, sbp->sb_agblocks -1, 0);
	xfs_ino_t	ino = XFS_AGINO_TO_INO(mp, sbp->sb_agcount -1, agino);
	xfs_perag_t	*pag;

	/* Calculate how much should be reserved for inodes to meet
	 * the max inode percentage.
	 */
	if (mp->m_maxicount) {
		__uint64_t	icount;

		icount = sbp->sb_dblocks * sbp->sb_imax_pct;
		do_div(icount, 100);
		icount += sbp->sb_agblocks - 1;
		do_div(icount, sbp->sb_agblocks);
		max_metadata = icount;
	} else {
		max_metadata = sbp->sb_agcount;
	}

	for (index = 0; index < sbp->sb_agcount; index++) {
		ino = XFS_AGINO_TO_INO(mp, index, agino);

		if (ino > XFS_MAXINUMBER_32) {
			pag = xfs_perag_get(mp, index);
			pag->pagi_inodeok = 0;
			pag->pagf_metadata = 0;
			xfs_perag_put(pag);
			continue;
		}

		pag = xfs_perag_get(mp, index);
		pag->pagi_inodeok = 1;
		maxagi++;
		if (index < max_metadata)
			pag->pagf_metadata = 1;
		xfs_perag_put(pag);
	}
	mp->m_flags |= (XFS_MOUNT_32BITINODES |
			XFS_MOUNT_SMALL_INUMS);

	return maxagi;
}

xfs_agnumber_t
xfs_set_inode64(struct xfs_mount *mp)
{
	xfs_agnumber_t index = 0;

	for (index = 0; index < mp->m_sb.sb_agcount; index++) {
		struct xfs_perag	*pag;

		pag = xfs_perag_get(mp, index);
		pag->pagi_inodeok = 1;
		pag->pagf_metadata = 0;
		xfs_perag_put(pag);
	}

	/* There is no need for lock protection on m_flags,
	 * the rw_semaphore of the VFS superblock is locked
	 * during mount/umount/remount operations, so this is
	 * enough to avoid concurency on the m_flags field
	 */
	mp->m_flags &= ~(XFS_MOUNT_32BITINODES |
			 XFS_MOUNT_SMALL_INUMS);
	return index;
}

/*
 * Slab object creation initialisation for the XFS inode.
 * This covers only the idempotent fields in the XFS inode;
 * all other fields need to be initialised on allocation
 * from the slab. This avoids the need to repeatedly initialise
 * fields in the xfs inode that left in the initialise state
 * when freeing the inode.
 */
STATIC void
xfs_fs_inode_init_once(
	void			*inode)
{
	struct xfs_inode	*ip = inode;

	memset(ip, 0, sizeof(struct xfs_inode));

	/* xfs inode */
	atomic_set(&ip->i_pincount, 0);
	spin_lock_init(&ip->i_flags_lock);

	mrlock_init(&ip->i_lock, MRLOCK_ALLOW_EQUAL_PRI|MRLOCK_BARRIER,
		     "xfsino", ip->i_ino);
}

STATIC int __init
xfs_init_zones(void)
{

	xfs_bmap_free_item_zone = kmem_zone_init(sizeof(xfs_bmap_free_item_t),
						"xfs_bmap_free_item");
	if (!xfs_bmap_free_item_zone)
		goto out_destroy_log_ticket_zone;

	xfs_btree_cur_zone = kmem_zone_init(sizeof(xfs_btree_cur_t),
						"xfs_btree_cur");
	if (!xfs_btree_cur_zone)
		goto out_destroy_bmap_free_item_zone;

	xfs_da_state_zone = kmem_zone_init(sizeof(xfs_da_state_t),
						"xfs_da_state");
	if (!xfs_da_state_zone)
		goto out_destroy_btree_cur_zone;

	xfs_ifork_zone = kmem_zone_init(sizeof(xfs_ifork_t), "xfs_ifork");
	if (!xfs_ifork_zone)
		goto out_destroy_da_state_zone;

	/*
	 * The size of the zone allocated buf log item is the maximum
	 * size possible under XFS.  This wastes a little bit of memory,
	 * but it is much faster.
	 */
	xfs_inode_zone =
		kmem_zone_init_flags(sizeof(xfs_inode_t), "xfs_inode",
			KM_ZONE_HWALIGN | KM_ZONE_RECLAIM | KM_ZONE_SPREAD,
			xfs_fs_inode_init_once);
	if (!xfs_inode_zone)
		goto out_destroy_efi_zone;

	return 0;

 out_destroy_efi_zone:
	kmem_zone_destroy(xfs_ifork_zone);
 out_destroy_da_state_zone:
	kmem_zone_destroy(xfs_da_state_zone);
 out_destroy_btree_cur_zone:
	kmem_zone_destroy(xfs_btree_cur_zone);
 out_destroy_bmap_free_item_zone:
	kmem_zone_destroy(xfs_bmap_free_item_zone);
 out_destroy_log_ticket_zone:
	return -ENOMEM;
}

STATIC void
xfs_destroy_zones(void)
{
	kmem_zone_destroy(xfs_inode_zone);
	kmem_zone_destroy(xfs_ifork_zone);
	kmem_zone_destroy(xfs_da_state_zone);
	kmem_zone_destroy(xfs_btree_cur_zone);
	kmem_zone_destroy(xfs_bmap_free_item_zone);

}

int xfs_fs_init()
{
	int			error;

	xfs_dir_startup();

	error = xfs_init_zones();
	if (error)
		goto out;

	error = xfs_buf_init();
	if (error)
		goto out_filestream_uninit;

	return 0;

 out_filestream_uninit:
	xfs_destroy_zones();
 out:
	return error;

}

int xfs_fs_exit()
{
	xfs_buf_terminate();
	xfs_destroy_zones();
	return 0;
}

STATIC void
xfs_free_fsname(
	struct xfs_mount	*mp)
{
	kfree(mp->m_fsname);
	kfree(mp->m_rtname);
	kfree(mp->m_logname);
}

int xfs_mount( struct xfs_mount **mpp)
{
	struct xfs_mount	*mp = NULL;
	int			flags = 0, error = ENOMEM;

	mp = kmem_zalloc(sizeof(struct xfs_mount), KM_NOFS);
	if (!mp)
		goto out;

	spin_lock_init(&mp->m_sb_lock);
	mutex_init(&mp->m_growlock);
	atomic_set(&mp->m_active_trans, 0);

	mp->m_super = NULL;

	mp->m_ddev_targp = xfs_alloc_buftarg(mp, NULL, 0, mp->m_fsname);

	error = xfs_readsb(mp, flags);
	if (error)
		goto out_free_mp;
	/*
	 * we must configure the block size in the superblock before we run the
	 * full mount process as the mount process can lookup and cache inodes.
	 */
	error = xfs_mountfs(mp);
	if ( error)
		goto out_free_sb;

	*mpp = mp;

	return 0;

 out_free_sb:
	xfs_freesb(mp);
 out_free_mp:
	/*
	xfs_free_fsname(mp);
	*/
	kfree(mp);
 out:
	return -error;
}

int xfs_unmount( struct xfs_mount **mpp)
{
	struct xfs_mount	*mp = *mpp;
	xfs_unmountfs(mp);
	xfs_freesb(mp);
	/*
	xfs_free_fsname(mp);
	*/
	return 0;
}
