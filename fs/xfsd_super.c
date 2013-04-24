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
#include "xfs/xfs_rtalloc.h"
#include "xfs/xfs_error.h"
#include "xfs/xfs_attr.h"
#include "xfs/xfs_buf_item.h"
#include "xfs/xfs_utils.h"
#include "xfs/xfs_filestream.h"
#include "xfs/xfs_da_btree.h"
#include "xfs/xfs_extfree_item.h"
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

int xfs_fs_init()
{
	struct inode		*root;
	struct xfs_mount	*mp = NULL;
	int			flags = 0, error = ENOMEM;

	mp = kmem_zalloc(sizeof(struct xfs_mount), KM_NOFS);
	if (!mp)
		goto out;

	spin_lock_init(&mp->m_sb_lock);
	mutex_init(&mp->m_growlock);
	atomic_set(&mp->m_active_trans, 0);
	INIT_DELAYED_WORK(&mp->m_reclaim_work, xfs_reclaim_worker);
	INIT_DELAYED_WORK(&mp->m_eofblocks_work, xfs_eofblocks_worker);

	mp->m_super = NULL;

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
 out_free_sb:
	xfs_freesb(mp);
 out_free_mp:
	kfree(mp);
 out:
	return -error;
}
