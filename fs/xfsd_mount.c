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
#include "xfs/xfs_inum.h"
#include "xfs/xfs_trans.h"
#include "xfs/xfs_trans_priv.h"
#include "xfs/xfs_sb.h"
#include "xfs/xfs_ag.h"
#include "xfs/xfs_dir2.h"
#include "xfs/xfs_mount.h"
#include "xfs/xfs_bmap_btree.h"
#include "xfs/xfs_alloc_btree.h"
#include "xfs/xfs_ialloc_btree.h"
#include "xfs/xfs_dinode.h"
#include "xfs/xfs_inode.h"
#include "xfs/xfs_btree.h"
#include "xfs/xfs_ialloc.h"
#include "xfs/xfs_alloc.h"
#include "xfs/xfs_rtalloc.h"
#include "xfs/xfs_bmap.h"
#include "xfs/xfs_error.h"
#include "xfs/xfs_quota.h"
#include "xfs/xfs_fsops.h"
#include "xfs/xfs_utils.h"

#include "xfsd_trace.h"
#include "xfs/xfs_icache.h"


#ifdef HAVE_PERCPU_SB
STATIC void	xfs_icsb_balance_counter(xfs_mount_t *, xfs_sb_field_t,
						int);
STATIC void	xfs_icsb_balance_counter_locked(xfs_mount_t *, xfs_sb_field_t,
						int);
STATIC void	xfs_icsb_disable_counter(xfs_mount_t *, xfs_sb_field_t);
#else

#define xfs_icsb_balance_counter(mp, a, b)		do { } while (0)
#define xfs_icsb_balance_counter_locked(mp, a, b)	do { } while (0)
#endif

static const struct {
	short offset;
	short type;	/* 0 = integer
			 * 1 = binary / string (no translation)
			 */
} xfs_sb_info[] = {
    { offsetof(xfs_sb_t, sb_magicnum),   0 },
    { offsetof(xfs_sb_t, sb_blocksize),  0 },
    { offsetof(xfs_sb_t, sb_dblocks),    0 },
    { offsetof(xfs_sb_t, sb_rblocks),    0 },
    { offsetof(xfs_sb_t, sb_rextents),   0 },
    { offsetof(xfs_sb_t, sb_uuid),       1 },
    { offsetof(xfs_sb_t, sb_logstart),   0 },
    { offsetof(xfs_sb_t, sb_rootino),    0 },
    { offsetof(xfs_sb_t, sb_rbmino),     0 },
    { offsetof(xfs_sb_t, sb_rsumino),    0 },
    { offsetof(xfs_sb_t, sb_rextsize),   0 },
    { offsetof(xfs_sb_t, sb_agblocks),   0 },
    { offsetof(xfs_sb_t, sb_agcount),    0 },
    { offsetof(xfs_sb_t, sb_rbmblocks),  0 },
    { offsetof(xfs_sb_t, sb_logblocks),  0 },
    { offsetof(xfs_sb_t, sb_versionnum), 0 },
    { offsetof(xfs_sb_t, sb_sectsize),   0 },
    { offsetof(xfs_sb_t, sb_inodesize),  0 },
    { offsetof(xfs_sb_t, sb_inopblock),  0 },
    { offsetof(xfs_sb_t, sb_fname[0]),   1 },
    { offsetof(xfs_sb_t, sb_blocklog),   0 },
    { offsetof(xfs_sb_t, sb_sectlog),    0 },
    { offsetof(xfs_sb_t, sb_inodelog),   0 },
    { offsetof(xfs_sb_t, sb_inopblog),   0 },
    { offsetof(xfs_sb_t, sb_agblklog),   0 },
    { offsetof(xfs_sb_t, sb_rextslog),   0 },
    { offsetof(xfs_sb_t, sb_inprogress), 0 },
    { offsetof(xfs_sb_t, sb_imax_pct),   0 },
    { offsetof(xfs_sb_t, sb_icount),     0 },
    { offsetof(xfs_sb_t, sb_ifree),      0 },
    { offsetof(xfs_sb_t, sb_fdblocks),   0 },
    { offsetof(xfs_sb_t, sb_frextents),  0 },
    { offsetof(xfs_sb_t, sb_uquotino),   0 },
    { offsetof(xfs_sb_t, sb_gquotino),   0 },
    { offsetof(xfs_sb_t, sb_qflags),     0 },
    { offsetof(xfs_sb_t, sb_flags),      0 },
    { offsetof(xfs_sb_t, sb_shared_vn),  0 },
    { offsetof(xfs_sb_t, sb_inoalignmt), 0 },
    { offsetof(xfs_sb_t, sb_unit),	 0 },
    { offsetof(xfs_sb_t, sb_width),	 0 },
    { offsetof(xfs_sb_t, sb_dirblklog),	 0 },
    { offsetof(xfs_sb_t, sb_logsectlog), 0 },
    { offsetof(xfs_sb_t, sb_logsectsize),0 },
    { offsetof(xfs_sb_t, sb_logsunit),	 0 },
    { offsetof(xfs_sb_t, sb_features2),	 0 },
    { offsetof(xfs_sb_t, sb_bad_features2), 0 },
    { sizeof(xfs_sb_t),			 0 }
};

/*
 * Reference counting access wrappers to the perag structures.
 * Because we never free per-ag structures, the only thing we
 * have to protect against changes is the tree structure itself.
 */
struct xfs_perag *
xfs_perag_get(struct xfs_mount *mp, xfs_agnumber_t agno)
{
	struct xfs_perag	*pag;
	int			ref = 0;

	rcu_read_lock();
	pag = radix_tree_lookup(&mp->m_perag_tree, agno);
	if (pag) {
		ASSERT(atomic_read(&pag->pag_ref) >= 0);
		ref = atomic_inc_return(&pag->pag_ref);
	}
	rcu_read_unlock();
	trace_xfs_perag_get(mp, agno, ref, _RET_IP_);
	return pag;
}

void
xfs_perag_put(struct xfs_perag *pag)
{
	int	ref;

	ASSERT(atomic_read(&pag->pag_ref) > 0);
	ref = atomic_dec_return(&pag->pag_ref);
	trace_xfs_perag_put(pag->pag_mount, pag->pag_agno, ref, _RET_IP_);
}

STATIC void
__xfs_free_perag(
	struct rcu_head	*head)
{
	struct xfs_perag *pag = container_of(head, struct xfs_perag, rcu_head);

	ASSERT(atomic_read(&pag->pag_ref) == 0);
	kmem_free(pag);
}

/*
 * Free up the per-ag resources associated with the mount structure.
 */
STATIC void
xfs_free_perag(
	xfs_mount_t	*mp)
{
	xfs_agnumber_t	agno;
	struct xfs_perag *pag;

	for (agno = 0; agno < mp->m_sb.sb_agcount; agno++) {
		spin_lock(&mp->m_perag_lock);
		pag = radix_tree_delete(&mp->m_perag_tree, agno);
		spin_unlock(&mp->m_perag_lock);
		ASSERT(pag);
		ASSERT(atomic_read(&pag->pag_ref) == 0);
		call_rcu(&pag->rcu_head, __xfs_free_perag);
	}
}

/*
 * Check size of device based on the (data/realtime) block count.
 * Note: this check is used by the growfs code as well as mount.
 */
int
xfs_sb_validate_fsb_count(
	xfs_sb_t	*sbp,
	__uint64_t	nblocks)
{
	ASSERT(PAGE_SHIFT >= sbp->sb_blocklog);
	ASSERT(sbp->sb_blocklog >= BBSHIFT);

#if XFS_BIG_BLKNOS     /* Limited by ULONG_MAX of page cache index */
	if (nblocks >> (PAGE_CACHE_SHIFT - sbp->sb_blocklog) > ULONG_MAX)
		return EFBIG;
#else                  /* Limited by UINT_MAX of sectors */
	if (nblocks << (sbp->sb_blocklog - BBSHIFT) > UINT_MAX)
		return EFBIG;
#endif
	return 0;
}

/*
 * Check the validity of the SB found.
 */
STATIC int
xfs_mount_validate_sb(
	xfs_mount_t	*mp,
	xfs_sb_t	*sbp,
	bool		check_inprogress)
{

	/*
	 * If the log device and data device have the
	 * same device number, the log is internal.
	 * Consequently, the sb_logstart should be non-zero.  If
	 * we have a zero sb_logstart in this case, we may be trying to mount
	 * a volume filesystem in a non-volume manner.
	 */
	if (sbp->sb_magicnum != XFS_SB_MAGIC) {
		xfs_warn(mp, "bad magic number");
		return XFS_ERROR(EWRONGFS);
	}

	if (!xfs_sb_good_version(sbp)) {
		xfs_warn(mp, "bad version");
		return XFS_ERROR(EWRONGFS);
	}

	if (unlikely(
	    sbp->sb_logstart == 0 && mp->m_logdev_targp == mp->m_ddev_targp)) {
		xfs_warn(mp,
		"filesystem is marked as having an external log; "
		"specify logdev on the mount command line.");
		return XFS_ERROR(EINVAL);
	}

	if (unlikely(
	    sbp->sb_logstart != 0 && mp->m_logdev_targp != mp->m_ddev_targp)) {
		xfs_warn(mp,
		"filesystem is marked as having an internal log; "
		"do not specify logdev on the mount command line.");
		return XFS_ERROR(EINVAL);
	}

	/*
	 * More sanity checking.  Most of these were stolen directly from
	 * xfs_repair.
	 */
	if (unlikely(
	    sbp->sb_agcount <= 0					||
	    sbp->sb_sectsize < XFS_MIN_SECTORSIZE			||
	    sbp->sb_sectsize > XFS_MAX_SECTORSIZE			||
	    sbp->sb_sectlog < XFS_MIN_SECTORSIZE_LOG			||
	    sbp->sb_sectlog > XFS_MAX_SECTORSIZE_LOG			||
	    sbp->sb_sectsize != (1 << sbp->sb_sectlog)			||
	    sbp->sb_blocksize < XFS_MIN_BLOCKSIZE			||
	    sbp->sb_blocksize > XFS_MAX_BLOCKSIZE			||
	    sbp->sb_blocklog < XFS_MIN_BLOCKSIZE_LOG			||
	    sbp->sb_blocklog > XFS_MAX_BLOCKSIZE_LOG			||
	    sbp->sb_blocksize != (1 << sbp->sb_blocklog)		||
	    sbp->sb_inodesize < XFS_DINODE_MIN_SIZE			||
	    sbp->sb_inodesize > XFS_DINODE_MAX_SIZE			||
	    sbp->sb_inodelog < XFS_DINODE_MIN_LOG			||
	    sbp->sb_inodelog > XFS_DINODE_MAX_LOG			||
	    sbp->sb_inodesize != (1 << sbp->sb_inodelog)		||
	    (sbp->sb_blocklog - sbp->sb_inodelog != sbp->sb_inopblog)	||
	    (sbp->sb_rextsize * sbp->sb_blocksize > XFS_MAX_RTEXTSIZE)	||
	    (sbp->sb_rextsize * sbp->sb_blocksize < XFS_MIN_RTEXTSIZE)	||
	    (sbp->sb_imax_pct > 100 /* zero sb_imax_pct is valid */)	||
	    sbp->sb_dblocks == 0					||
	    sbp->sb_dblocks > XFS_MAX_DBLOCKS(sbp)			||
	    sbp->sb_dblocks < XFS_MIN_DBLOCKS(sbp))) {
		XFS_CORRUPTION_ERROR("SB sanity check failed",
				XFS_ERRLEVEL_LOW, mp, sbp);
		return XFS_ERROR(EFSCORRUPTED);
	}

	/*
	 * Until this is fixed only page-sized or smaller data blocks work.
	 */
	if (unlikely(sbp->sb_blocksize > PAGE_SIZE)) {
		xfs_warn(mp,
		"File system with blocksize %d bytes. "
		"Only pagesize (%ld) or less will currently work.",
				sbp->sb_blocksize, PAGE_SIZE);
		return XFS_ERROR(ENOSYS);
	}

	/*
	 * Currently only very few inode sizes are supported.
	 */
	switch (sbp->sb_inodesize) {
	case 256:
	case 512:
	case 1024:
	case 2048:
		break;
	default:
		xfs_warn(mp, "inode size of %d bytes not supported",
				sbp->sb_inodesize);
		return XFS_ERROR(ENOSYS);
	}

	if (xfs_sb_validate_fsb_count(sbp, sbp->sb_dblocks) ||
	    xfs_sb_validate_fsb_count(sbp, sbp->sb_rblocks)) {
		xfs_warn(mp,
		"file system too large to be mounted on this system.");
		return XFS_ERROR(EFBIG);
	}

	if (check_inprogress && sbp->sb_inprogress) {
		xfs_warn(mp, "Offline file system operation in progress!");
		return XFS_ERROR(EFSCORRUPTED);
	}

	/*
	 * Version 1 directory format has never worked on Linux.
	 */
	if (unlikely(!xfs_sb_version_hasdirv2(sbp))) {
		xfs_warn(mp, "file system using version 1 directory format");
		return XFS_ERROR(ENOSYS);
	}

	return 0;
}

/*
 * xfs_mount_common
 *
 * Mount initialization code establishing various mount
 * fields from the superblock associated with the given
 * mount structure
 */
STATIC void
xfs_mount_common(xfs_mount_t *mp, xfs_sb_t *sbp)
{
	mp->m_agfrotor = mp->m_agirotor = 0;
	spin_lock_init(&mp->m_agirotor_lock);
	mp->m_maxagi = mp->m_sb.sb_agcount;
	mp->m_blkbit_log = sbp->sb_blocklog + XFS_NBBYLOG;
	mp->m_blkbb_log = sbp->sb_blocklog - BBSHIFT;
	mp->m_sectbb_log = sbp->sb_sectlog - BBSHIFT;
	mp->m_agno_log = xfs_highbit32(sbp->sb_agcount - 1) + 1;
	mp->m_agino_log = sbp->sb_inopblog + sbp->sb_agblklog;
	mp->m_blockmask = sbp->sb_blocksize - 1;
	mp->m_blockwsize = sbp->sb_blocksize >> XFS_WORDLOG;
	mp->m_blockwmask = mp->m_blockwsize - 1;

	mp->m_alloc_mxr[0] = xfs_allocbt_maxrecs(mp, sbp->sb_blocksize, 1);
	mp->m_alloc_mxr[1] = xfs_allocbt_maxrecs(mp, sbp->sb_blocksize, 0);
	mp->m_alloc_mnr[0] = mp->m_alloc_mxr[0] / 2;
	mp->m_alloc_mnr[1] = mp->m_alloc_mxr[1] / 2;

	mp->m_inobt_mxr[0] = xfs_inobt_maxrecs(mp, sbp->sb_blocksize, 1);
	mp->m_inobt_mxr[1] = xfs_inobt_maxrecs(mp, sbp->sb_blocksize, 0);
	mp->m_inobt_mnr[0] = mp->m_inobt_mxr[0] / 2;
	mp->m_inobt_mnr[1] = mp->m_inobt_mxr[1] / 2;

	mp->m_bmap_dmxr[0] = xfs_bmbt_maxrecs(mp, sbp->sb_blocksize, 1);
	mp->m_bmap_dmxr[1] = xfs_bmbt_maxrecs(mp, sbp->sb_blocksize, 0);
	mp->m_bmap_dmnr[0] = mp->m_bmap_dmxr[0] / 2;
	mp->m_bmap_dmnr[1] = mp->m_bmap_dmxr[1] / 2;

	mp->m_bsize = XFS_FSB_TO_BB(mp, 1);
	mp->m_ialloc_inos = (int)MAX((__uint16_t)XFS_INODES_PER_CHUNK,
					sbp->sb_inopblock);
	mp->m_ialloc_blks = mp->m_ialloc_inos >> sbp->sb_inopblog;
}

int
xfs_initialize_perag(
	xfs_mount_t	*mp,
	xfs_agnumber_t	agcount,
	xfs_agnumber_t	*maxagi)
{
	xfs_agnumber_t	index;
	xfs_agnumber_t	first_initialised = 0;
	xfs_perag_t	*pag;
	xfs_agino_t	agino;
	xfs_ino_t	ino;
	xfs_sb_t	*sbp = &mp->m_sb;
	int		error = -ENOMEM;

	/*
	 * Walk the current per-ag tree so we don't try to initialise AGs
	 * that already exist (growfs case). Allocate and insert all the
	 * AGs we don't find ready for initialisation.
	 */
	for (index = 0; index < agcount; index++) {
		pag = xfs_perag_get(mp, index);
		if (pag) {
			xfs_perag_put(pag);
			continue;
		}
		if (!first_initialised)
			first_initialised = index;

		pag = kmem_zalloc(sizeof(*pag), KM_MAYFAIL);
		if (!pag)
			goto out_unwind;
		pag->pag_agno = index;
		pag->pag_mount = mp;
		spin_lock_init(&pag->pag_ici_lock);
		mutex_init(&pag->pag_ici_reclaim_lock);
		INIT_RADIX_TREE(&pag->pag_ici_root, GFP_ATOMIC);
		spin_lock_init(&pag->pag_buf_lock);
		pag->pag_buf_tree = RB_ROOT;

		if (radix_tree_preload(GFP_NOFS))
			goto out_unwind;

		spin_lock(&mp->m_perag_lock);
		if (radix_tree_insert(&mp->m_perag_tree, index, pag)) {
			/*
			 * We do not need to report bug.
			 */
			/*
			BUG();
			*/
			spin_unlock(&mp->m_perag_lock);
			radix_tree_preload_end();
			error = -EEXIST;
			goto out_unwind;
		}
		spin_unlock(&mp->m_perag_lock);
		radix_tree_preload_end();
	}

	/*
	 * If we mount with the inode64 option, or no inode overflows
	 * the legacy 32-bit address space clear the inode32 option.
	 */
	agino = XFS_OFFBNO_TO_AGINO(mp, sbp->sb_agblocks - 1, 0);
	ino = XFS_AGINO_TO_INO(mp, agcount - 1, agino);

	if ((mp->m_flags & XFS_MOUNT_SMALL_INUMS) && ino > XFS_MAXINUMBER_32)
		mp->m_flags |= XFS_MOUNT_32BITINODES;
	else
		mp->m_flags &= ~XFS_MOUNT_32BITINODES;

	if (mp->m_flags & XFS_MOUNT_32BITINODES)
		index = xfs_set_inode32(mp);
	else
		index = xfs_set_inode64(mp);

	if (maxagi)
		*maxagi = index;
	return 0;

out_unwind:
	kmem_free(pag);
	for (; index > first_initialised; index--) {
		pag = radix_tree_delete(&mp->m_perag_tree, index);
		kmem_free(pag);
	}
	return error;
}

void
xfs_sb_from_disk(
	struct xfs_sb	*to,
	xfs_dsb_t	*from)
{
	to->sb_magicnum = be32_to_cpu(from->sb_magicnum);
	to->sb_blocksize = be32_to_cpu(from->sb_blocksize);
	to->sb_dblocks = be64_to_cpu(from->sb_dblocks);
	to->sb_rblocks = be64_to_cpu(from->sb_rblocks);
	to->sb_rextents = be64_to_cpu(from->sb_rextents);
	memcpy(&to->sb_uuid, &from->sb_uuid, sizeof(to->sb_uuid));
	to->sb_logstart = be64_to_cpu(from->sb_logstart);
	to->sb_rootino = be64_to_cpu(from->sb_rootino);
	to->sb_rbmino = be64_to_cpu(from->sb_rbmino);
	to->sb_rsumino = be64_to_cpu(from->sb_rsumino);
	to->sb_rextsize = be32_to_cpu(from->sb_rextsize);
	to->sb_agblocks = be32_to_cpu(from->sb_agblocks);
	to->sb_agcount = be32_to_cpu(from->sb_agcount);
	to->sb_rbmblocks = be32_to_cpu(from->sb_rbmblocks);
	to->sb_logblocks = be32_to_cpu(from->sb_logblocks);
	to->sb_versionnum = be16_to_cpu(from->sb_versionnum);
	to->sb_sectsize = be16_to_cpu(from->sb_sectsize);
	to->sb_inodesize = be16_to_cpu(from->sb_inodesize);
	to->sb_inopblock = be16_to_cpu(from->sb_inopblock);
	memcpy(&to->sb_fname, &from->sb_fname, sizeof(to->sb_fname));
	to->sb_blocklog = from->sb_blocklog;
	to->sb_sectlog = from->sb_sectlog;
	to->sb_inodelog = from->sb_inodelog;
	to->sb_inopblog = from->sb_inopblog;
	to->sb_agblklog = from->sb_agblklog;
	to->sb_rextslog = from->sb_rextslog;
	to->sb_inprogress = from->sb_inprogress;
	to->sb_imax_pct = from->sb_imax_pct;
	to->sb_icount = be64_to_cpu(from->sb_icount);
	to->sb_ifree = be64_to_cpu(from->sb_ifree);
	to->sb_fdblocks = be64_to_cpu(from->sb_fdblocks);
	to->sb_frextents = be64_to_cpu(from->sb_frextents);
	to->sb_uquotino = be64_to_cpu(from->sb_uquotino);
	to->sb_gquotino = be64_to_cpu(from->sb_gquotino);
	to->sb_qflags = be16_to_cpu(from->sb_qflags);
	to->sb_flags = from->sb_flags;
	to->sb_shared_vn = from->sb_shared_vn;
	to->sb_inoalignmt = be32_to_cpu(from->sb_inoalignmt);
	to->sb_unit = be32_to_cpu(from->sb_unit);
	to->sb_width = be32_to_cpu(from->sb_width);
	to->sb_dirblklog = from->sb_dirblklog;
	to->sb_logsectlog = from->sb_logsectlog;
	to->sb_logsectsize = be16_to_cpu(from->sb_logsectsize);
	to->sb_logsunit = be32_to_cpu(from->sb_logsunit);
	to->sb_features2 = be32_to_cpu(from->sb_features2);
	to->sb_bad_features2 = be32_to_cpu(from->sb_bad_features2);
}

/*
 * Copy in core superblock to ondisk one.
 *
 * The fields argument is mask of superblock fields to copy.
 */
void
xfs_sb_to_disk(
	xfs_dsb_t	*to,
	xfs_sb_t	*from,
	__int64_t	fields)
{
	xfs_caddr_t	to_ptr = (xfs_caddr_t)to;
	xfs_caddr_t	from_ptr = (xfs_caddr_t)from;
	xfs_sb_field_t	f;
	int		first;
	int		size;

	ASSERT(fields);
	if (!fields)
		return;

	while (fields) {
		f = (xfs_sb_field_t)xfs_lowbit64((__uint64_t)fields);
		first = xfs_sb_info[f].offset;
		size = xfs_sb_info[f + 1].offset - first;

		ASSERT(xfs_sb_info[f].type == 0 || xfs_sb_info[f].type == 1);

		if (size == 1 || xfs_sb_info[f].type == 1) {
			memcpy(to_ptr + first, from_ptr + first, size);
		} else {
			switch (size) {
			case 2:
				*(__be16 *)(to_ptr + first) =
					cpu_to_be16(*(__u16 *)(from_ptr + first));
				break;
			case 4:
				*(__be32 *)(to_ptr + first) =
					cpu_to_be32(*(__u32 *)(from_ptr + first));
				break;
			case 8:
				*(__be64 *)(to_ptr + first) =
					cpu_to_be64(*(__u64 *)(from_ptr + first));
				break;
			default:
				ASSERT(0);
			}
		}

		fields &= ~(1LL << f);
	}
}

static void
xfs_sb_verify(
	struct xfs_buf	*bp)
{
	struct xfs_mount *mp = bp->b_target->bt_mount;
	struct xfs_sb	sb;
	int		error;

	xfs_sb_from_disk(&sb, XFS_BUF_TO_SBP(bp));

	/*
	 * Only check the in progress field for the primary superblock as
	 * mkfs.xfs doesn't clear it from secondary superblocks.
	 */
	error = xfs_mount_validate_sb(mp, &sb, bp->b_bn == XFS_SB_DADDR);
	if (error)
		xfs_buf_ioerror(bp, error);
}

static void
xfs_sb_read_verify(
	struct xfs_buf	*bp)
{
	xfs_sb_verify(bp);
}

/*
 * We may be probed for a filesystem match, so we may not want to emit
 * messages when the superblock buffer is not actually an XFS superblock.
 * If we find an XFS superblock, the run a normal, noisy mount because we are
 * really going to mount it and want to know about errors.
 */
static void
xfs_sb_quiet_read_verify(
	struct xfs_buf	*bp)
{
	struct xfs_sb	sb;

	xfs_sb_from_disk(&sb, XFS_BUF_TO_SBP(bp));

	if (sb.sb_magicnum == XFS_SB_MAGIC) {
		/* XFS filesystem, verify noisily! */
		xfs_sb_read_verify(bp);
		return;
	}
	/* quietly fail */
	xfs_buf_ioerror(bp, EWRONGFS);
}

static void
xfs_sb_write_verify(
	struct xfs_buf	*bp)
{
	xfs_sb_verify(bp);
}

const struct xfs_buf_ops xfs_sb_buf_ops = {
	.verify_read = xfs_sb_read_verify,
	.verify_write = xfs_sb_write_verify,
};

static const struct xfs_buf_ops xfs_sb_quiet_buf_ops = {
	.verify_read = xfs_sb_quiet_read_verify,
	.verify_write = xfs_sb_write_verify,
};

/*
 * xfs_readsb
 *
 * Does the initial read of the superblock.
 */
int
xfs_readsb(xfs_mount_t *mp, int flags)
{
	unsigned int	sector_size;
	xfs_buf_t	*bp;
	int		error;
	int		loud = !(flags & XFS_MFSI_QUIET);

	ASSERT(mp->m_sb_bp == NULL);
	ASSERT(mp->m_ddev_targp != NULL);

	/*
	 * Allocate a (locked) buffer to hold the superblock.
	 * This will be kept around at all times to optimize
	 * access to the superblock.
	 */
	/*
	 * Don't know any disk.
	 */
	/*
	sector_size = xfs_getsize_buftarg(mp->m_ddev_targp);
	*/
	sector_size = mp->m_sb.sb_sectsize;

reread:
	bp = xfs_buf_read_uncached(mp->m_ddev_targp, XFS_SB_DADDR,
				   BTOBB(sector_size), 0,
				   loud ? &xfs_sb_buf_ops
				        : &xfs_sb_quiet_buf_ops);
	if (!bp) {
		if (loud)
			xfs_warn(mp, "SB buffer read failed");
		return EIO;
	}
	if (bp->b_error) {
		error = bp->b_error;
		if (loud)
			xfs_warn(mp, "SB validate failed");
		goto release_buf;
	}

	/*
	 * Initialize the mount structure from the superblock.
	 */
	xfs_sb_from_disk(&mp->m_sb, XFS_BUF_TO_SBP(bp));

	/*
	 * We must be able to do sector-sized and sector-aligned IO.
	 */
	if (sector_size > mp->m_sb.sb_sectsize) {
		if (loud)
			xfs_warn(mp, "device supports %u byte sectors (not %u)",
				sector_size, mp->m_sb.sb_sectsize);
		error = ENOSYS;
		goto release_buf;
	}

	/*
	 * If device sector size is smaller than the superblock size,
	 * re-read the superblock so the buffer is correctly sized.
	 */
	if (sector_size < mp->m_sb.sb_sectsize) {
		xfs_buf_relse(bp);
		sector_size = mp->m_sb.sb_sectsize;
		goto reread;
	}

	/* Initialize per-cpu counters */
	xfs_icsb_reinit_counters(mp);

	mp->m_sb_bp = bp;
	xfs_buf_unlock(bp);
	return 0;

release_buf:
	xfs_buf_relse(bp);
	return error;
}

/*
 * xfs_getsb() is called to obtain the buffer for the superblock.
 * The buffer is returned locked and read in from disk.
 * The buffer should be released with a call to xfs_brelse().
 *
 * If the flags parameter is BUF_TRYLOCK, then we'll only return
 * the superblock buffer if it can be locked without sleeping.
 * If it can't then we'll return NULL.
 */
struct xfs_buf *
xfs_getsb(
	struct xfs_mount	*mp,
	int			flags)
{
	struct xfs_buf		*bp = mp->m_sb_bp;

	if (!xfs_buf_trylock(bp)) {
		if (flags & XBF_TRYLOCK)
			return NULL;
		xfs_buf_lock(bp);
	}

	xfs_buf_hold(bp);
	ASSERT(XFS_BUF_ISDONE(bp));
	return bp;
}

/*
 * Used to free the superblock along various error paths.
 */
void
xfs_freesb(
	struct xfs_mount	*mp)
{
	struct xfs_buf		*bp = mp->m_sb_bp;

	xfs_buf_lock(bp);
	mp->m_sb_bp = NULL;
	xfs_buf_relse(bp);
}

