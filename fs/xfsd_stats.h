#ifndef __XFSD_STATS_H__
#define __XFSD_STATS_H__

#define XFS_STATS_INC(count)
#define XFS_STATS_DEC(count)
#define XFS_STATS_ADD(count, inc)

static inline int xfs_init_procfs(void)
{
	return 0;
}

static inline void xfs_cleanup_procfs(void)
{
}

#endif
