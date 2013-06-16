#ifndef __TSLIB_H__
# define __TSLIB_H__
int tslib_init();
void tslib_exit();
struct xfs_sb;
struct xfs_sb *tslib_get_sb();

#define tslib_get_sb_dblocks() 10000
#define tslib_get_sb_sectsize() 4096
#define tslib_get_blksize() 512
#endif
