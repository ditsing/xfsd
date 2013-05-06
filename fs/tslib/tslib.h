#ifndef __TSLIB_H__
# define __TSLIB_H__
int tslib_init();
void tslib_exit();
struct xfs_sb;
struct xfs_sb *tslib_get_sb();
#endif
