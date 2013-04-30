#ifndef __TSLIB_DISK_H__
#define __TSLIB_DISK_H__

#define BLK_SIZE (512)

#ifdef WIN32
#else
int tslib_read_disk_block( long long block, void *data, int bytes);
#endif
#endif
