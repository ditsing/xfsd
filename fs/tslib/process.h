#ifndef __TSLIB_PROCESS_H__
#define __TSLIB_PROCESS_H__
#ifdef WIN32
#else

struct process
{
	int flags;
};

enum {
	BLK_RW_ASYNC	= 0,
	BLK_RW_SYNC	= 1,
};

#define HZ 1000
#define PF_FSTRANS	0x00020000	/* inside a filesystem transaction */

extern const struct process *current;
static inline long congestion_wait(int sync, long timeout)
{
	return 0;
}
#endif
#endif
