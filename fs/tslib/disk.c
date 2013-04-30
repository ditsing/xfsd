#include "disk.h"
#include "xfsd_types.h"
#include "syscall.h"

#ifdef WIN32
#else
int tslib_read_disk_block( long long block, void *data, int bytes)
{
	// Overflow.
	long long offset = block * BLK_SIZE;
	seek_disk_file_set( offset);
	return read_disk_file( data, bytes, 1) != 1;
}

#endif
