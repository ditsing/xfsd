#include "disk.h"
#include "xfsd_types.h"
#include "syscall.h"

#ifdef WIN32
#else
int tslib_read_disk( long long block, void *data, int bytes)
{
	// Overflow.
	long long offset = block * BLK_SIZE;
	seek_file_set( offset);
	return read_file( data, bytes, 1);
}
#endif
