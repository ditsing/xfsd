#include "xfsd.h"
#include "xfsd_types.h"

#include "xfs/xfs_types.h"
#include "xfs/xfs_sb.h"
#include "xfs/xfs_log.h"
#include "xfs/xfs_ag.h"
#include "xfs/xfs_mount.h"

#include "xfsd_trace.h"


void
xfs_buf_ioerror(
	xfs_buf_t		*bp,
	int			error)
{
	ASSERT(error >= 0 && error <= 0xffff);
	bp->b_error = (unsigned short)error;
	trace_xfs_buf_ioerror(bp, error, _RET_IP_);
}

