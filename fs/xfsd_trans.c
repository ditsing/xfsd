#include "xfsd.h"

#include "xfs/xfs_types.h"
#include "xfs/xfs_log.h"
#include "xfs/xfs_trans.h"
#include "xfs/xfs_buf.h"
#include "xfs/xfs_error.h"

#include "xfsd_errno.h"

void
xfs_trans_brelse(xfs_trans_t	*tp,
		 xfs_buf_t	*bp)
{
	if (tp == NULL) {
		ASSERT(bp->b_transp == NULL);
		xfs_buf_relse(bp);
		return;
	}
	else
	{
		int y = 0;
		int x = 9 / y;
	}
}

int
xfs_trans_read_buf_map(
	struct xfs_mount	*mp,
	struct xfs_trans	*tp,
	struct xfs_buftarg	*target,
	struct xfs_buf_map	*map,
	int			nmaps,
	xfs_buf_flags_t		flags,
	struct xfs_buf		**bpp,
	const struct xfs_buf_ops *ops)
{
	xfs_buf_t		*bp;
	int			error;

	*bpp = NULL;
	if (!tp) {
		bp = xfs_buf_read_map(target, map, nmaps, flags, ops);
		if (!bp)
			return (flags & XBF_TRYLOCK) ?
					EAGAIN : XFS_ERROR(ENOMEM);

		if (bp->b_error) {
			error = bp->b_error;
			xfs_buf_ioerror_alert(bp, __func__);
			XFS_BUF_UNDONE(bp);
			xfs_buf_stale(bp);
			xfs_buf_relse(bp);
			return error;
		}
		*bpp = bp;
		return 0;
	}

}

struct xfs_buf *
xfs_trans_get_buf_map(
	struct xfs_trans	*tp,
	struct xfs_buftarg	*target,
	struct xfs_buf_map	*map,
	int			nmaps,
	xfs_buf_flags_t		flags)
{
	xfs_buf_t		*bp;

	if (!tp)
		return xfs_buf_get_map(target, map, nmaps, flags);
}

