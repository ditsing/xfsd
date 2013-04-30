#include "xfsd.h"

#include "xfs/xfs_types.h"
#include "xfs/xfs_sb.h"
#include "xfs/xfs_log.h"
#include "xfs/xfs_ag.h"
#include "xfs/xfs_mount.h"
#include "xfsd_mem.h"

#include "xfsd_trace.h"

// To access disk.
#include "tslib/disk.h"

static kmem_zone_t *xfs_buf_zone;

#define XB_SET_OWNER(x)
#define XB_CLEAR_OWNER(x)

#define xb_to_gfp(flags) \
	((((flags) & XBF_READ_AHEAD) ? __GFP_NORETRY : GFP_NOFS) | __GFP_NOWARN)

/*
 * When we mark a buffer stale, we remove the buffer from the LRU and clear the
 * b_lru_ref count so that the buffer is freed immediately when the buffer
 * reference count falls to zero. If the buffer is already on the LRU, we need
 * to remove the reference that LRU holds on the buffer.
 *
 * This prevents build-up of stale buffers on the LRU.
 */
void
xfs_buf_stale(
	struct xfs_buf	*bp)
{
	ASSERT(xfs_buf_islocked(bp));

	bp->b_flags |= XBF_STALE;

	/*
	 * Clear the delwri status so that a delwri queue walker will not
	 * flush this buffer to disk now that it is stale. The delwri queue has
	 * a reference to the buffer, so this is safe to do.
	 */
	bp->b_flags &= ~_XBF_DELWRI_Q;

	atomic_set(&(bp)->b_lru_ref, 0);
	if (!list_empty(&bp->b_lru)) {
		struct xfs_buftarg *btp = bp->b_target;

		spin_lock(&btp->bt_lru_lock);
		if (!list_empty(&bp->b_lru) &&
		    !(bp->b_lru_flags & _XBF_LRU_DISPOSE)) {
			list_del_init(&bp->b_lru);
			btp->bt_lru_nr--;
			atomic_dec(&bp->b_hold);
		}
		spin_unlock(&btp->bt_lru_lock);
	}
	ASSERT(atomic_read(&bp->b_hold) >= 1);
}

static int
xfs_buf_get_maps(
	struct xfs_buf		*bp,
	int			map_count)
{
	ASSERT(bp->b_maps == NULL);
	bp->b_map_count = map_count;

	if (map_count == 1) {
		bp->b_maps = &bp->__b_map;
		return 0;
	}

	bp->b_maps = kmem_zalloc(map_count * sizeof(struct xfs_buf_map),
				KM_NOFS);
	if (!bp->b_maps)
		return ENOMEM;
	return 0;
}

/*
 *	Frees b_pages if it was allocated.
 */
static void
xfs_buf_free_maps(
	struct xfs_buf	*bp)
{
	if (bp->b_maps != &bp->__b_map) {
		kmem_free(bp->b_maps);
		bp->b_maps = NULL;
	}
}

struct xfs_buf *
_xfs_buf_alloc(
	struct xfs_buftarg	*target,
	struct xfs_buf_map	*map,
	int			nmaps,
	xfs_buf_flags_t		flags)
{
	struct xfs_buf		*bp;
	int			error;
	int			i;

	bp = kmem_zone_zalloc(xfs_buf_zone, KM_NOFS);
	if (unlikely(!bp))
		return NULL;

	/*
	 * We don't want certain flags to appear in b_flags unless they are
	 * specifically set by later operations on the buffer.
	 */
	flags &= ~(XBF_UNMAPPED | XBF_TRYLOCK | XBF_ASYNC | XBF_READ_AHEAD);

	atomic_set(&bp->b_hold, 1);
	atomic_set(&bp->b_lru_ref, 1);
	/*
	 * Comment out.
	 * Do not use completion.
	 */
	/*
	init_completion(&bp->b_iowait);
	*/
	INIT_LIST_HEAD(&bp->b_lru);
	INIT_LIST_HEAD(&bp->b_list);
	RB_CLEAR_NODE(&bp->b_rbnode);
	sema_init(&bp->b_sema, 0); /* held, no waiters */
	XB_SET_OWNER(bp);
	bp->b_target = target;
	bp->b_flags = flags;

	/*
	 * Set length and io_length to the same value initially.
	 * I/O routines should use io_length, which will be the same in
	 * most cases but may be reset (e.g. XFS recovery).
	 */
	error = xfs_buf_get_maps(bp, nmaps);
	if (error)  {
		kmem_zone_free(xfs_buf_zone, bp);
		return NULL;
	}

	bp->b_bn = map[0].bm_bn;
	bp->b_length = 0;
	for (i = 0; i < nmaps; i++) {
		bp->b_maps[i].bm_bn = map[i].bm_bn;
		bp->b_maps[i].bm_len = map[i].bm_len;
		bp->b_length += map[i].bm_len;
	}
	bp->b_io_length = bp->b_length;

	atomic_set(&bp->b_pin_count, 0);
	/*
	 * Comment out.
	 * No worker queue.
	 */
	/*
	init_waitqueue_head(&bp->b_waiters);
	*/

	XFS_STATS_INC(xb_create);
	trace_xfs_buf_init(bp, _RET_IP_);

	return bp;
}

void
xfs_buf_free(
	xfs_buf_t 		*bp)
{
	xfs_buf_free_maps( bp);
	kmem_zone_free( xfs_buf_zone, bp->b_addr);
}

/*
 * Allocates all the pages for buffer in question and builds it's page list.
 */
STATIC int
xfs_buf_allocate_memory(
	xfs_buf_t		*bp,
	uint			flags)
{
	size_t			size;
	size_t			nbytes, offset;
	gfp_t			gfp_mask = xb_to_gfp(flags);
	unsigned short		page_count, i;
	xfs_off_t		start, end;
	int			error;

	/*
	 * for buffers that are contained within a single page, just allocate
	 * the memory from the heap - there's no need for the complexity of
	 * page arrays to keep allocation down to order 0.
	 */
	size = BBTOB(bp->b_length);
	bp->b_addr = kmem_alloc(size, KM_NOFS);
	bp->b_offset = 0;
	bp->b_flags |= _XBF_KMEM;
	return 0;
}

/*
 *	Map buffer into kernel address-space if necessary.
 */
STATIC int
_xfs_buf_map_pages(
	xfs_buf_t		*bp,
	uint			flags)
{
	ASSERT(bp->b_flags & _XBF_PAGES);
	/*
	 * All memory are not paged.
	 */
	return 0;
}

/*
 *	Look up, and creates if absent, a lockable buffer for
 *	a given range of an inode.  The buffer is returned
 *	locked.	No I/O is implied by this call.
 */
xfs_buf_t *
_xfs_buf_find(
	struct xfs_buftarg	*btp,
	struct xfs_buf_map	*map,
	int			nmaps,
	xfs_buf_flags_t		flags,
	xfs_buf_t		*new_bp)
{
	size_t			numbytes;
	struct xfs_perag	*pag;
	struct rb_node		**rbp;
	struct rb_node		*parent;
	xfs_buf_t		*bp;
	xfs_daddr_t		blkno = map[0].bm_bn;
	xfs_daddr_t		eofs;
	int			numblks = 0;
	int			i;

	for (i = 0; i < nmaps; i++)
		numblks += map[i].bm_len;
	numbytes = BBTOB(numblks);

	/* Check for IOs smaller than the sector size / not sector aligned */
	ASSERT(!(numbytes < (1 << btp->bt_sshift)));
	ASSERT(!(BBTOB(blkno) & (xfs_off_t)btp->bt_smask));

	/*
	 * Corrupted block numbers can get through to here, unfortunately, so we
	 * have to check that the buffer falls within the filesystem bounds.
	 */
	eofs = XFS_FSB_TO_BB(btp->bt_mount, btp->bt_mount->m_sb.sb_dblocks);
	if (blkno >= eofs) {
		/*
		 * XXX (dgc): we should really be returning EFSCORRUPTED here,
		 * but none of the higher level infrastructure supports
		 * returning a specific error on buffer lookup failures.
		 */
		xfs_alert(btp->bt_mount,
			  "%s: Block out of range: block 0x%llx, EOFS 0x%llx ",
			  __func__, blkno, eofs);
		return NULL;
	}

	/* get tree root */
	pag = xfs_perag_get(btp->bt_mount,
				xfs_daddr_to_agno(btp->bt_mount, blkno));

	/* walk tree */
	spin_lock(&pag->pag_buf_lock);
	rbp = &pag->pag_buf_tree.rb_node;
	parent = NULL;
	bp = NULL;
	while (*rbp) {
		parent = *rbp;
		bp = rb_entry(parent, struct xfs_buf, b_rbnode);

		if (blkno < bp->b_bn)
			rbp = &(*rbp)->rb_left;
		else if (blkno > bp->b_bn)
			rbp = &(*rbp)->rb_right;
		else {
			/*
			 * found a block number match. If the range doesn't
			 * match, the only way this is allowed is if the buffer
			 * in the cache is stale and the transaction that made
			 * it stale has not yet committed. i.e. we are
			 * reallocating a busy extent. Skip this buffer and
			 * continue searching to the right for an exact match.
			 */
			if (bp->b_length != numblks) {
				ASSERT(bp->b_flags & XBF_STALE);
				rbp = &(*rbp)->rb_right;
				continue;
			}
			atomic_inc(&bp->b_hold);
			goto found;
		}
	}

	/* No match found */
	if (new_bp) {
		rb_link_node(&new_bp->b_rbnode, parent, rbp);
		rb_insert_color(&new_bp->b_rbnode, &pag->pag_buf_tree);
		/* the buffer keeps the perag reference until it is freed */
		new_bp->b_pag = pag;
		spin_unlock(&pag->pag_buf_lock);
	} else {
		XFS_STATS_INC(xb_miss_locked);
		spin_unlock(&pag->pag_buf_lock);
		xfs_perag_put(pag);
	}
	return new_bp;

found:
	spin_unlock(&pag->pag_buf_lock);
	xfs_perag_put(pag);

	if (!xfs_buf_trylock(bp)) {
		if (flags & XBF_TRYLOCK) {
			xfs_buf_rele(bp);
			XFS_STATS_INC(xb_busy_locked);
			return NULL;
		}
		xfs_buf_lock(bp);
		XFS_STATS_INC(xb_get_locked_waited);
	}

	/*
	 * if the buffer is stale, clear all the external state associated with
	 * it. We need to keep flags such as how we allocated the buffer memory
	 * intact here.
	 */
	if (bp->b_flags & XBF_STALE) {
		ASSERT((bp->b_flags & _XBF_DELWRI_Q) == 0);
		ASSERT(bp->b_iodone == NULL);
		bp->b_flags &= _XBF_KMEM | _XBF_PAGES;
		bp->b_ops = NULL;
	}

	trace_xfs_buf_find(bp, flags, _RET_IP_);
	XFS_STATS_INC(xb_get_locked);
	return bp;
}

/*
 * Assembles a buffer covering the specified range. The code is optimised for
 * cache hits, as metadata intensive workloads will see 3 orders of magnitude
 * more hits than misses.
 */
struct xfs_buf *
xfs_buf_get_map(
	struct xfs_buftarg	*target,
	struct xfs_buf_map	*map,
	int			nmaps,
	xfs_buf_flags_t		flags)
{
	struct xfs_buf		*bp;
	struct xfs_buf		*new_bp;
	int			error = 0;

	bp = _xfs_buf_find(target, map, nmaps, flags, NULL);
	if (likely(bp))
		goto found;

	new_bp = _xfs_buf_alloc(target, map, nmaps, flags);
	if (unlikely(!new_bp))
		return NULL;

	error = xfs_buf_allocate_memory(new_bp, flags);
	if (error) {
		xfs_buf_free(new_bp);
		return NULL;
	}

	bp = _xfs_buf_find(target, map, nmaps, flags, new_bp);
	if (!bp) {
		xfs_buf_free(new_bp);
		return NULL;
	}

	if (bp != new_bp)
		xfs_buf_free(new_bp);

found:
	if (!bp->b_addr) {
		error = _xfs_buf_map_pages(bp, flags);
		if (unlikely(error)) {
			xfs_warn(target->bt_mount,
				"%s: failed to map pages\n", __func__);
			xfs_buf_relse(bp);
			return NULL;
		}
	}

	XFS_STATS_INC(xb_get);
	trace_xfs_buf_get(bp, flags, _RET_IP_);
	return bp;
}

STATIC int
_xfs_buf_read(
	xfs_buf_t		*bp,
	xfs_buf_flags_t		flags)
{
	ASSERT(!(flags & XBF_WRITE));
	ASSERT(bp->b_maps[0].bm_bn != XFS_BUF_DADDR_NULL);

	bp->b_flags &= ~(XBF_WRITE | XBF_ASYNC | XBF_READ_AHEAD);
	bp->b_flags |= flags & (XBF_READ | XBF_ASYNC | XBF_READ_AHEAD);

	xfs_buf_iorequest(bp);
	if (flags & XBF_ASYNC)
		return 0;
	return xfs_buf_iowait(bp);
}

xfs_buf_t *
xfs_buf_read_map(
	struct xfs_buftarg	*target,
	struct xfs_buf_map	*map,
	int			nmaps,
	xfs_buf_flags_t		flags,
	const struct xfs_buf_ops *ops)
{
	struct xfs_buf		*bp;

	flags |= XBF_READ;

	bp = xfs_buf_get_map(target, map, nmaps, flags);
	if (bp) {
		trace_xfs_buf_read(bp, flags, _RET_IP_);

		if (!XFS_BUF_ISDONE(bp)) {
			XFS_STATS_INC(xb_get_read);
			bp->b_ops = ops;
			_xfs_buf_read(bp, flags);
		} else if (flags & XBF_ASYNC) {
			/*
			 * Read ahead call which is already satisfied,
			 * drop the buffer
			 */
			xfs_buf_relse(bp);
			return NULL;
		} else {
			/* We do not want read in the flags */
			bp->b_flags &= ~XBF_READ;
		}
	}

	return bp;
}

void
xfs_buf_readahead_map(
	struct xfs_buftarg	*target,
	struct xfs_buf_map	*map,
	int			nmaps,
	const struct xfs_buf_ops *ops)
{
	xfs_buf_read_map(target, map, nmaps,
		     XBF_TRYLOCK|XBF_ASYNC|XBF_READ_AHEAD, ops);
}

struct xfs_buf *
xfs_buf_read_uncached(
	struct xfs_buftarg	*target,
	xfs_daddr_t		daddr,
	size_t			numblks,
	int			flags,
	const struct xfs_buf_ops *ops)
{
	struct xfs_buf		*bp;

	bp = xfs_buf_get_uncached(target, numblks, flags);
	if (!bp)
		return NULL;

	/* set up the buffer for a read IO */
	ASSERT(bp->b_map_count == 1);
	bp->b_bn = daddr;
	bp->b_maps[0].bm_bn = daddr;
	bp->b_flags |= XBF_READ;
	bp->b_ops = ops;

	xfs_buf_iorequest(bp);
	xfs_buf_iowait(bp);
	return bp;
}


xfs_buf_t *
xfs_buf_get_uncached(
	struct xfs_buftarg	*target,
	size_t			numblks,
	int			flags)
{
	unsigned long		page_count;
	int			error, i;
	struct xfs_buf		*bp;
	DEFINE_SINGLE_BUF_MAP(map, XFS_BUF_DADDR_NULL, numblks);

	bp = _xfs_buf_alloc(target, &map, 1, 0);
	if (unlikely(bp == NULL))
		goto fail;

	bp->b_addr = kmem_alloc(numblks << BBSHIFT, KM_NOFS);
	error = bp->b_addr == NULL;
	if (error)
		goto fail_free_buf;

	bp->b_flags |= _XBF_PAGES;

	error = _xfs_buf_map_pages(bp, 0);
	if (unlikely(error)) {
		xfs_warn(target->bt_mount,
			"%s: failed to map pages\n", __func__);
		goto fail_free_mem;
	}

	trace_xfs_buf_get_uncached(bp, _RET_IP_);
	return bp;

 fail_free_mem:
	kmem_free(bp->b_addr);
 fail_free_buf:
	xfs_buf_free_maps(bp);
	kmem_zone_free(xfs_buf_zone, bp);
 fail:
	return NULL;
}

void
xfs_buf_hold(
	xfs_buf_t		*bp)
{
	trace_xfs_buf_hold(bp, _RET_IP_);
	atomic_inc(&bp->b_hold);
}

/*
 *	Releases a hold on the specified buffer.  If the
 *	the hold count is 1, calls xfs_buf_free.
 */
void
xfs_buf_rele(
	xfs_buf_t		*bp)
{
	struct xfs_perag	*pag = bp->b_pag;

	trace_xfs_buf_rele(bp, _RET_IP_);

	if (!pag) {
		ASSERT(list_empty(&bp->b_lru));
		ASSERT(RB_EMPTY_NODE(&bp->b_rbnode));
		if (atomic_dec_and_test(&bp->b_hold))
			xfs_buf_free(bp);
		return;
	}

	ASSERT(!RB_EMPTY_NODE(&bp->b_rbnode));

	ASSERT(atomic_read(&bp->b_hold) > 0);
	if (atomic_dec_and_lock(&bp->b_hold, &pag->pag_buf_lock)) {
		if (!(bp->b_flags & XBF_STALE) &&
			   atomic_read(&bp->b_lru_ref)) {
			spin_unlock(&pag->pag_buf_lock);
		} else {
			ASSERT(!(bp->b_flags & _XBF_DELWRI_Q));
			rb_erase(&bp->b_rbnode, &pag->pag_buf_tree);
			spin_unlock(&pag->pag_buf_lock);
			xfs_perag_put(pag);
			xfs_buf_free(bp);
		}
	}
}

/*
 *	Lock a buffer object, if it is not already locked.
 *
 *	If we come across a stale, pinned, locked buffer, we know that we are
 *	being asked to lock a buffer that has been reallocated. Because it is
 *	pinned, we know that the log has not been pushed to disk and hence it
 *	will still be locked.  Rather than continuing to have trylock attempts
 *	fail until someone else pushes the log, push it ourselves before
 *	returning.  This means that the xfsaild will not get stuck trying
 *	to push on stale inode buffers.
 */
int
xfs_buf_trylock(
	struct xfs_buf		*bp)
{
	int			locked;

	locked = down_trylock(&bp->b_sema) == 0;
	if (locked)
		XB_SET_OWNER(bp);

	trace_xfs_buf_trylock(bp, _RET_IP_);
	return locked;
}

/*
 *	Lock a buffer object.
 *
 *	If we come across a stale, pinned, locked buffer, we know that we
 *	are being asked to lock a buffer that has been reallocated. Because
 *	it is pinned, we know that the log has not been pushed to disk and
 *	hence it will still be locked. Rather than sleeping until someone
 *	else pushes the log, push it ourselves before trying to get the lock.
 */
void
xfs_buf_lock(
	struct xfs_buf		*bp)
{
	trace_xfs_buf_lock(bp, _RET_IP_);

	/* No way to be STALE. */
	down(&bp->b_sema);
	XB_SET_OWNER(bp);

	trace_xfs_buf_lock_done(bp, _RET_IP_);
}

void
xfs_buf_unlock(
	struct xfs_buf		*bp)
{
	XB_CLEAR_OWNER(bp);
	up(&bp->b_sema);

	trace_xfs_buf_unlock(bp, _RET_IP_);
}

void
xfs_buf_ioerror(
	xfs_buf_t		*bp,
	int			error)
{
	ASSERT(error >= 0 && error <= 0xffff);
	bp->b_error = (unsigned short)error;
	trace_xfs_buf_ioerror(bp, error, _RET_IP_);
}

void
xfs_buf_ioerror_alert(
	struct xfs_buf		*bp,
	const char		*func)
{
	xfs_alert(bp->b_target->bt_mount,
"metadata I/O error: block 0x%llx (\"%s\") error %d numblks %d",
		(__uint64_t)XFS_BUF_ADDR(bp), func, bp->b_error, bp->b_length);
}

static void
xfs_buf_ioapply_map(
	struct xfs_buf	*bp,
	int		map,
	int		*buf_offset,
	int		*count,
	int		rw)
{
	int		size;
	int		offset;

	offset = *buf_offset;
	/*
	 * Limit the IO size to the length of the current vector, and update the
	 * remaining IO count for the next time around.
	 */
	size = min_t(int, BBTOB(bp->b_maps[map].bm_len), *count);
	*count -= size;
	*buf_offset += size;

	bp->b_error = tslib_read_disk_block( bp->b_maps[map].bm_bn, bp->b_addr + offset, size);
}

STATIC void
_xfs_buf_ioapply(
	struct xfs_buf	*bp)
{
	int		rw;
	int		offset;
	int		size;
	int		i;

	/*
	 * Make sure we capture only current IO errors rather than stale errors
	 * left over from previous use of the buffer (e.g. failed readahead).
	 */
	bp->b_error = 0;

	if (bp->b_flags & XBF_WRITE) {
		/*
		 * Error!
		 */
	} else if (bp->b_flags & XBF_READ_AHEAD) {
	} else {
	}

	/*
	 * Walk all the vectors issuing IO on them. Set up the initial offset
	 * into the buffer and the desired IO size before we start -
	 * _xfs_buf_ioapply_vec() will modify them appropriately for each
	 * subsequent call.
	 */
	offset = bp->b_offset;
	size = BBTOB(bp->b_io_length);
	for (i = 0; i < bp->b_map_count; i++) {
		xfs_buf_ioapply_map(bp, i, &offset, &size, rw);
		if (bp->b_error)
			break;
		if (size <= 0)
			break;	/* all done */
	}
}

void
xfs_buf_iorequest(
	xfs_buf_t		*bp)
{
	trace_xfs_buf_iorequest(bp, _RET_IP_);

	ASSERT(!(bp->b_flags & _XBF_DELWRI_Q));

	xfs_buf_hold(bp);

	/* Set the count to 1 initially, this will stop an I/O
	 * completion callout which happens before we have started
	 * all the I/O from calling xfs_buf_ioend too early.
	 */
	atomic_set(&bp->b_io_remaining, 1);

	_xfs_buf_ioapply(bp);

	xfs_buf_rele(bp);
}

/*
 * Waits for I/O to complete on the buffer supplied.  It returns immediately if
 * no I/O is pending or there is already a pending error on the buffer.  It
 * returns the I/O error code, if any, or 0 if there was no error.
 */
int
xfs_buf_iowait(
	xfs_buf_t		*bp)
{
	trace_xfs_buf_iowait(bp, _RET_IP_);

	trace_xfs_buf_iowait_done(bp, _RET_IP_);
	return bp->b_error;
}

xfs_caddr_t
xfs_buf_offset(
	xfs_buf_t		*bp,
	size_t			offset)
{
	return bp->b_addr + offset;
}

/*
 *	Move data into or out of a buffer.
 */
void
xfs_buf_iomove(
	xfs_buf_t		*bp,	/* buffer to process		*/
	size_t			boff,	/* starting buffer offset	*/
	size_t			bsize,	/* length to copy		*/
	void			*data,	/* data address			*/
	xfs_buf_rw_t		mode)	/* read/write/zero flag		*/
{
	size_t csize = min_t( size_t, bsize, BBTOB( bp->b_io_length) - boff);
	switch (mode) {
		case XBRW_ZERO:
			memset(bp->b_addr, 0, csize);
			break;
		case XBRW_READ:
			memcpy(data, bp->b_addr, csize);
			break;
		case XBRW_WRITE:
			memcpy(bp->b_addr, data, csize);
	}
}

int
xfs_buf_init(void)
{
	xfs_buf_zone = kmem_zone_init_flags(sizeof(xfs_buf_t), "xfs_buf",
						KM_ZONE_HWALIGN, NULL);
	if (!xfs_buf_zone)
		return -ENOMEM;
	return 0;
}

void
xfs_buf_terminate(void)
{
	kmem_zone_destroy(xfs_buf_zone);
}

STATIC int
xfs_setsize_buftarg_flags(
	xfs_buftarg_t		*btp,
	unsigned int		blocksize,
	unsigned int		sectorsize,
	int			verbose)
{
	btp->bt_bsize = blocksize;
	btp->bt_sshift = ffs(sectorsize) - 1;
	btp->bt_smask = sectorsize - 1;
	return 0;
}

/*
 *	When allocating the initial buffer target we have not yet
 *	read in the superblock, so don't know what sized sectors
 *	are being used is at this early stage.  Play safe.
 */
STATIC int
xfs_setsize_buftarg_early(
	xfs_buftarg_t		*btp,
	struct block_device	*bdev)
{
	return xfs_setsize_buftarg_flags(btp,
			PAGE_SIZE, bdev_logical_block_size(bdev), 0);
}

int
xfs_setsize_buftarg(
	xfs_buftarg_t		*btp,
	unsigned int		blocksize,
	unsigned int		sectorsize)
{
	return xfs_setsize_buftarg_flags(btp, blocksize, sectorsize, 1);
}

xfs_buftarg_t *
xfs_alloc_buftarg(
	struct xfs_mount	*mp,
	struct block_device	*bdev,
	int			external,
	const char		*fsname)
{
	xfs_buftarg_t		*btp;

	btp = kmem_zalloc(sizeof(*btp), KM_SLEEP);

	btp->bt_mount = mp;

	INIT_LIST_HEAD(&btp->bt_lru);
	spin_lock_init(&btp->bt_lru_lock);
	if (xfs_setsize_buftarg_early(btp, bdev))
		goto error;
	return btp;

error:
	kmem_free(btp);
	return NULL;
}
