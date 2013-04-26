#include "tslib/tslib.h"
#include "xfsd.h"

#include "xfsd_types.h"
#include "xfs/xfs_types.h"
#include "xfs/xfs_sb.h"
#include "xfs/xfs_mount.h"

#include "radix-tree.h"


xfs_mount_t *mount;

int tslib_init()
{
	radix_tree_init();

	int error;
	error = xfs_fs_init();
	if ( error)
	{
		goto out;
	}

	error = open_file( "disk/xfs.lib", "r");
	if ( error)
	{
		goto out_fs;
	}

	error = xfs_mount( &mount);
	if ( error)
	{
		goto out_umount;
	}

	return 0;

 out_umount:
 out_fs:
	xfs_fs_exit();
 out:
	return error;
}

xfs_sb_t *tslib_get_sb()
{
	return &(mount->m_sb);
}
