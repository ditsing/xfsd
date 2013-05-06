#include "tslib/tslib.h"
#include "xfsd.h"

#include "xfsd_types.h"
#include "xfs/xfs_types.h"
#include "xfs/xfs_sb.h"
#include "xfs/xfs_mount.h"

#include "radix-tree.h"
#include "read_file2.h"


xfs_mount_t *mount;

int tslib_init()
{
	int error;
	radix_tree_init();
	tslib_file_init();

	error = xfs_fs_init();
	if ( error)
	{
		goto out;
	}

	error = open_disk_file( "disk/xfs.lib", "r");
	if ( error)
	{
		goto out_fs;
	}

	error = xfs_mount( &mount);
	if ( error)
	{
		goto out_close_file;
	}

	return 0;

 out_close_file:
	close_disk_file();
 out_fs:
	xfs_fs_exit();
 out:
	return error;
}

void tslib_exit()
{
	xfs_unmount( &mount);
	close_disk_file();
	xfs_fs_exit();
}

xfs_sb_t *tslib_get_sb()
{
	return &(mount->m_sb);
}
