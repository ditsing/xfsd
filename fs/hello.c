#include <stdio.h>
#include <memory.h>
#include "tslib/tslib.h"
#include "tslib/read_super.h"
#include "tslib/read_file2.h"

int main()
{
	char magic[100] = { 0};
	int ret;
	char tmp[10000];
	tslib_file_p fp;
	if ( tslib_init())
	{
		printf("INIT ERROR!\n");
		return 0;
	}
	read_super_init( tslib_get_sb());

	get_sb_magic( magic);
	printf("sb_magic \t\t\t%s\n", magic);
	printf("disk sb_magic int \t\t%u\n", get_sb_magic_int());
	printf("sbs count \t\t\t%d\n", get_sbs_count());
	printf("disk sb size \t\t\t%d\n", get_dsb_size());
	printf("sb size \t\t\t%d\n", get_sb_size());
	printf("sb features2 \t\t\t0x%x\n", get_sb_features2());
	printf("sb sectsize \t\t\t%d\n", get_sb_sectsize());
	printf("sb inode free \t\t\t%d\n", get_sb_ifree());

	get_agf_magic( magic);
	printf("agf magic \t\t\t%s\n", magic);
	printf("agf flcount \t\t\t%d\n", get_agf_flcount());
	printf("agf version num \t\t%d\n", get_agf_versionnum());
	printf("agf free block 1 \t\t%d\n", get_agf_free_block( 0));
	printf("agf free block 2 \t\t%d\n", get_agf_free_block( 1));
	printf("agf free block 3 \t\t%d\n", get_agf_free_block( 2));
	printf("agf free block 4 \t\t%d\n", get_agf_free_block( 3));

	printf("Begin to read disk\n");
	fp = open_file2("xfsd_types.h");
	if ( fp)
	{
		ret = read_file2( fp, tmp, 10000);
		printf("%s\n\n\n\n", tmp);
		printf("return %d\n", ret);
	}
	else
	{
		printf("Got nothing!\n");
	}

	fp = open_file2("xfsd_types.h");
	if ( !fp)
	{
		printf("Got nothing!\n");
	}

	memset( tmp, 0, sizeof( tmp));
	fp = open_file2("/xfsd/xfsd.h");
	if ( fp)
	{
		ret = read_file2( fp, tmp, 10000);
		printf("return %d\n", ret);
		printf("%s\n\n\n\n", tmp);
	}
	else
	{
		printf("Got nothing!\n");
	}

	tslib_exit();

	return 0;
}
