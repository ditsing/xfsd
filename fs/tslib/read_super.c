#include "xfsd.h"
#include "read_super.h"
#include "xfsd_types.h"
#include "syscall.h"

#include "xfs/xfs_types.h"
#include "xfs/xfs_sb.h"

#include "xfs/xfs_inum.h"
#include "linux/rbtree.h"
#include "xfs/xfs_ag.h"

#include "xfs/xfs_ialloc_btree.h"
#include "xfs/xfs_alloc_btree.h"
#include "xfs/xfs_bmap_btree.h"
#include "xfs/xfs_btree.h"

xfs_sb_t sb;
static xfs_agf_t agf;
static xfs_agi_t agi;
static xfs_agfl_t agfl[10];

int read_block( int offset, void *mem, int nmeb)
{
	// Here is a bug: we cannot seek files larger that 2GB.
	if (  ( seek_disk_file_set( offset * ( long) sb.sb_blocksize)) == -1)
	{
		return -1;
	}

	return read_disk_file( mem, sb.sb_blocksize, nmeb);
}

int read_super_init( struct xfs_sb *sbp)
{
	sb = *sbp;

	seek_disk_file_set( sb.sb_sectsize);
	read_disk_file( ( void *)&agf, sizeof( agf), 1);

	seek_disk_file_set( sb.sb_sectsize * 2);
	read_disk_file( ( void *)&agi, sizeof( agi), 1);

	seek_disk_file_set( sb.sb_sectsize * 3);
	read_disk_file( ( void *)agfl, sizeof( xfs_agfl_t), be32_to_cpu( agf.agf_flcount));
	return 0;
}

void get_sb_magic( char * magic)
{
	char *cur = ( char *)&(sb.sb_magicnum);
	mem_cpy( magic, cur, 4);
}

unsigned int get_sb_magic_int()
{
	return sb.sb_magicnum;
}

int get_sbs_count()
{
	return XFS_SB_NUM_BITS;
}

xfs_sb_t get_sb()
{
	return sb;
}

int get_dsb_size()
{
	return sizeof( xfs_dsb_t);
}

int get_sb_size()
{
	return sizeof( xfs_sb_t);
}

int get_sb_features2()
{
	return sb.sb_features2;
}

int get_sb_sectsize()
{
	return sb.sb_sectsize;
}

void get_agf_magic( char * magic)
{
	char *cur = ( char *)&(agf.agf_magicnum);
	mem_cpy( magic, cur, 4);
}

int get_agf_free_block( int count)
{
	int flcount = be32_to_cpu( agf.agf_flcount);
	int ret = 0;
	if ( count <= flcount)
	{
		ret = count + be32_to_cpu( agf.agf_flfirst);
		ret = be32_to_cpu( agfl[ret].agfl_bno[0]);
	}
	return ret;
}

int get_agf_flcount()
{
	return be32_to_cpu( agf.agf_flcount);
}

int get_agf_versionnum()
{
	return be32_to_cpu( agf.agf_versionnum);
}


int get_sb_ifree()
{
	return sb.sb_ifree;
}

__uint64_t get_sb_rootino()
{
	return sb.sb_rootino;
}

__uint64_t get_agi_root()
{
	return ( xfs_daddr_t)be32_to_cpu( agi.agi_root);
}

__uint32_t get_agi_seqno()
{
	return be32_to_cpu( agi.agi_seqno);
}
