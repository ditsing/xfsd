#ifndef __READ_SUPER_H__
#define __READ_SUPER_H__

struct xfs_sb;
int read_super_init( struct xfs_sb *sbp);
void get_sb_magic( char *);
unsigned int get_dsb_magic_int();
int get_sbs_count();
int get_dsb_size();
int get_sb_size();
int get_sb_features2();
int get_sb_sectsize();
void get_agf_magic( char * magic);
int get_agf_free_block( int count);
int get_agf_flcount();
int get_agf_versionnum();
int get_sb_ifree();
__uint64_t get_sb_rootino();
__uint64_t get_agi_root();
__uint32_t get_agi_seqno();

#endif
