#ifndef __TSLIB_READ_FILE2_H__
#define __TSLIB_READ_FILE2_H__

struct tslib_file;
typedef struct tslib_file tslib_file_t;
typedef tslib_file_t *tslib_file_p;


typedef struct xfsd_buf
{
	void * cur;
	unsigned long space;
	unsigned long unit;
	unsigned long long offset;
} xfsd_buf_t;

int tslib_file_init();
tslib_file_p open_file2( const char *name);
tslib_file_p open_file2_relative( tslib_file_p dir, const char *name);
ssize_t read_file2( tslib_file_p fp, void *ptr, size_t size);
int read_file2_by_name( const char *name, void *ptr, size_t size);

unsigned long long tslib_file_size( tslib_file_p f);
int tslib_file_is_dir( tslib_file_p f);
long long tslib_file_inode_number( tslib_file_p f);
tslib_file_p tslib_file_get_root_dir();
bool tslib_file_seek( tslib_file_p f, unsigned long long offset);


typedef int (* filldir_t)( void *buf, const char *name, int len, long long offset, unsigned long long index, unsigned type);
int tslib_readdir( tslib_file_p f, xfsd_buf_t *buf, filldir_t fill);


#endif
