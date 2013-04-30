#ifndef __TSLIB_DISK_H__
#define __TSLIB_DISK_H__

#define BLK_SIZE (512)

int open_disk_file( const char *name, const char *mode);
int read_disk_file( void *ptr, size_t size, size_t nmemb);
int write_disk_file( void *ptr, size_t size, size_t nmemb);
int seek_disk_file( long offset, size_t whence);
int seek_disk_file_set( long offset);
int seek_disk_file_cur( long offset);
int seek_disk_file_end( long offset);
int tslib_read_disk_block( long long block, void *data, int bytes);
int read_disk_file_length( void *ptr, long offset, size_t size, size_t nmemb);
#endif
