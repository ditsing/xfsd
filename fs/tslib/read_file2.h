#ifndef __TSLIB_READ_FILE2_H__
#define __TSLIB_READ_FILE2_H__

struct tslib_file;
typedef struct tslib_file tslib_file_t;
typedef tslib_file_t *tslib_file_p;

int tslib_file_init();
tslib_file_p open_file2( const char *name);
tslib_file_p open_file2_relative( tslib_file_p dir, const char *name);
int read_file2( tslib_file_p fp, void *ptr, size_t size);
int read_file2_by_name( const char *name, void *ptr, size_t size);

long long tslib_file_size( tslib_file_p f);
int tslib_file_is_dir( tslib_file_p f);
long long tslib_file_inode_number( tslib_file_p f);
tslib_file_p tslib_file_get_root_dir();

#endif
