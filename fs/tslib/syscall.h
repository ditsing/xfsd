#ifndef __SYSCALL_H__
#define __SYSCALL_H__

int open_disk_file( const char *name, const char *mode);
int read_disk_file( void *ptr, int size, int nmemb);
int write_disk_file( void *ptr, int size, int nmemb);
int seek_disk_file( long offset, int whence);
int seek_disk_file_set( long offset);
int seek_disk_file_cur( long offset);
int seek_disk_file_end( long offset);
void *mem_set( void *s, int c, long n);
void *mem_cpy( void *dst, const void *src, int n);
void *mem_move( void *dst, const void *src, int n);
int mem_cmp( const void *s1, const void *s2, size_t n);
long str_len( const char *str);
int str_ncmp( const char *s1, const char *s2, long n);
int read_disk_file_length( void *ptr, long offset, int size, int nmemb);
int print( const char *format, ...);

void *mem_alloc( size_t size);
void *mem_zalloc( size_t size);
void mem_free( const void *p);
void *mem_realloc( void *p, size_t size);

#ifndef __IN_TSLIB__

#define malloc mem_alloc
#define free mem_free

#define memcpy mem_cpy
#define memmove mem_move
#define memset mem_set
#define memcmp mem_cmp
#define strlen str_len

#endif
#endif
