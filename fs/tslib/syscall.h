#ifndef __SYSCALL_H__
#define __SYSCALL_H__

int open_file( const char *name, const char *mode);
int read_file( void *ptr, int size, int nmemb);
int write_file( void *ptr, int size, int nmemb);
int seek_file( long offset, int whence);
int seek_file_set( long offset);
int seek_file_cur( long offset);
int seek_file_end( long offset);
void *mem_cpy( void *dst, const void *src, int n);
void *mem_move( void *dst, const void *src, int n);
long str_len( const char *str);
int str_ncmp( const char *s1, const char *s2, long n);
int read_file_length( void *ptr, long offset, int size, int nmemb);

#ifndef __IN_TSLIB__

#define memcpy mem_cpy
#define memmove mem_move
#define memset mem_set
#define strlen str_len

#endif
#endif
