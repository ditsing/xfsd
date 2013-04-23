#ifndef __SYSCALL_H__
#define __SYSCALL_H__

int open_file( const char *name, const char *mode);
int read_file( void *ptr, int size, int nmemb);
int write_file( void *ptr, int size, int nmemb);
int seek_file( long offset, int whence);
int seek_file_set( long offset);
int seek_file_cur( long offset);
int seek_file_end( long offset);
void *mem_set( void *s, int c, long n);
void *mem_cpy( void *dst, const void *src, int n);
void *mem_move( void *dst, const void *src, int n);
long str_len( const char *str);
int str_ncmp( const char *s1, const char *s2, long n);
int read_file_length( void *ptr, long offset, int size, int nmemb);

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
#define strlen str_len

#endif
#endif
