#ifndef __SYSCALL_H__
#define __SYSCALL_H__

void *mem_set( void *s, size_t c, long n);
void *mem_cpy( void *dst, const void *src, size_t n);
void *mem_move( void *dst, const void *src, size_t n);
int mem_cmp( const void *s1, const void *s2, size_t n);
long str_len( const char *str);
int str_ncmp( const char *s1, const char *s2, long n);
int read_disk_file_length( void *ptr, long offset, size_t size, size_t nmemb);
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
