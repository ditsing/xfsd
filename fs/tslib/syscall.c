#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

#define __IN_TSLIB__
#include "syscall.h"

void *mem_cpy( void *dst, const void *src, size_t n)
{
	return memcpy( dst, src, n);
}

void *mem_move( void *dst, const void *src, size_t n)
{
	return memmove( dst, src, n);
}

void *mem_set( void *s, size_t c, long n)
{
	return memset( s, c, n);
}

int mem_cmp( const void *s1, const void *s2, size_t n)
{
	return memcmp( s1, s2, n);
}

long str_len( const char *str)
{
	return strlen( str);
}

int str_ncmp( const char *s1, const char *s2, long n)
{
	return strncmp( s1, s2, n);
}

int read_disk_file_length( void *ptr, long offset, size_t size, size_t nmemb)
{
	seek_disk_file_set( offset);
	return read_disk_file( ptr, size, nmemb);
}

int print( const char *format, ...)
{
	va_list arg;
	int ret;
	va_start( arg, format);
	ret = vprintf( format, arg);
	va_end( arg);

	return ret;
}

int eprint( const char *format, ...)
{
	va_list arg;
	int ret;

	va_start( arg, format);
	ret = vfprintf( stderr, format, arg);
	va_end( arg);

	return ret;
}

void *mem_alloc( size_t size)
{
	return malloc( size);
}

void *mem_zalloc( size_t size)
{
	return calloc( 1, size);
}

void mem_free( const void *p)
{
	return free( ( void *) p);
}

void *mem_realloc( void *p, size_t size)
{
	return realloc( p, size);
}
