#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

#define __IN_TSLIB__
#include "syscall.h"

static FILE *file;

int open_disk_file( const char *name, const char *mode)
{
	file = fopen( name, mode);
	return file == NULL ? -1 : 0;
}

int read_disk_file( void *ptr, int size, int nmemb)
{
	return fread( ptr, size, nmemb, file);
}

int write_disk_file( void * ptr, int size, int nmemb)
{
	return fwrite( ptr, size, nmemb, file);
}

int seek_disk_file( long offset, int whence)
{
	return fseek( file, offset, whence);
}

int seek_disk_file_set( long offset)
{
	return fseek( file, offset, SEEK_SET);
}

int seek_disk_file_cur( long offset)
{
	return fseek( file, offset, SEEK_CUR);
}

int seek_disk_file_end( long offset)
{
	return fseek( file, offset, SEEK_END);
}

void *mem_cpy( void *dst, const void *src, int n)
{
	return memcpy( dst, src, n);
}

void *mem_move( void *dst, const void *src, int n)
{
	return memmove( dst, src, n);
}

void *mem_set( void *s, int c, long n)
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

int read_disk_file_length( void *ptr, long offset, int size, int nmemb)
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
