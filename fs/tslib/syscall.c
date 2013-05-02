#ifdef WIN32
#define __IN_TSLIB__
#include <ntddk.h>
#include "syscall.h"

void *ddk_mem_zalloc( size_t size, unsigned flags)
{
	void *ptr = ddk_mem_alloc( size, flags);
	if ( ptr)
	{
		mem_set( ptr, 0, size);
	}
	return ptr;
}

void *ddk_mem_alloc( size_t size, unsigned flags)
{
	return ExAllocatePool( flags ? PagedPool : NonPagedPool, size);
}

void ddk_mem_free( const void *ptr)
{
	ExFreePool( ( void *)ptr);
}

#else
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>

#define __IN_TSLIB__
#include "syscall.h"

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
#endif

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

int to_lower( int c)
{
	return tolower( c);
}
