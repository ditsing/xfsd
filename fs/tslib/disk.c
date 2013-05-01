#include <stdio.h>
#include "disk.h"

#ifdef WIN32
#include <ntddk.h>

static HANDLE file;

int open_disk_file( const char *name, const char *mode)
{
	OBJECT_ATTRIBUTES attr;
	IO_STATUS_BLOCK ios;
	UNICODE_STRING filename;
	NTSTATUS nts;

	RtlInitUnicodeString( &filename, L"\\Device\\HarddiskVolume1\\xfsd\disk\xfs.lib");
	InitializeObjectAttributes( &attr, &filename, OBJ_CASE_INSENSITIVE, NULL, NULL);
	nts = ZwOpenFile( &file, GENERIC_ALL, &attr, &ios, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

	return !NT_SUCCESS(nts);
}

#else
static FILE *file;

int open_disk_file( const char *name, const char *mode)
{
	file = fopen( name, mode);
	return file == NULL ? -1 : 0;
}

int read_disk_file( void *ptr, size_t size, size_t nmemb)
{
	return fread( ptr, size, nmemb, file);
}

int write_disk_file( void * ptr, size_t size, size_t nmemb)
{
	return fwrite( ptr, size, nmemb, file);
}

int seek_disk_file( long offset, size_t whence)
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

int tslib_read_disk_block( long long block, void *data, int bytes)
{
	// Overflow.
	long long offset = block * BLK_SIZE;
	seek_disk_file_set( offset);
	return read_disk_file( data, bytes, 1) != 1;
}

int read_disk_file_length( void *ptr, long offset, size_t size, size_t nmemb)
{
	seek_disk_file_set( offset);
	return read_disk_file( ptr, size, nmemb);
}

#endif
