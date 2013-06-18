//This file is used to build a precompiled header
#include "stdafx.h"

VOID xfsd_driver_wchar_to_char( CHAR *dest, const WCHAR *source, ULONG len)
{
	ULONG i;
	for (i = 0; i < len; i++)
	{
		dest[i] = (CHAR) source[i];
	}
}

VOID xfsd_driver_char_to_wchar( WCHAR *dest, const CHAR *source, ULONG len)
{
	ULONG i;
	for (i = 0; i < len; i++)
	{
		dest[i] = (WCHAR) source[i];
	}
}

VOID xfsd_driver_init_string( PUNICODE_STRING dest, PUNICODE_STRING source)
{
	dest->Length = dest->MaximumLength = source->Length;
	if ( dest->Buffer)
	{
		ExFreePool( dest->Buffer);
	}
	dest->Buffer = (PWCHAR) ExAllocatePool( NonPagedPool, source->Length * 2);
	RtlCopyUnicodeString( dest, source);
}

