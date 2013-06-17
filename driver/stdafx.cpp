//This file is used to build a precompiled header
#include "stdafx.h"

VOID xfsd_driver_wchar_to_char( CHAR *dest, WCHAR *source, ULONG len)
{
	ULONG i;
	for (i = 0; i < len; i++)
	{
		dest[i] = (WCHAR) source[i];
	}
}

VOID xfsd_driver_char_to_wchar( WCHAR *dest, CHAR *source, ULONG len)
{
	ULONG i;
	for (i = 0; i < len; i++)
	{
		dest[i] = (CHAR) source[i];
	}
}