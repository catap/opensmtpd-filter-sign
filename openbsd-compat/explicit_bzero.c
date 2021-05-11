/*  $OpenBSD: explicit_bzero.c,v 1.4 2015/08/31 02:53:57 guenther Exp $ */
/*
 * Public domain.
 * Written by Matthew Dempsky.
 */

#include "openbsd-compat.h"

#include <string.h>

void
explicit_bzero(void *buf, size_t len)
{
	memset(buf, 0, len);
}
