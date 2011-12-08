/*
 * This file is part of MSM security plugin
 * Greatly based on the code of MSSF security plugin
 *
 * Copyright (C) 2010 Nokia Corporation and/or its subsidiary(-ies).
 *
 * Contact: Tero Aho <ext-tero.aho@nokia.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "msm.h"

/* Wild card strcmp, wild cards * and ? allowed in s1 */
int strwcmp(const char *s1, const char *s2)
{
    char *c1 = (char *)s1;
    char *c2 = (char *)s2;
    char *star = NULL;
    int ok = 0;

    if (!s1 || !s2) return 1;

    while (*c2) {
	if (*c1 == '*') {
	    if (star && (c1 - star) != ok)
		goto fail;
	    c1++;
	    star = c1;
	    ok = 0;
	}
	if (*c1 == '?') {
	    c1++;
	    c2++;
	    continue;
	}	    
	if (*c1 == *c2) {
	    c1++;
	    c2++;
	    ok++;
	} else if (star) {
	    c1 = star;
	    c2++;
	    ok = 0;
	} else goto fail;
    }
    if (*c1 == '\0' && *c2 == '\0' && (!star || (c1 - star) == ok))
	return 0;
 fail:
    return (*c1 < *c2 ? -1 : 1);
}

