/* $Id: bitncmp.h,v 1.1 2005-04-08 19:46:46 dmeglio Exp $ */

/*
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */

#ifndef BITNCMP_H
#define BITNCMP_H

#ifndef HAVE_BITNCMP
int ares_bitncmp(const void *l, const void *r, int n);
#else
#define ares_bitncmp(x,y,z) bitncmp(x,y,z)
#endif

#endif /* BITNCMP_H */
