#!/usr/bin/env perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 1998 - 2005, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at http://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# $Id: keywords.pl,v 1.1 2005-04-15 23:48:58 bagder Exp $
###########################################################################

use strict;

@INC=(@INC, $ENV{'srcdir'}, ".");

require "getpart.pm"; # array functions

my $srcdir = $ENV{'srcdir'} || '.';
my $TESTDIR="$srcdir/data";

# Get all commands and find out their test numbers
opendir(DIR, $TESTDIR) || die "can't opendir $TESTDIR: $!";
my @cmds = grep { /^test([0-9]+)$/ && -f "$TESTDIR/$_" } readdir(DIR);
closedir DIR;

my $TESTCASES; # start with no test cases

# cut off everything but the digits
for(@cmds) {
    $_ =~ s/[a-z\/\.]*//g;
}
# the the numbers from low to high
for(sort { $a <=> $b } @cmds) {
    $TESTCASES .= " $_";
}

my $t;
for $t (split(/ /, $TESTCASES)) {
    if(loadtest("${TESTDIR}/test${t}")) {
        # bad case
        next;
    }
    my @what = getpart("info", "keywords");

    for(@what) {
        print "Test $t: $_";
    }
}


