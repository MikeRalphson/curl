#!/usr/bin/perl
# $Id: runtests.pl,v 1.29 2001-05-04 07:47:11 bagder Exp $
#
# Main curl test script, in perl to run on more platforms
#
#######################################################################
# These should be the only variables that might be needed to get edited:

use strict;

use stunnel;

my $srcdir = $ENV{'srcdir'} || '.';
my $HOSTIP="127.0.0.1";
my $HOSTPORT=8999; # bad name, but this is the HTTP server port
my $HTTPSPORT=8433; # this is the HTTPS server port
my $FTPPORT=8921;  # this is the FTP server port
my $FTPSPORT=8821;  # this is the FTPS server port
my $CURL="../src/curl"; # what curl executable to run on the tests
my $LOGDIR="log";
my $TESTDIR="data";
my $SERVERIN="$LOGDIR/server.input"; # what curl sent the server
my $CURLLOG="$LOGDIR/curl.log"; # all command lines run
my $FTPDCMD="$LOGDIR/ftpserver.cmd"; # copy ftp server instructions here

# Normally, all test cases should be run, but at times it is handy to
# simply run a particular one:
my $TESTCASES="all";

# To run specific test cases, set them like:
# $TESTCASES="1 2 3 7 8";

#######################################################################
# No variables below this point should need to be modified
#

my $HTTPPIDFILE=".server.pid";
my $HTTPSPIDFILE=".https.pid";
my $FTPPIDFILE=".ftps.pid";
my $FTPSPIDFILE=".ftpsserver.pid";

# this gets set if curl is compiled with memory debugging:
my $memory_debug=0;

# name of the file that the memory debugging creates:
my $memdump="memdump";

# the path to the script that analyzes the memory debug output file:
my $memanalyze="../memanalyze.pl";

my $checkstunnel = &checkstunnel;

#######################################################################
# variables the command line options may set
#

my $short;
my $verbose;
my $debugprotocol;
my $anyway;
my $gdbthis;      # run test case with gdb debugger
my $keepoutfiles; # keep stdout and stderr files after tests

#######################################################################
# Return the pid of the server as found in the given pid file
#
sub serverpid {
    my $PIDFILE = $_[0];
    open(PFILE, "<$PIDFILE");
    my $PID=<PFILE>;
    close(PFILE);
    return $PID;
}

#######################################################################
# stop the given test server
#
sub stopserver {
    my $PIDFILE = $_[0];
    # check for pidfile
    if ( -f $PIDFILE ) {
        my $PID = serverpid($PIDFILE);

        my $res = kill (9, $PID); # die!
        unlink $PIDFILE; # server is killed

        if($res && $verbose) {
            print "Test server pid $PID signalled to die\n";
        }
        elsif($verbose) {
            print "Test server pid $PID didn't exist\n";
        }
    }
}

#######################################################################
# check the given test server if it is still alive
#
sub checkserver {
    my ($pidfile)=@_;
    my $RUNNING=0;
    my $PID=0;

    # check for pidfile
    if ( -f $pidfile ) {
        my $PID=serverpid($pidfile);
        if ($PID ne "" && kill(0, $PID)) {
            $RUNNING=1;
        }
        else {
            $RUNNING=0;
            $PID = -$PID; # negative means dead process
        }
    }
    else {
        $RUNNING=0;
    }
    return $PID
}

#######################################################################
# start the http server, or if it already runs, verify that it is our
# test server on the test-port!
#
sub runhttpserver {
    my $verbose = $_[0];
    my $RUNNING;

    my $pid = checkserver($HTTPPIDFILE );

    if ($pid <= 0) {
        my $flag=$debugprotocol?"-v ":"";
        system("perl $srcdir/httpserver.pl $flag $HOSTPORT &");
        if($verbose) {
            print "httpd started\n";
        }
    }
    else {
        if($pid > 0) {
            print "httpd ($pid) runs\n";
        }

        # verify that our server is one one running on this port:
        my $data=`$CURL --silent -i $HOSTIP:$HOSTPORT/verifiedserver`;

        if ( $data !~ /WE ROOLZ/ ) {
            print "Another HTTP server is running on port $HOSTPORT\n",
            "Edit runtests.pl to use another port and rerun the test script\n";
            exit;
        }

        if($verbose) {
            print "The running HTTP server has been verified to be our server\n";
        }
    }
}

#######################################################################
# start the https server (or rather, tunnel) if needed
#
sub runhttpsserver {
    my $verbose = $_[0];
    my $STATUS;
    my $RUNNING;
    my $PID=checkserver($HTTPSPIDFILE );

    if($PID > 0) {
        # kill previous stunnel!
        if($verbose) {
            print "kills off running stunnel at $PID\n";
        }
        stopserver($HTTPSPIDFILE);
    }

    my $flag=$debugprotocol?"-v ":"";
    system("perl $srcdir/httpsserver.pl $flag -r $HOSTPORT $HTTPSPORT &");
    if($verbose) {
        print "httpd stunnel started\n";
    }
}

#######################################################################
# start the ftp server if needed
#
sub runftpserver {
    my $verbose = $_[0];
    my $STATUS;
    my $RUNNING;
    # check for pidfile
    my $pid = checkserver ($FTPPIDFILE );

    if ($pid <= 0) {
        my $flag=$debugprotocol?"-v ":"";
        if($debugprotocol) {
            print "* Starts ftp server verbose:\n";
            print "perl $srcdir/ftpserver.pl $flag $FTPPORT &\n";
        }
        system("perl $srcdir/ftpserver.pl $flag $FTPPORT &");
        if($verbose) {
            print "ftpd started\n";
        }
    }
    else {
        if($verbose) {
            print "ftpd ($pid) is already running\n";
        }

        # verify that our server is one one running on this port:
        my $data=`$CURL --silent -i ftp://$HOSTIP:$FTPPORT/verifiedserver`;

        if ( $data !~ /WE ROOLZ/ ) {
            print "Another FTP server is running on port $FTPPORT\n",
            "Edit runtests.pl to use another FTP port and rerun the ",
            "test script\n";
            exit;
        }

        if($verbose) {
            print "The running FTP server has been verified to be our server\n";
        }
    }
}

#######################################################################
# start the ftps server (or rather, tunnel) if needed
#
sub runftpsserver {
    my $verbose = $_[0];
    my $STATUS;
    my $RUNNING;
    my $PID=checkserver($FTPSPIDFILE );

    if($PID > 0) {
        # kill previous stunnel!
        if($verbose) {
            print "kills off running stunnel at $PID\n";
        }
        stopserver($FTPSPIDFILE);
    }

    my $flag=$debugprotocol?"-v ":"";
    my $cmd="perl $srcdir/ftpsserver.pl $flag -r $FTPPORT $FTPSPORT &";
    print "CMD: $cmd\n";
    system($cmd);
    if($verbose) {
        print "ftpd stunnel started\n";
    }
}


#######################################################################
# This function compares two binary files and return non-zero if they
# differ
#
sub comparefiles {
    my $source=$_[0];
    my $dest=$_[1];
    my $res=0;

    open(S, "<$source") ||
        return 1;
    open(D, "<$dest") ||
        return 1;

    # silly win-crap
    binmode S;
    binmode D;

    my $m = 20;
    my ($snum, $dnum, $s, $d);
    do {
        $snum = read(S, $s, $m);
        $dnum = read(D, $d, $m);
        if(($snum != $dnum) ||
           ($s ne $d)) {
            return 1;
        }
    } while($snum);
    close(S);
    close(D);
    return $res;
}

#######################################################################
# Remove all files in the specified directory
#
sub cleardir {
    my $dir = $_[0];
    my $count;
    my $file;

    # Get all files
    opendir(DIR, $dir) ||
        return 0; # can't open dir
    while($file = readdir(DIR)) {
        if($file !~ /^\./) {
            unlink("$dir/$file");
            $count++;
        }
    }
    closedir DIR;
    return $count;
}

#######################################################################
# filter out the specified pattern from the given input file and store the
# results in the given output file
#
sub filteroff {
    my $infile=$_[0];
    my $filter=$_[1];
    my $ofile=$_[2];

    open(IN, "<$infile")
        || return 1;

    open(OUT, ">$ofile")
        || return 1;

    # print "FILTER: off $filter from $infile to $ofile\n";

    while(<IN>) {
        $_ =~ s/$filter//;
        print OUT $_;
    }
    close(IN);
    close(OUT);    
    return 0;
}

#######################################################################
# compare test results with the expected output, we might filter off
# some pattern that is allowed to differ, output test results
#

sub compare {
    # filter off the 4 pattern before compare!

    my $first=$_[0];
    my $sec=$_[1];
    my $text=$_[2];
    my $strip=$_[3];
    my $res;

    if ($strip ne "") {
        filteroff($first, $strip, "$LOGDIR/generated.tmp");
        filteroff($sec, $strip, "$LOGDIR/stored.tmp");
                
        $first="$LOGDIR/generated.tmp";
        $sec="$LOGDIR/stored.tmp";
    }

    $res = comparefiles($first, $sec);
    if ($res != 0) {
        print " $text FAILED\n";
        print "=> diff $first $sec' looks like (\">\" added by runtime):\n";
        print `diff $sec $first`;
        return 1;
    }

    if(!$short) {
        print " $text OK";
    }
    return 0;
}

#######################################################################
# display information about curl and the host the test suite runs on
#
sub displaydata {

    unlink($memdump); # remove this if there was one left

    my $version=`$CURL -V`;
    chomp $version;

    my $curl = $version;

    $curl =~ s/^(.*)(libcurl.*)/$1/g;
    my $libcurl = $2;

    my $hostname=`hostname`;
    my $hosttype=`uname -a`;

    print "********* System characteristics ******** \n",
    "* $curl\n",
    "* $libcurl\n",
    "* Host: $hostname",
    "* System: $hosttype";

    if( -r $memdump) {
        # if this exists, curl was compiled with memory debugging
        # enabled and we shall verify that no memory leaks exist
        # after each and every test!
        $memory_debug=1;
    }
    printf("* Memory debugging: %s\n", $memory_debug?"ON":"OFF");
    printf("* HTTPS server:     %s\n", $checkstunnel?"ON":"OFF");
    printf("* FTPS server:      %s\n", $checkstunnel?"ON":"OFF");
    print "***************************************** \n";
}

#######################################################################
# Run a single specified test case
#

sub singletest {
    my $NUMBER=$_[0];
    my $REPLY="${TESTDIR}/reply${NUMBER}.txt";

    if ( -f "$TESTDIR/reply${NUMBER}0001.txt" ) {
        # we use this file instead to check the final output against
        $REPLY="$TESTDIR/reply${NUMBER}0001.txt";
    }

    # curl command to run
    my $CURLCMD="$TESTDIR/command$NUMBER.txt";

    # this is the valid protocol file we should generate
    my $PROT="$TESTDIR/prot$NUMBER.txt";

    # redirected stdout/stderr here
    $STDOUT="$LOGDIR/stdout$NUMBER";
    $STDERR="$LOGDIR/stderr$NUMBER";

    # if this file exists, we verify that the stdout contained this:
    my $VALIDOUT="$TESTDIR/stdout$NUMBER.txt";

    # if this file exists, we verify upload
    my $UPLOAD="$TESTDIR/upload$NUMBER.txt";

    # if this file exists, it is FTP server instructions:
    my $ftpservercmd="$TESTDIR/ftpd$NUMBER.txt";

    my $CURLOUT="$LOGDIR/curl$NUMBER.out"; # curl output if not stdout

    if(! -r $CURLCMD) {
        if($verbose) {
            # this is not a test
            print "$NUMBER doesn't look like a test case!\n";
            return -1;
        }
    }

    # remove previous server output logfile
    unlink($SERVERIN);

    if(-r $ftpservercmd) {
        # copy the instruction file
        system("cp $ftpservercmd $FTPDCMD");
    }

    # name of the test
    open(N, "<$TESTDIR/name$NUMBER.txt") ||
        return -1; # not a test
    my $DESC=<N>;
    close(N);
    $DESC =~ s/[\r\n]//g;

    print "test $NUMBER...";
    if(!$short) {
        print "[$DESC]\n";
    }

    # get the command line options to use

    open(COMMAND, "<$CURLCMD");
    my $cmd=<COMMAND>;
    chomp $cmd;
    close(COMMAND);

    # make some nice replace operations
    $cmd =~ s/%HOSTIP/$HOSTIP/g;
    $cmd =~ s/%HOSTPORT/$HOSTPORT/g;
    $cmd =~ s/%HTTPSPORT/$HTTPSPORT/g;
    $cmd =~ s/%FTPPORT/$FTPPORT/g;
    $cmd =~ s/%FTPSPORT/$FTPSPORT/g;
    #$cmd =~ s/%HOSTNAME/$HOSTNAME/g;

    if($memory_debug) {
        unlink($memdump);
    }

    my $out="";
    if ( ! -r "$VALIDOUT" ) {
        $out="--output $CURLOUT ";
    }

    # run curl, add -v for debug information output
    my $cmdargs="$out--include -v --silent $cmd";

    my $STDINFILE="$TESTDIR/stdin$NUMBER.txt";
    if(-f $STDINFILE) {
        $cmdargs .= " < $STDINFILE";
    }
    my $CMDLINE="$CURL $cmdargs >$STDOUT 2>$STDERR";

    if($verbose) {
        print "$CMDLINE\n";
    }

    print CMDLOG "$CMDLINE\n";

    my $res;
    # run the command line we built
    if($gdbthis) {
        open(GDBCMD, ">log/gdbcmd");
        print GDBCMD "set args $cmdargs\n";
        print GDBCMD "show args\n";
        close(GDBCMD);
        system("gdb $CURL -x log/gdbcmd");
        $res =0; # makes it always continue after a debugged run
    }
    else {
        $res = system("$CMDLINE");
        $res /= 256;
    }

    my $ERRORCODE = "$TESTDIR/error$NUMBER.txt";

    if ($res != 0) {
        # the invoked command return an error code

        my $expectederror=0;

        if(-f $ERRORCODE) {
            open(ERRO, "<$ERRORCODE");
            $expectederror = <ERRO>;
            close(ERRO);
            # strip non-digits
            $expectederror =~ s/[^0-9]//g;
        }

        if($expectederror != $res) {

            print "*** Failed to invoke curl for test $NUMBER ***\n",
            "*** [$DESC] ***\n",
            "*** The command returned $res for: ***\n $CMDLINE\n";
            return 1;
        }
        elsif(!$short) {
            print " error OK";
        }
    }
    else {
        if(-f $ERRORCODE) {
            # this command was meant to fail, it didn't and thats WRONG
            if(!$short) {
                print " error FAILED";
            }
            return 1;
        }

        if ( -r "$VALIDOUT" ) {
            # verify redirected stdout
            $res = compare($STDOUT, $VALIDOUT, "data");
            if($res) {
                return 1;
            }
        }
        else {
            if (! -r $REPLY && -r $CURLOUT) {
                print "** Missing reply data file for test $NUMBER",
                ", should be similar to $CURLOUT\n";
                return 1;            
            }

            if( -r $CURLOUT ) {
                # verify the received data
                $res = compare($CURLOUT, $REPLY, "data");
                if ($res) {
                    return 1;
                }
            }
        }

        if(-r $UPLOAD) {
             # verify uploaded data
            $res = compare("$LOGDIR/upload.$NUMBER", $UPLOAD, "upload");
            if ($res) {
                return 1;
            }
        }


        if(-r $SERVERIN) {
            if(! -r $PROT) {
                print "** Missing protocol file for test $NUMBER",
                ", should be similar to $SERVERIN\n";
                return 1;
            }

            # The strip pattern below is for stripping off User-Agent: since
            # that'll be different in all versions, and the lines in a
            # RFC1876-post that are randomly generated and therefore are
            # doomed to always differ!
            
            # verify the sent request
            $res = compare($SERVERIN, $PROT, "protocol",
                           "^(User-Agent:|--curl|Content-Type: multipart/form-data; boundary=|PORT ).*\r\n");
            if($res) {
                return 1;
            }
        }

    }

    if(!$keepoutfiles) {
        # remove the stdout and stderr files
        unlink($STDOUT);
        unlink($STDERR);
        unlink($CURLOUT); # remove the downloaded results

        unlink("$LOGDIR/upload.$NUMBER");  # remove upload leftovers
    }

    unlink($FTPDCMD); # remove the instructions for this test

    if($memory_debug) {
        if(! -f $memdump) {
            print "\n** ALERT! memory debuggin without any output file?\n";
        }
        else {
            my @memdata=`$memanalyze < $memdump`;
            my $leak=0;
            for(@memdata) {
                if($_ ne "") {
                    # well it could be other memory problems as well, but
                    # we call it leak for short here
                    $leak=1;
                }
            }
            if($leak) {
                print "\n** MEMORY FAILURE\n";
                print @memdata;
                return 1;
            }
            else {
                if(!$short) {
                    print " memory OK";
                }
            }
        }
    }
    if($short) {
        print "OK";
    }
    print "\n";

    return 0;
}

my %run;

sub serverfortest {
    my ($testnum)=@_;

    if($testnum< 100) {
        # 0 - 99 is for HTTP
        if(!$run{'http'}) {
            runhttpserver($verbose);
            $run{'http'}=$HTTPPIDFILE;
        }
    }
    elsif($testnum< 200) {
        # 100 - 199 is for FTP
        if(!$run{'ftp'}) {
            runftpserver($verbose);
            $run{'ftp'}=$FTPPIDFILE;
        }
    }
    elsif($testnum< 300) {
        # 200 - 299 is for FILE, no server!
        $run{'file'}="moo";
    }
    elsif($testnum< 400) {
        # 300 - 399 is for HTTPS, two servers!

        if(!$checkstunnel) {
            # we can't run https tests without stunnel
            return 1;
        }

        if(!$run{'http'}) {
            runhttpserver($verbose);
            $run{'http'}=$HTTPPIDFILE;
        }
        if(!$run{'https'}) {
            runhttpsserver($verbose);
            $run{'https'}=$HTTPSPIDFILE;
        }
    }
    elsif($testnum< 500) {
        # 400 - 499 is for FTPS, also two servers

        if(!$checkstunnel) {
            # we can't run https tests without stunnel
            return 1;
        }
        if(!$run{'ftp'}) {
            runftpserver($verbose);
            $run{'ftp'}=$FTPPIDFILE;
        }
        if(!$run{'ftps'}) {
            runftpsserver($verbose);
            $run{'ftps'}=$FTPSPIDFILE;
        }
    }
    else {
        print "Bad test number, no server available\n";
        return 100;
    }
    sleep 1; # give a second for the server(s) to startup
    return 0; # ok
}

#######################################################################
# Check options to this test program
#

my $number=0;
my $fromnum=-1;
my @testthis;
do {
    if ($ARGV[0] eq "-v") {
        # verbose output
        $verbose=1;
    }
    elsif ($ARGV[0] eq "-d") {
        # have the servers display protocol output 
        $debugprotocol=1;
    }
    elsif ($ARGV[0] eq "-g") {
        # run this test with gdb
        $gdbthis=1;
    }
    elsif($ARGV[0] eq "-s") {
        # short output
        $short=1;
    }
    elsif($ARGV[0] eq "-a") {
        # continue anyway, even if a test fail
        $anyway=1;
    }
    elsif($ARGV[0] eq "-k") {
        # keep stdout and stderr files after tests
        $keepoutfiles=1;
    }
    elsif($ARGV[0] eq "-h") {
        # show help text
        print <<EOHELP
Usage: runtests.pl [options]
  -a       continue even if a test fails
  -d       display server debug info
  -g       run the test case with gdb
  -h       this help text
  -k       keep stdout and stderr files present after tests
  -s       short output
  -v       verbose output
  [num]    like "5 6 9" or " 5 to 22 " to run those tests only
EOHELP
    ;
        exit;
    }
    elsif($ARGV[0] =~ /^(\d+)/) {
        $number = $1;
        if($fromnum >= 0) {
            for($fromnum .. $number) {
                push @testthis, $_;
            }
            $fromnum = -1;
        }
        else {
            push @testthis, $1;
        }
    }
    elsif($ARGV[0] =~ /^to$/i) {
        $fromnum = $number+1;
    }
} while(shift @ARGV);

if($testthis[0] ne "") {
    $TESTCASES=join(" ", @testthis);
}


#######################################################################
# Output curl version and host info being tested
#

displaydata();

#######################################################################
# clear and create logging directory:
#
cleardir($LOGDIR);
mkdir($LOGDIR, 0777);

#######################################################################
# First, start our test servers
#

#runhttpserver($verbose);
#runftpserver($verbose);
#runhttpsserver($verbose);

#sleep 1; # start-up time

#######################################################################
# If 'all' tests are requested, find out all test numbers
#

if ( $TESTCASES eq "all") {
    # Get all commands and find out their test numbers
    opendir(DIR, $TESTDIR) || die "can't opendir $TESTDIR: $!";
    my @cmds = grep { /^command([0-9]+).txt/ && -f "$TESTDIR/$_" } readdir(DIR);
    closedir DIR;

    $TESTCASES=""; # start with no test cases

    # cut off everything but the digits 
    for(@cmds) {
        $_ =~ s/[a-z\/\.]*//g;
    }
    # the the numbers from low to high
    for(sort { $a <=> $b } @cmds) {
        $TESTCASES .= " $_";
    }
}

#######################################################################
# Start the command line log
#
open(CMDLOG, ">$CURLLOG") ||
    print "can't log command lines to $CURLLOG\n";

#######################################################################
# The main test-loop
#

my $failed;
my $testnum;
my $ok=0;
my $total=0;
my $skipped=0;

foreach $testnum (split(" ", $TESTCASES)) {

    my $serverproblem = serverfortest($testnum);

    if($serverproblem) {
        # there's a problem with the server, don't run
        # this particular server, but count it as "skipped"
        $skipped++;
        next;
    }

    my $error = singletest($testnum);
    if(-1 != $error) {
        # valid test case number
        $total++;
    }
    if($error>0) {
        if(!$anyway) {
            # a test failed, abort
            print "\n - abort tests\n";
            last;
        }
        $failed.= "$testnum ";
    }
    elsif(!$error) {
        $ok++;
    }

    # loop for next test
}

#######################################################################
# Close command log
#
close(CMDLOG);

#######################################################################
# Tests done, stop the servers
#

for(keys %run) {
    stopserver($run{$_}); # the pid file is in the hash table
}
#stopserver($FTPPIDFILE);
#stopserver($PIDFILE);
#stopserver($HTTPSPIDFILE);

if($total) {
    print "$ok tests out of $total reported OK\n";

    if($ok != $total) {
        print "These test cases failed: $failed\n";
    }
}
else {
    print "No tests were performed!\n";
}
if($skipped) {
    print "$skipped tests were skipped due to server problems\n";
}
