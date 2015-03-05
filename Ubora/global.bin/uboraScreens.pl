#!/usr/bin/perl -w

use strict;

#  This command sets up the screens needed for Ubora
#  It will not set up screens that already exist.  This means
#  it can be multiple times without corrupting state or leaking
#  file descriptors

my @screen_trgt = ("borg", "mitm", "betterProp", "filterDown","redis");
my @screen_oput = `screen -ls`;

my $screen_news;
my $screen_line;


open(INFILE, "INSTALL_DIR");
my $INSTALL_DIR = <INFILE>;
close(INFILE);

foreach $screen_news (@screen_trgt) {
    my $absent_scrn = 1;
    foreach $screen_line (@screen_oput) {
	if ($screen_line =~ /.*\.$screen_news\s/) {
	    print "Found existing screen: $screen_news $screen_line";
	    $absent_scrn = 0;
	}
    }
    if ($absent_scrn == 1) {
	`screen -dmS $screen_news`;
	sleep 2;
	`screen -S $screen_news  -p0 -X stuff \$'export LD_LIBRARY_PATH=/usr/local/lib\\n'`;
	sleep 2;
	`screen -S $screen_news  -p0 -X stuff \$'cd $INSTALL_DIR\n'`;
    }
}

