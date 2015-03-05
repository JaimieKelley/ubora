#!/usr/bin/perl -w
#  This program copies the ubora.conf file
#  to all nodes listed therein
#
#  It should be run in the local directory
#  of Ubora
#  c. stewart-- May 12, 2012


use strict;

open (UBORACONF, "ubora.conf");

my @ubor_node;
my @ubor_file = ("ubora.conf" "INSTALL_DIR");

my $INSTALL_DIR=`pwd`;
if (-e "INSTALL_DIR") {
    $INSTALL_DIR=`cat INSTALL_DIR`;
}
$INSTALL_DIR =~ s/^\s+|\s+$//g;


while (<UBORACONF>) {
    my $curr_line = $_;
    $curr_line = lc($curr_line);

    if ($curr_line=~/#.*/) {
	# Ignore comments
    }
    elsif ($curr_line=~/^fullnode:\s*(\S*)$/) {
	my $curr_node = $1;
	chomp($curr_node);
	$ubor_node[$#ubor_node+1] = $curr_node;
    }
    elsif ($curr_line=~/^recordnode:\s*(\S*)$/) {
	my $curr_node = $1;
	chomp($curr_node);
	$ubor_node[$#ubor_node+1] = $curr_node;
    }
}

my $dcnf_item = 0;
while ($dcnf_item <= $#ubor_file) {
    my $dcnf_iter = 0;
    while ($dcnf_iter <= $#ubor_node) {
	print "scp $ubor_file[$dcnf_item]  $ubor_node[$dcnf_iter]:/root/Ubora/$ubor_file[$dcnf_item]\n";
	`scp $ubor_file[$dcnf_item]  $ubor_node[$dcnf_iter]:/root/Ubora/$ubor_file[$dcnf_item]`;
	$dcnf_iter++;
    }
    $dcnf_item++;
}
