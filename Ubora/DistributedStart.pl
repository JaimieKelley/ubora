#!/usr/bin/perl -w

use strict;
# This script uses ssh to remotely log in and start 
# Ubora minor on all nodes specified in config file
#
# For simplicity in design, I simply read all record and full nodes
# from the config into an array.  Then I iterate of the array
# doing ssh and scp as needed.
# cstewart 05/16/2014
my $INSTALL_DIR=`pwd`;
if (-e "INSTALL_DIR") {
    $INSTALL_DIR=`cat INSTALL_DIR`;
}
$INSTALL_DIR =~ s/^\s+|\s+$//g;

print "Install Directory: $INSTALL_DIR\n";
my $cfg_file = sprintf("%s/ubora.conf",$INSTALL_DIR);

my @dst_node;
my $CFG_THIS;
my $compile= "";
my $mode = "";

if ($#ARGV == 1){
    $mode = $ARGV[0];
    $compile= $ARGV[1];
}
else {
    print "Inputrs are either: minor compile/nocompile \n";
    exit(-1);
}
open ($CFG_THIS, $cfg_file);
while (<$CFG_THIS>) {
    if (/^fullnode:(.*)$/) {
	my $tmp_node = $1;
	chomp($tmp_node);
	$dst_node[$#dst_node+1] = $tmp_node;
    }
   elsif (/^recordnode:(.*)$/) {
	my $tmp_node = $1;
	chomp($tmp_node);
	$dst_node[$#dst_node+1] = $tmp_node;
    }
}

my $cur_node;
foreach $cur_node (@dst_node) {
    print "scp $INSTALL_DIR/ubora.conf $cur_node:$INSTALL_DIR/ubora.conf\n";
    print "ssh $cur_node \"cd $INSTALL_DIR/; ./start.sh clean; sleep 6; ./start.sh $mode $compile\n\" ";
    `scp $INSTALL_DIR/ubora.conf $cur_node:$INSTALL_DIR/ubora.conf`;
    `scp $INSTALL_DIR/INSTALL_DIR $cur_node:$INSTALL_DIR/INSTALL_DIR`;
    `ssh $cur_node \"cd $INSTALL_DIR/; ./start.sh clean; sleep 4; ./start.sh $mode $compile\"`;
}
