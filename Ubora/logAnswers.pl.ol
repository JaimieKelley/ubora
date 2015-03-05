#!/usr/bin/perl -w
use strict;
# Copies manswer panswer and query files to a directory for later use.

my $test_iden = 0;
if (open (EXPFILE, "myexperiment") ) {
    $test_iden = <EXPFILE>;
    chomp($test_iden);
    close(EXPFILE);
}
my @test_cfgs = split(":",$ARGV[0]);
my $panswer = $ARGV[0];
my $manswer = $ARGV[1];
my $qanswer = sprintf("%s:query",$test_cfgs[0]);

open (CONF,"ubora.conf");
my $redisHost = "";
my $possibleHost = "";
my $redisPort = 1055;
while (<CONF>) {
    if ($_ =~ /^storageport:(.*)$/) {
	$redisPort = $1;
	chomp($redisPort);
    }
    if ($_ =~ /^fullnode:(.*)$/) {
	$possibleHost = $1;
	chomp($possibleHost);
    }
    if ($redisHost =~ /\s*/)  {
	$redisHost = $possibleHost;
    }
}

print "loganswer: mkdir /root/tests/$test_iden\n";
print "loganswer: ./redis-stable/src/redis-cli -h $redisHost -p $redisPort get $panswer > /root/tests/$test_iden/$test_cfgs[0]-panswer\n";
print "loganswer: ./redis-stable/src/redis-cli -h $redisHost -p $redisPort get $manswer > /root/tests/$test_iden/$test_cfgs[0]-manswer\n";
print "loganswer: ./redis-stable/src/redis-cli -h $redisHost -p $redisPort get $qanswer > /root/tests/$test_iden/$test_cfgs[0]-qanswer\n";

`mkdir /root/tests/$test_iden`;
` ./redis-stable/src/redis-cli -h $redisHost -p $redisPort get $panswer > /root/tests/$test_iden/$test_cfgs[0]-panswer`;
` ./redis-stable/src/redis-cli -h $redisHost -p $redisPort get $manswer > /root/tests/$test_iden/$test_cfgs[0]-manswer`;
` ./redis-stable/src/redis-cli -h $redisHost -p $redisPort get $qanswer > /root/tests/$test_iden/$test_cfgs[0]-qanswer`;
