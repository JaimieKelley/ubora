#!/usr/bin/perl -w
use strict;
# Copies manswer panswer and query files to a directory for later use.

my $DEBUG = 0;
my $test_iden = 0;
if (open (EXPFILE, "myexperiment") ) {
    $test_iden = <EXPFILE>;
    chomp($test_iden);
    close(EXPFILE);
}


my @test_cfgs = split(":",$ARGV[0]);
my $pkey = $ARGV[0];
my $mkey = $ARGV[1];
my $qkey = sprintf("%s:query",$test_cfgs[0]);

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

my $debugfile = "/dev/null";
if ($DEBUG == 1) {
    $debugfile = "zout.netflixparseandlog.$test_cfgs[0]";
}
open (DEBUGFILE,">$debugfile");


print DEBUGFILE "Netflix.parse and log. Waits on manswer key\n";
my $exists = 0;
my $retries = 0;
while (($exists == 0) && ($retries < 5) ) {
    my $rslt = ` ./redis-stable/src/redis-cli -h $redisHost -p $redisPort exists $mkey`;
    print DEBUGFILE " ./redis-stable/src/redis-cli -h $redisHost -p $redisPort exists $mkey  $rslt";
    sleep(1);
    $retries++;
    my $tmp = "";
    if ($rslt =~ /.*1.*/) {
	$exists = 1;
	chomp($exists);
    }
}
if ($retries >= 5) {
    print DEBUGFILE "Unabled to get manswer value\n";
    exit(-1);
}
$retries = 0;
$exists = 0;
print DEBUGFILE "Netflix.parse and log. Waits on panswer key\n";
while (($exists == 0) && ($retries < 5) ) {
    my $rslt = ` ./redis-stable/src/redis-cli -h $redisHost -p $redisPort exists $pkey`;
    #print DEBUGFILE "$rslt";
    sleep(1);
    $retries++;
    my $tmp = "";
    if ($rslt =~ /.*1.*/) {
	$exists = 1;
	chomp($exists);
    }
}
if ($retries >= 5) {
    print DEBUGFILE "Unabled to get panswer value\n";
    exit(-1);
}

print DEBUGFILE "loganswer: mkdir /root/tests/$test_iden\n";
print DEBUGFILE "loganswer: ./redis-stable/src/redis-cli -h $redisHost -p $redisPort get $pkey > /root/tests/$test_iden/$test_cfgs[0]-panswer\n";
print DEBUGFILE "loganswer: ./redis-stable/src/redis-cli -h $redisHost -p $redisPort get $mkey > /root/tests/$test_iden/$test_cfgs[0]-manswer\n";
print DEBUGFILE "loganswer: ./redis-stable/src/redis-cli -h $redisHost -p $redisPort get $qkey > /root/tests/$test_iden/$test_cfgs[0]-qanswer\n";
`mkdir /root/tests/$test_iden`;

my $manswer = ` ./redis-stable/src/redis-cli -h $redisHost -p $redisPort get $mkey`;
my $panswer = ` ./redis-stable/src/redis-cli -h $redisHost -p $redisPort get $pkey`;
my $qanswer = ` ./redis-stable/src/redis-cli -h $redisHost -p $redisPort get $qkey`;



#open (FILE, ">/root/tests/$test_iden/$test_cfgs[0]-panswer");
#print FILE "$panswer";
#close(FILE);
#open (FILE, ">/root/tests/$test_iden/$test_cfgs[0]-manswer");
#print FILE "$manswer";
#close(FILE);
#open (FILE, ">/root/tests/$test_iden/$test_cfgs[0]-qanswer");
#print FILE "$qanswer";
#close(FILE);

# Compute answer quality
my @matures; my $temp;
my @tmp = split('</id>', $manswer);
foreach $temp (@tmp) {
    if ($temp =~ /.*<id>(\d*)/) {
	my $id=$1;
	chomp($id);
	unshift @matures, $id;
    }
}

my @prematures;
@tmp = split('</id>', $panswer);
foreach $temp (@tmp) {
    if ($temp =~ /.*<id>(\d*)/) {
	my $id=$1;
	chomp($id);
	unshift @prematures, $id;
    }
}

my $mature_count=0;
my $mature; 
my $premature;
my $mature_limit=1000;
my $mature_track=0;
foreach $mature (@matures) {
    if ($mature_limit > $mature_track) {
	foreach $premature (@prematures) {
	    #print  "Compare $mature ==? $premature\n";
	    if ($mature =~ /^$premature$/) {
		$mature_count = $mature_count+1;
		last;
	    }
	}	
    }
    $mature_track++;
}

my $aq = 0;
if (($mature_track) > 0) {
    $aq = $mature_count / ($mature_track);
}

if ($mature_track > 0) {
    open (FILE, ">>/root/answerquality");
    print FILE "$aq\n";
    close(FILE);

    open (FILE, ">>/root/answerquality.log");
    print FILE "$aq $test_cfgs[0]\n";
    close(FILE);
}

` ./redis-stable/src/redis-cli -h $redisHost -p $redisPort del $pkey`;
` ./redis-stable/src/redis-cli -h $redisHost -p $redisPort del $mkey`;
` ./redis-stable/src/redis-cli -h $redisHost -p $redisPort del $qkey`;
