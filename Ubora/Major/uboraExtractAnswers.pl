#!/usr/bin/perl -w
use strict;
#  Looks over the system config,  capturing the IP and role of each component
#  sshes into the component and starts the right script (in parallel)
#  Loops around the "isready" of all aggregators
#  then starts the workload generators
#  
#  

my $rates=0;
my $numData = 2;
my $i = 0;
my $lat=0;
my $rank=0;
my $ans_cnt = 0;
my $ans_cnt2 = 0;
my $comps_cnt = -1;

my @comps_doc;
my @comps_doc2;
my @comps_ans2;
my @comps_scr2;
my @comps_typ;
my @comps_ids;
my @comps_ipa;
my @comps_indexLat;
my @comps_indexRank;
my @comps_ans;
my @comps_scr;

my $first_time=0;
my $oends_rnk=-1;
my $oends_cvt=1;
my $oends_wnd=1;

my $ind = index($ARGV[0],"-");
my $rhash = substr($ARGV[0], 0, $ind);
my $outfile = ">>$rhash-answerq";
print "rhash $rhash $outfile";

open (CFGFILE, $ARGV[0]);
while (<CFGFILE>) {
    if (/^\[(\d+)\](.*)$/){
	my $ans = $2;
	chomp($ans);
	my $index = $1;
	chomp($index);

	$comps_ans[$index]=$ans;
	$ans_cnt = $index;
	#print "$ans_cnt,$comps_ans[$index]\n";
    }
    elsif (/^\s+Score:\s+(\d+\.+\d+)$/) {
	my $score = $1;
	chomp($score);
	$comps_scr[$ans_cnt]=$score;
	#print "S $ans_cnt, $comps_scr[$ans_cnt]\n";
    }
    elsif (/^\s+Document:\s+(.*)\s+$/) {
	my $doc = $1;
	chomp($doc);

	$comps_doc[$ans_cnt]=$doc;
	#print "D $ans_cnt, $comps_doc[$ans_cnt]\n";
    }
}

close (CFGFILE);

open (CFGFILE2, $ARGV[1]);
while (<CFGFILE2>) {
    if (/^\[(\d+)\](.*)$/){
        my $ans = $2;
        chomp($ans);
        my $index = $1;
        chomp($index);

        $comps_ans2[$index]=$ans;
        $ans_cnt2 = $index;
	$comps_doc2[$index]="";
        #print "$ans_cnt2,$comps_ans2[$index]\n";
    }
    elsif (/^\s+Score:\s+(\d+\.+\d+)$/) {
        my $score = $1;
        chomp($score);
        $comps_scr2[$ans_cnt2]=$score;
        #print "S $ans_cnt2, $comps_scr2[$ans_cnt2]\n";
    }
    elsif (/^\s+Document:\s+(.*)\s+$/) {
        my $doc = $1;
        chomp($doc);

        $comps_doc2[$ans_cnt2]=$doc;
        #print "D $ans_cnt2, $comps_doc2[$ans_cnt2]\n";
    }
}

close(CFGFILE2);

my $topk = $ans_cnt2;
if ($ans_cnt2 > $ARGV[2]){
    $topk = $ARGV[2];
}

my $top2k = $topk;
if ($ans_cnt < $top2k){
    $top2k = $ans_cnt;
}

my $count = 0;

for(my $j = 0; $j <= $topk; $j += 1)
{
    my $found = 0;
    if($comps_doc2[$j] ne ""){
        #print "doc2 $comps_doc2[$j]";
        for(my $m = 0; $m <= $top2k; $m += 1)
        {
	    #print "doc $comps_doc[$m]";
	    if($comps_doc[$m] ne "")
	    {	
            	if($found == 0 && index($comps_doc2[$j],$comps_doc[$m]) != -1 && index($comps_doc[$m], $comps_doc2[$j]) != -1)
	    	{
	        	$count += 1;
	        	$found = 1;
	        	print "found $comps_doc2[$j] in $comps_doc[$m] at $m\n";
	    	}
	    }
	}
    }
}

my $percent = $count / $topk;
print "topk $count $topk percent ";
print sprintf("%0.6f", $percent);

open(OUTFILE, $outfile);
print OUTFILE sprintf("%0.6f", $percent);
close(OUTFILE);

