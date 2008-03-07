#!/usr/bin/perl

use strict;
use lib "/opt/vyatta/share/perl5/";
use VyattaConfig;
use VyattaNatRule;

sub numerically { $a <=> $b; }

exit 1 if ($#ARGV != 0);
my $xsl_file = $ARGV[0];

if (! -e $xsl_file) {
  print "Invalid XSL file \"$xsl_file\"\n";
  exit 1;
}

my %stats = (
              source      => [ ],
              destination => [ ],
            );
open(STATS, "/sbin/iptables -t nat -L -vn |") or exit 1;
my $skey = "";
while (<STATS>) {
  if (m/^Chain PREROUTING/) {
    $skey = "destination";
  } elsif (m/^Chain POSTROUTING/) {
    $skey = "source";
  } elsif (m/^Chain /) {
    $skey = "";
  }

  if ($skey ne "" && (m/SNAT/ || m/DNAT/ || m/MASQUERADE/ || m/RETURN/)) {
    m/^\s*(\d+[KMG]?)\s+(\d+[KMG]?)\s/;
    push @{$stats{$skey}}, ($1, $2);
  }
}
close STATS;

open(RENDER, "| /opt/vyatta/sbin/render_xml $xsl_file") or exit 1;

# begin
print RENDER "<opcommand name='natrules'><format type='row'>\n";

my $config = new VyattaConfig;
$config->setLevel("service nat rule");
my @rules_pre = $config->listOrigNodes();
my $rule;
my @rules = sort numerically @rules_pre;
for $rule (@rules) {
  my $nrule = new VyattaNatRule;
  $nrule->setupOrig("service nat rule $rule");
  my $ntype = $nrule->orig_type(); 
  print RENDER "  <row>\n";
  print RENDER "    <rule_num>$rule</rule_num>\n";
  my $pkts = shift @{$stats{$ntype}};
  my $bytes = shift @{$stats{$ntype}};
  print RENDER "    <pkts>$pkts</pkts>\n";
  print RENDER "    <bytes>$bytes</bytes>\n";
  $nrule->outputXml(*RENDER{IO}); 
  print RENDER "  </row>\n";
}

# end 
print RENDER "</format></opcommand>\n";

close RENDER;
exit 0;

