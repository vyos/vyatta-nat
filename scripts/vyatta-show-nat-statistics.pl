#!/usr/bin/perl

use strict;
use Getopt::Long;
use lib "/opt/vyatta/share/perl5";
use Vyatta::Config;
use Vyatta::NatRuleCommon;
use Vyatta::SrcNatRule;
use Vyatta::DstNatRule;

sub numerically { $a <=> $b; }

my $format = "%-5s  %-6s  %-6s  %-12s";

my $iptables = "sudo /sbin/iptables";

my $src_level = "nat source rule";
my $dst_level = "nat destination rule";
my $level = undef;

my $src_chain = "POSTROUTING";
my $dst_chain = "PREROUTING";
my $chain = undef;

my $type = undef;

my @stats = ();

GetOptions(
     "type=s" => \$type
);

die("Must specify NAT type!") if !defined($type);

if ($type eq 'source') {
    $level = $src_level;
    $chain = $src_chain;
} elsif ($type eq 'destination') {
    $level = $dst_level;
    $chain = $dst_chain;
} else {
    die("Unknown NAT type $type!");
}

open(STATS, "$iptables -t nat -L $chain -vn |") or exit 1;
my ($rule_tcp_pkts, $rule_tcp_bytes, $rule_pkts, $rule_bytes);
my $tcp_done = 0;
while (<STATS>) {
  if ( (m/ SNAT/ || m/ DNAT/ || m/MASQUERADE/ || m/RETURN/ || m/NETMAP/)) {
    m/^\s*(\d+[KMG]?)\s+(\d+[KMG]?)\s/;
    $rule_pkts = $1;
    $rule_bytes = $2;
    if (m/tcp_udp/) { # protocol is tcp_udp, 2 rules in iptables for it
      if ($tcp_done == 0) {
        $rule_tcp_pkts = $rule_pkts;
        $rule_tcp_bytes = $rule_bytes;
        $tcp_done = 1;
        next;
      } else {
        $rule_pkts += $rule_tcp_pkts;
        $rule_bytes += $rule_tcp_bytes;
        $tcp_done = 0;
      }
    }
    push @stats, ($rule_pkts, $rule_bytes);
  }
}
close STATS;

printf($format, "rule", "pkts", "bytes", "interface");
print "\n";
printf($format, "----", "----", "-----", "---------");
print "\n";

my $config = new Vyatta::Config;
$config->setLevel("$level");
my @rules_pre = $config->listOrigNodes();
my $rule;
my @rules = sort numerically @rules_pre;
for $rule (@rules) {
  my $nrule = undef;
  $nrule = new Vyatta::SrcNatRule if $type eq 'source';
  $nrule = new Vyatta::DstNatRule if $type eq 'destination';
  
  $nrule->setupOrig("$level $rule");
  next if defined $nrule->{_disable};

  my $pkts = shift @stats;
  my $bytes = shift @stats;

  my $intf = undef;
  $intf = $nrule->{_outbound_if} if $type eq 'source';
  $intf = $nrule->{_inbound_if} if $type eq 'destination';

  printf($format, $rule, $pkts, $bytes, $intf);
  print "\n";
}


exit 0;

