#!/usr/bin/perl
#
# Module: vyatta-update-dst-nat.pl
#
# **** License ****
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# This code was originally developed by Vyatta, Inc.
# Portions created by Vyatta are Copyright (C) 2009 Vyatta, Inc.
# All Rights Reserved.
#
# Author: eng@vyatta.com
# Date: 2011
# Description: Script to update iptables destination NAT rules
#
# **** End License ****
#

use strict;
use lib "/opt/vyatta/share/perl5/";
use Vyatta::Config;
use Vyatta::NatRuleCommon;
use Vyatta::DstNatRule;
use Vyatta::IpTables::Mgr;

my $CONFIG_LEVEL = "nat destination";
my $IPTABLES = "/sbin/iptables";

sub numerically { $a <=> $b; }

sub raw_cleanup {
  # remove the conntrack setup.
  ipt_disable_conntrack('iptables', 'NAT_CONNTRACK');
}

my $config = new Vyatta::Config;

my $all_deleted = 1;

$config->setLevel("nat source rule");
my %rules_src = $config->listNodeStatus();
my $rule_src;
for $rule_src (keys %rules_src) {
  if ($rules_src{$rule_src} ne "deleted") {
    $all_deleted = 0;
  }
}

$config->setLevel($CONFIG_LEVEL." rule");
my %rules = $config->listNodeStatus();
my $rule;
my $debug = 0;
if ($debug) {
  open(OUT, ">>/tmp/nat") or exit 1;
} else {
  open(OUT, ">>/dev/null") or exit 1;
}

my $ipt_rulenum = 2;

my $chain_name = "PREROUTING";

print OUT "========= dst-nat list =========\n";
my @rule_keys = sort numerically keys %rules;
if ($#rule_keys < 0) {
  raw_cleanup();
  exit 0;
}

## it seems that "multiport" does not like port range (p1:p2) if nobody has
## touched the nat table yet after reboot!?
system("$IPTABLES -t nat -L -n >& /dev/null");

# we have some nat rule(s). make sure conntrack is enabled.
ipt_enable_conntrack('iptables', 'NAT_CONNTRACK');

for $rule (@rule_keys) {
  print OUT "$rule: $rules{$rule}\n";
  my $tmp = `iptables -L -nv --line -t nat`;
  print OUT "iptables before:\n$tmp\n";
  my $nrule = new Vyatta::DstNatRule;
  $nrule->setup($CONFIG_LEVEL." rule $rule");

  if ($rules{$rule} ne "deleted") {
    $all_deleted = 0;
  }
 
  my $cmd;
  if ($rules{$rule} eq "static") {
    my $ipt_rules = $nrule->get_num_ipt_rules();
    $ipt_rulenum += $ipt_rules;
    next;
  } elsif ($rules{$rule} eq "deleted") {
    my $orule = new Vyatta::DstNatRule;
    $orule->setupOrig($CONFIG_LEVEL." rule $rule");
    my $ipt_rules = $orule->get_num_ipt_rules();
    for (1 .. $ipt_rules) {
      $cmd = "$IPTABLES -t nat -D $chain_name $ipt_rulenum";
      print OUT "$cmd\n";
      if (system($cmd)) {
        exit 1;
      }
    }
    next;
  }
  
  my ($err, @rule_strs) = $nrule->rule_str();
  if (defined $err) {
    # rule check failed => return error
    print OUT "Destination NAT configuration error in rule $rule: $err\n";
    print STDERR "Destination NAT configuration error in rule $rule: $err\n";
    exit 5;
  }
  
  if ($rules{$rule} eq "added") {
    foreach my $rule_str (@rule_strs) {
      next if !defined $rule_str;
      $cmd = "$IPTABLES -t nat -I $chain_name $ipt_rulenum " .
          "$rule_str";
      print OUT "$cmd\n";
      if (system($cmd)) {
        exit 1;
      }
      $ipt_rulenum++;
    }

  } elsif ($rules{$rule} eq "changed") {
    # delete the old rule(s)
    my $orule = new Vyatta::DstNatRule;
    $orule->setupOrig($CONFIG_LEVEL." rule $rule");
    my $ipt_rules = $orule->get_num_ipt_rules();
    my $idx = $ipt_rulenum;
    for (1 .. $ipt_rules) {
      $cmd = "$IPTABLES -t nat -D $chain_name $idx";
      print OUT "$cmd\n";
      if (system($cmd)) {
        exit 1;
      }
    }

    # add the new rule(s)
    foreach my $rule_str (@rule_strs) {
      next if !defined $rule_str;
      $cmd = "$IPTABLES -t nat -I $chain_name $ipt_rulenum " .
          "$rule_str";
      print OUT "$cmd\n";
      if (system($cmd)) {
        exit 1;
      }
      $ipt_rulenum++;
    }

  }
}

if ($all_deleted) {
  raw_cleanup();
}

close OUT;
exit 0;

# Local Variables:
# mode: perl
# indent-tabs-mode: nil
# perl-indent-level: 2
# End:
