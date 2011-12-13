#!/usr/bin/perl
#
# Module: vyatta-clear-nat-counters.pl
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
# Portions created by Vyatta are Copyright (C) 2006-2009 Vyatta, Inc.
# All Rights Reserved.
#
# Author: Mohit Mehta
# Date: February 2010
# Description: Script to clear nat counters
#
# **** End License ****
#

use Getopt::Long;
use POSIX;
use warnings;
use strict;
use lib "/opt/vyatta/share/perl5";
use Vyatta::Config;

# NAT type mapping from config node to iptables chain
my $src_chain = "POSTROUTING";
my $dst_chain = "PREROUTING";
my $chain = undef;

# NAT CLI levels
my $src_level = "nat source rule";
my $dst_level = "nat destination rule";
my $level = undef;

my $iptables = "sudo /sbin/iptables";

sub numerically { $a <=> $b; }

sub get_nat_rules {
  my $config = new Vyatta::Config;
  $config->setLevel($level);
  my @rules = sort numerically $config->listOrigNodes();
  return @rules;
}

sub print_nat_rules {
  my @rules = get_nat_rules();
  my $rule_string = join(" ",@rules);
  print $rule_string;
  return;
}

sub clear_rule {
  my $clirule = shift;
  my $error = undef;

  if ($clirule eq 'all') {
    # clear counters for all rules in NAT table
    $error = system("$iptables -Z -t nat &>/dev/null");
    return "error clearing NAT rule counters" if $error;
  } else {
    # clear counters for a specific NAT rule
    my @rules = get_nat_rules();

    # validate that it's a legit CLI rule
    if (!((scalar(grep(/^$clirule$/, @rules)) > 0))) {
      return "Invalid NAT rule number \"$clirule\"";
    }

    my $config = new Vyatta::Config;
    $config->setLevel($level);

    # make sure rule is enabled
    my $is_rule_disabled = $config->existsOrig("$clirule disable");
    return "NAT rule $clirule is disabled" if defined $is_rule_disabled;

    # find corresponding rulenum in the underlying NAT table
    my $iptables_rule = undef;
    my $cmd = "$iptables -L $chain -t nat -nv " .
              "--line-numbers | grep '/\* .*NAT-$clirule' | awk {'print \$1'}";
    $iptables_rule = `$cmd`;
    return "couldn't find an underlying iptables rule" if ! defined $iptables_rule;
    chomp $iptables_rule;
    # Rules with "log" statement and "tcp_udp" rules take more than one line
    my @numbers = split(/\n/, $iptables_rule);

    # clear the counters for that rule
    for my $number (@numbers) {
        $cmd = "$iptables -t nat -Z $chain $number";
        $error = system($cmd);
        return "error clearing counters for NAT rule $clirule" if $error;
    }
  }
  return;
}

#
# main
#

my ($action, $clirulenum, $type);

GetOptions( "action=s"  => \$action,
            "clirule=s" => \$clirulenum,
            "type=s"    => \$type
          );

die "undefined action" if ! defined $action;
die "undefined rule number" if ! defined $clirulenum;
die "undefined NAT type" if ! defined $type;

if ($type eq 'source') {
    $level = $src_level;
    $chain = $src_chain;
} elsif ($type eq 'destination') {
    $level = $dst_level;
    $chain = $dst_chain;
} else {
    die "unknown NAT type";
}

my ($error, $warning);

($error, $warning) = clear_rule($clirulenum) if $action eq 'clear-counters';

($error, $warning) = print_nat_rules() if $action eq 'print-nat-rules';

if (defined $warning) {
    print "$warning\n";
}

if (defined $error) {
    print "$error\n";
    exit 1;
}

exit 0;

# end of file
