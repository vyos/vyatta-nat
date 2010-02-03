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
my %chain_hash = ( 'source'        => 'POSTROUTING',
                   'destination'   => 'PREROUTING',
                   'masquerade'    => 'POSTROUTING');

sub clear_rule {
  my $clirule = shift;
  my $error = undef;

  if ($clirule eq 'all') {
    # clear counters for all rules in NAT table
    $error = system("sudo /sbin/iptables -Z -t nat &>/dev/null");
    return "error clearing NAT rule counters" if $error;
  } else {
    # clear counters for a specific NAT rule
    my $config = new Vyatta::Config;
    $config->setLevel("service nat rule");
    my @rules = $config->listOrigNodes();

    # validate that it's a legit CLI rule
    if (!((scalar(grep(/^$clirule$/, @rules)) > 0))) {
      return "Invalid NAT rule number \"$clirule\"";
    }

    # determine rule type
    my $rule_type = $config->returnOrigValue("$clirule type");

    # find corresponding rulenum in the underlying NAT table
    my $iptables_rule = undef;
    my $cmd = "sudo /sbin/iptables -L $chain_hash{$rule_type} -t nat -nv " .
              "--line-numbers | grep '/\* NAT-$clirule ' | awk {'print \$1'}";
    $iptables_rule = `$cmd`;
    return "couldn't find an underlying iptables rule" if ! defined $iptables_rule;
    chomp $iptables_rule;

    # clear the counters for that rule
    $cmd = "sudo /sbin/iptables -t nat -Z $chain_hash{$rule_type} $iptables_rule";
    $error = system($cmd);
    return "error clearing counters for NAT rule $clirule" if $error;
  }
  return;
}

#
# main
#

my ($clirulenum);
GetOptions("clirule=s" => \$clirulenum);

die "undefined rule number" if ! defined $clirulenum;

my ($error, $warning);

($error, $warning) = clear_rule($clirulenum);

if (defined $warning) {
    print "$warning\n";
}

if (defined $error) {
    print "$error\n";
    exit 1;
}

exit 0;

# end of file
