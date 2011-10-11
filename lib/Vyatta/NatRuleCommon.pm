#
# Module: NatRuleCommon.pm
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
# Description: Shared NAT rule handling procedures library
#
# **** End License ****
#


package Vyatta::NatRuleCommon;

use strict;
use lib "/opt/vyatta/share/perl5";
require Vyatta::Config;
require Vyatta::IpTables::AddressFilter;
use Vyatta::Misc;
use Vyatta::TypeChecker;

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(is_disabled get_num_ipt_rules  get_log_prefix output_xml_elem);

sub is_disabled {
  my $self = shift;
  return 1 if defined $self->{_disable};
  return 0;
}

sub get_num_ipt_rules {
  my $self = shift;
  return 0 if defined $self->{_disable};
  my $ipt_rules = 1;
  if ("$self->{_log}" eq 'enable') {
      $ipt_rules++;
  }
  if (defined $self->{_proto} && $self->{_proto} eq 'tcp_udp') {
      $ipt_rules++;
      $ipt_rules++ if $self->{_log} eq 'enable';
  }
  return $ipt_rules;
}

sub get_log_prefix {
  my ($rule_num, $jump_target, $type) = @_;

  # In iptables it allows a 29 character log_prefix, but we ideally
  # want to include "[nat-$type-$num-$target] "
  #                   4   4     4    7        = 19   
  # so no truncation is needed.
  my $log_prefix  = "[NAT-$type-$rule_num-$jump_target] ";
  return $log_prefix;
}

sub output_xml_elem {
  my ($name, $value, $fh) = @_;
  print $fh "    <$name>$value</$name>\n";
}


1;

