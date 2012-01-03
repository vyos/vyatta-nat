#!/usr/bin/perl
#
# Module: vyatta-show-nat-rules.pl
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
# Author: Mohit Mehta
# Date: January 2009
# Description: Script to generate output for "show nat <source|destination> rules" commands
#
# **** End License ****
#

use strict;
use Getopt::Long;
use Text::Wrap qw(wrap 80 wrap);
use lib "/opt/vyatta/share/perl5";
use Vyatta::Config;
use Vyatta::NatRuleCommon;
use Vyatta::SrcNatRule;
use Vyatta::DstNatRule;
use Vyatta::IpTables::AddressFilter;

my $type = undef;
GetOptions(
    "type=s" => \$type
);

my $src_level = "nat source rule";
my $dst_level = "nat destination rule";
my $level = undef;

my $format1  = "%-6s  %-16s  %-58s";
my $format2  = "        %-16s  %-62s";

sub numerically { $a <=> $b; }

sub get_srcdst_address {
 my ($level) = @_;
 my $address = "ANY";
 my $addr = new Vyatta::IpTables::AddressFilter;
 $addr->setupOrig("$level");
 if (defined $addr->{_address}) {
  $address = $addr->{_address};
 } elsif (defined $addr->{_network}) {
   $address = $addr->{_network};
 } elsif (defined $addr->{_range_start} && defined $addr->{_range_stop}) {
   $address = $addr->{_range_start} . "-" . $addr->{_range_stop};
 }
 return $address;
}

sub get_srcdst_port {

 my ($level) = @_;
 my $portstr = "ANY";
 my $port = new Vyatta::IpTables::AddressFilter;
 $port->setupOrig("$level");
 $portstr = $port->{_port} if defined $port->{_port};
 return $portstr;
}

sub get_inout_port {

 my ($level, $inoroutaddr) = @_;
 my $portstr = "ANY";
 my $port = undef;
 $port = new Vyatta::SrcNatRule if ($type eq 'source');
 $port = new Vyatta::DstNatRule if ($type eq 'destination');
 $port->setupOrig("$level");
 $portstr = $port->{$inoroutaddr}->{_port} if defined $port->{$inoroutaddr}->{_port};
 return $portstr;

}

sub get_inout_address {

 my ($level, $inoroutaddr) = @_;
 my $address = "ANY";
 my $addr = undef;
 $addr = new Vyatta::SrcNatRule if ($type eq 'source');
 $addr = new Vyatta::DstNatRule if ($type eq 'destination');
 $addr->setupOrig("$level");
 if (defined $addr->{$inoroutaddr}->{_addr}) {
  $address = $addr->{$inoroutaddr}->{_addr};
 } elsif (defined $addr->{$inoroutaddr}->{_range}->{_start} && 
          defined $addr->{$inoroutaddr}->{_range}->{_stop}) {
   $address = $addr->{$inoroutaddr}->{_range}->{_start} 
              . "-" . $addr->{$inoroutaddr}->{_range}->{_stop};
 }
 return $address; 

}

sub get_primary_addr {

    my $intf = shift;
    my @addr_list = ();
    my @lines = `ip addr show $intf 2>/dev/null | grep 'inet'`;
    foreach my $line (@lines) {
        (my $inet, my $addr, my $remainder) = split(' ', $line, 3);
         my $ip = new NetAddr::IP($addr);
	 if ($ip->version() == 4) {
            push @addr_list, $ip->cidr();
         }
    }
    chomp  @addr_list;
    my $addr = $addr_list[0];
    $addr =~ s/\/\d+$//;
    return $addr;

}

sub print_constants {
 print "Disabled rules are not shown\n";
 print "Codes: X - exclude rule";
 print ", M - masquerade rule" if $type eq 'source'; # M code never appears in destination
 print "\n\n";
 printf($format1, 'rule', 'intf', 'translation');
 print "\n";
 printf($format1, '----', '----', '-----------');

}

sub make_translate_addrorport_str {
   
 my ($type, $addr, $trans_addr, $addrorport) = @_;
 my $string = "";
 $string = "saddr " if ($type eq "source" && $addrorport eq "address");
 $string = "sport " if ($type eq "source" && $addrorport eq "port");
 $string = "daddr " if ($type eq "destination" && $addrorport eq "address");
 $string = "dport " if ($type eq "destination" && $addrorport eq "port");
 $string .= $addr;
 $string .= " to " . $trans_addr if !($trans_addr eq "ANY");
 return $string;

}

sub make_condition_str {
 
 my ($type, $addr, $port) = @_;
 my ($string, $addr_string, $port_string) = "";
 if ($type eq "source") {
  $addr_string = "saddr";
  $port_string = "sport";
 } else {
  $addr_string = "daddr";
  $port_string = "dport";
 }
 $string = "when ". $addr_string . " ". $addr . ", " . $port_string 
           . " " . $port if (!($addr eq "ANY" && $port eq "ANY"));
 return $string;

}

#
# main
#

if ( !defined($type) ) {
    die("Must specify NAT type!\n");
}
else {
     if ($type eq "source") {
         $level = $src_level;
     }
     elsif ($type eq "destination") {
         $level = $dst_level;
     }
     else {
         die("Unknown NAT type $type");
     }
}

my $config = new Vyatta::Config;
$config->setLevel("$level");
my @rules_pre = $config->listOrigNodes();
my $rule;
my @rules = sort numerically @rules_pre;

print_constants();
for $rule (@rules) {
  my ($rulenum, $protocol, $interface, $source_addr, $source_port,
      $destination_addr, $destination_port, $translation_addr, $translation_port,
      $translation_addr_str, $translation_port_str, $condition, $description);
  
  $rulenum = $rule;
  $protocol = "all";
  
  my $nrule = undef;
  $nrule = new Vyatta::SrcNatRule if ($type eq "source");
  $nrule = new Vyatta::DstNatRule if ($type eq "destination");
  my $src = new Vyatta::IpTables::AddressFilter;
  my $dst = new Vyatta::IpTables::AddressFilter;
  
  $nrule->setupOrig("$level $rule");
  next if defined $nrule->{_disable};
  $rulenum = "X" . $rulenum if defined $nrule->{_exclude};
  $rulenum = "M". $rulenum if defined $nrule->{_is_masq};
  $protocol = $nrule->{_proto} if defined $nrule->{_proto};
  $protocol = "proto-" . $protocol;
  $interface = $nrule->{_inbound_if} if defined $nrule->{_inbound_if};
  $interface = $nrule->{_outbound_if} if defined $nrule->{_outbound_if};

  $source_addr = get_srcdst_address("$level $rule source");
  $destination_addr = get_srcdst_address("$level $rule destination");
  $source_port = get_srcdst_port("$level $rule source");
  $destination_port = get_srcdst_port("$level $rule destination");

  $description = $config->returnOrigValue("$rule description");

  if ($type eq 'source') {
      my $raw_translation_addr = get_inout_address("$level $rule", "_outside_addr");
      if ($raw_translation_addr eq "masquerade") {
          $translation_addr = get_primary_addr($interface);
	  # if translation address is empty after that,
	  # it's a masquerade rule for any interface
	  if ($translation_addr eq '') {
		  $translation_addr = "ANY";
          }
      }
      else {
          $translation_addr = $raw_translation_addr;
      }
      $translation_port = get_inout_port("$level $rule", "_outside_addr");
      $translation_addr_str = make_translate_addrorport_str ("source", 
                           $source_addr, $translation_addr, "address");
      $translation_port_str = make_translate_addrorport_str ("source", 
                              $source_port, $translation_port, "port");
      $condition = make_condition_str ("destination", 
                   $destination_addr, $destination_port);
   } elsif ($type eq 'destination') {
   $translation_addr = get_inout_address("$level $rule", "_inside_addr");
   $translation_port = get_inout_port("$level $rule", "_inside_addr");
   $translation_addr_str = make_translate_addrorport_str ("destination",
                           $destination_addr, $translation_addr, "address");
   $translation_port_str = make_translate_addrorport_str ("destination",
                           $destination_port, $translation_port, "port");
   $condition = make_condition_str ("source",
                $source_addr, $source_port);
  }
  
  print "\n";
  printf ($format1, $rulenum, $interface, $translation_addr_str);
  print "\n";
  printf ($format2, $protocol, $translation_port_str);
  print "\n";
  printf ($format1, "", "", "$condition") if $condition;
  print "\n" if $condition;
  print wrap("", "", "Desc: $description\n") if $description;
}

print "\n";
exit 0;

