#
# Module: DstNatRule.pm
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
# Description: Destination NAT rule handling library
#
# **** End License ****
#


package Vyatta::DstNatRule;

use strict;
use lib "/opt/vyatta/share/perl5";
require Vyatta::Config;
require Vyatta::IpTables::AddressFilter;
use Vyatta::Misc;
use Vyatta::TypeChecker;
use Vyatta::NatRuleCommon;

my $src = new Vyatta::IpTables::AddressFilter;
my $dst = new Vyatta::IpTables::AddressFilter;

my %fields = (
  _rule_number  => undef,
  _inbound_if   => undef,
  _proto        => undef,
  _exclude      => undef,
  _disable      => undef,
  _log          => undef,
  _inside_addr  => {
                    _addr => undef,
                    _range  => {
                                _start => undef,
                                _stop  => undef,
                               },
                    _port => undef,
                   }
);

my $type = "DST";

sub new {
  my $that = shift;
  my $class = ref ($that) || $that;
  my $self = {
    %fields,
  };

  bless $self, $class;
  return $self;
}

sub setup {
  my ( $self, $level ) = @_;
  my $config = new Vyatta::Config;

  $config->setLevel("$level");

  $self->{_rule_number} = $config->returnParent("..");
  $self->{_inbound_if} = $config->returnValue("inbound-interface");
  $self->{_proto} = $config->returnValue("protocol");
  $self->{_exclude} = $config->exists("exclude");
  $self->{_disable} = $config->exists("disable");
  $self->{_log} = $config->returnValue("log");

  $self->{_inside_addr}->{_addr}
    = $config->returnValue("translation address");
  $self->{_inside_addr}->{_range}->{_start} = undef;
  $self->{_inside_addr}->{_range}->{_stop} = undef;
  if (defined($self->{_inside_addr}->{_addr})
      && $self->{_inside_addr}->{_addr} =~ /^([^-]+)-([^-]+)$/) {
    $self->{_inside_addr}->{_range}->{_start} = $1;
    $self->{_inside_addr}->{_range}->{_stop} = $2;
    $self->{_inside_addr}->{_addr} = undef;
  }
  $self->{_inside_addr}->{_port}
    = $config->returnValue("translation port");
  $src->setup("$level source");
  $dst->setup("$level destination");

  return 0;
}

sub setupOrig {
  my ( $self, $level ) = @_;
  my $config = new Vyatta::Config;

  $config->setLevel("$level");

  $self->{_rule_number} = $config->returnParent("..");
  $self->{_inbound_if} = $config->returnOrigValue("inbound-interface");
  $self->{_proto} = $config->returnOrigValue("protocol");
  $self->{_exclude} = $config->existsOrig("exclude");
  $self->{_disable} = $config->existsOrig("disable");
  $self->{_log} = $config->returnOrigValue("log");

  $self->{_inside_addr}->{_addr}
    = $config->returnOrigValue("translation address");
  $self->{_inside_addr}->{_range}->{_start} = undef;
  $self->{_inside_addr}->{_range}->{_stop} = undef;
  if (defined($self->{_inside_addr}->{_addr})
      && $self->{_inside_addr}->{_addr} =~ /^([^-]+)-([^-]+)$/) {
    $self->{_inside_addr}->{_range}->{_start} = $1;
    $self->{_inside_addr}->{_range}->{_stop} = $2;
    $self->{_inside_addr}->{_addr} = undef;
  }
  $self->{_inside_addr}->{_port}
    = $config->returnOrigValue("translation port");
    
  $src->setupOrig("$level source");
  $dst->setupOrig("$level destination");

  return 0;
}


sub rule_str {
  my ($self) = @_;
  my $rule_str = "";
  my $can_use_port = 1;
  my $jump_target = '';
  my $jump_param  = '';
  my $log_modifier = '';
  my $use_netmap = 0;
  my $tcp_and_udp = 0;

  # If protocol is not TCP or UDP rule can't use destination port
  if (!defined($self->{_proto}) ||
      (($self->{_proto} ne "tcp_udp")
        && ($self->{_proto} ne "tcp") && ($self->{_proto} ne "6")
        && ($self->{_proto} ne "udp") && ($self->{_proto} ne "17"))) {
    $can_use_port = 0;
  }

  if ($self->{_exclude}) {
    $jump_target = 'RETURN';
    $log_modifier = 'EXCL';
  } else {
    $jump_target = 'DNAT';
  }
  
  if (defined($self->{_proto})) {
    my $str = $self->{_proto};
    my $negate ="";
    $negate = "!" if (m/^\!(.*)$/);
    $str =~ s/^\!(.*)$/ $1/;
    if ($str eq 'tcp_udp') {
      $tcp_and_udp = 1;
      $rule_str .= " -p tcp "; # we'll add the '-p udp' to 2nd rule later
    } else {
      $rule_str .= " $negate -p $str ";
    }
  }

  if (defined($self->{_inbound_if})) {
    if ($self->{_inbound_if} ne "any") {
      $rule_str .= " -i $self->{_inbound_if} ";
    }
  } else {
    # make this a requirement to prevent users from
    # inadvertently NATing loopback traffic.
    return ('inbound-interface not specified', undef);
  }

  my $to_dst = "";
  if (defined($self->{_inside_addr}->{_addr})) {
    my $addr = $self->{_inside_addr}->{_addr};
    if ($addr =~ m/\//) {
       return ("\"$addr\" is not a valid IPv4net address", undef)
       if (!Vyatta::TypeChecker::validateType('ipv4net', $addr, 1));
       $to_dst = " --to ";
       $to_dst .= $addr;
       $use_netmap = 1;
    } else {
       return ("\"$addr\" is not a valid IP address", undef)
           if (!Vyatta::TypeChecker::validateType('ipv4', $addr, 1));
       $to_dst = " --to-destination ";
       $to_dst .= $addr;
    }
  } elsif (defined($self->{_inside_addr}->{_range}->{_start})
           && defined($self->{_inside_addr}->{_range}->{_stop})) {
    my $start = $self->{_inside_addr}->{_range}->{_start};
    my $stop = $self->{_inside_addr}->{_range}->{_stop};
    return ("\"$start-$stop\" is not a valid IP range", undef)
      if (!Vyatta::TypeChecker::validateType('ipv4', $start, 1)
          || !Vyatta::TypeChecker::validateType('ipv4', $stop, 1));
    $to_dst = " --to-destination ";
    $to_dst .= "$start-$stop";
  }

  if (defined($self->{_inside_addr}->{_port})) {
    if (!$can_use_port) {
      return ("ports can only be specified when protocol is \"tcp\" "
              . "\"udp\" or \"tcp_udp\" (currently \"$self->{_proto}\")", undef);
    }
    if ($use_netmap) {
      return ("Cannot use ports with an IPv4net type translation address as it "
              . "statically maps a whole network of addresses onto another "
              . "network of addresses", undef);
    }
    my ($success, $err) = (undef, undef);
    my $port = $self->{_inside_addr}->{_port};
    if ($port =~ /-/) {
      ($success, $err) = Vyatta::Misc::isValidPortRange($port, '-');
      return ($err, undef) if (!defined($success));
    } elsif ($port =~ /^\d/) {
      ($success, $err) = Vyatta::Misc::isValidPortNumber($port);
      return ($err, undef) if (!defined($success));
    } else {
      if ($self->{_proto} eq 'tcp_udp') {
   ($success, $err) = Vyatta::Misc::isValidPortName($port, 'tcp');
      return ($err, undef) if !defined $success ;
   ($success, $err) = Vyatta::Misc::isValidPortName($port, 'udp');
      return ($err, undef) if !defined $success ;
      $port = getservbyname($port, 'tcp');
      } else {
  ($success, $err) = Vyatta::Misc::isValidPortName($port, $self->{_proto});
      return ($err, undef) if !defined $success ;
      $port = getservbyname($port, $self->{_proto});
      }
    }
    $to_dst = " --to-destination " if $to_dst eq "";
    $to_dst .= ":$port";
  }
  if ($self->{_exclude}) {
    # translation address has no effect for "exclude" rules
  } elsif ($to_dst ne "") {
     if ($use_netmap) {
         # replace "DNAT" with "NETMAP"
         $jump_target = 'NETMAP';
         $jump_param .= " $to_dst";
       } else {
           $jump_param .= " $to_dst";
       }
   } else {
     return ("translation address not specified", undef);
   }
   
  # source rule string
  my ($src_str, $src_err) = $src->rule();
  return ($src_err, undef) if (!defined($src_str));


  # destination rule string
  my ($dst_str, $dst_err) = $dst->rule();
  return ($dst_err, undef) if (!defined($dst_str));
  
  if ($use_netmap) {
    if (!defined $dst->{_network}){
      return ("\ndestination address needs to be defined as a subnet with the same network prefix as translation address" .
              "\nwhen translation address is defined with a prefix for static network mapping "
              , undef);
    }

    my $inside_addr_mask = $self->{_inside_addr}->{_addr};
    my $dst_addr_mask = $dst->{_network};
    $inside_addr_mask =~ s/.+\///;
    $dst_addr_mask =~ s/.+\///;
       if (!($inside_addr_mask == $dst_addr_mask)) {
        return ("\ndestination address should be a subnet with the same network prefix as translation address" .
                "\nwhen translation address is defined with a prefix for static network mapping"
                , undef);
      }

      if ($dst->{_network} =~ /\!/) {
        return ("\ncannot define a negated destination address when translation address" .
                "\nis defined with a prefix for static network mapping "
                , undef);
      }
  }

  return (undef, undef) if defined $self->{_disable};
  
  my $comment = "\"$type-NAT-$self->{_rule_number}\" ";
  if ($tcp_and_udp == 1) {
    $comment = "\"$type-NAT-$self->{_rule_number} tcp_udp\" ";
  }
  my $src_dst_str = make_src_dst_str($src_str, $dst_str);
  $rule_str .= " $src_dst_str " . " -m comment --comment " . $comment . " ";
  if ("$self->{_log}" eq "enable") {
    my $rule_num = $self->{_rule_number};
    my $log_prefix = get_log_prefix($rule_num, $type, $log_modifier);
    if ($tcp_and_udp == 1) {
      my $tcp_log_rule = $rule_str;
      $tcp_log_rule .= " -j LOG --log-prefix \"$log_prefix\" ";
      my $udp_log_rule = $tcp_log_rule;
      $udp_log_rule =~ s/ \-p tcp / -p udp /;
      $rule_str .= " -j $jump_target $jump_param";
      my $udp_rule_str = $rule_str;
      $udp_rule_str =~ s/ \-p tcp / -p udp /;
      return (undef, $tcp_log_rule, $rule_str, $udp_log_rule, $udp_rule_str);
    } else {
      my $log_rule   = $rule_str;
      $log_rule     .= " -j LOG --log-prefix \"$log_prefix\" ";
      $rule_str     .= " -j $jump_target $jump_param";
      return (undef, $log_rule, $rule_str);
    }
  } else {
      $rule_str .= " -j $jump_target $jump_param";
    if ($tcp_and_udp == 1) {
      # protocol is 'tcp_udp'; make another rule for protocol 'udp'
      my $udp_rule_str = $rule_str;
      $udp_rule_str =~ s/ \-p tcp / -p udp /;
      return (undef, $rule_str, $udp_rule_str);
    } else {
      return (undef, $rule_str);
    }
  }
}




sub print_str {
  my ($self) = @_;
  my $str =
  "in_if[$self->{_inbound_if}] " .
  "proto[$self->{_proto}] " .
  "inaddr[$self->{_inside_addr}->{_addr}] " .
  "inrange[$self->{_inside_addr}->{_range}->{_start}-" .
  "$self->{_inside_addr}->{_range}->{_stop}] " .
  "inp[$self->{_inside_addr}->{_port}] ";

  return $str;
}


sub outputXml {
  my ($self, $fh) = @_;
  outputXmlElem("in_interface", $self->{_inbound_if}, $fh);
  outputXmlElem("in_addr", $self->{_inside_addr}->{_addr}, $fh);
  outputXmlElem("in_addr_start", $self->{_inside_addr}->{_range}->{_start},
                $fh);
  outputXmlElem("in_addr_stop", $self->{_inside_addr}->{_range}->{_stop},
                $fh);
  outputXmlElem("in_port", $self->{_inside_addr}->{_port}, $fh);
  $dst->outputXml("dst", $fh);
  # no proto? ($self->{_proto})
}

1;
