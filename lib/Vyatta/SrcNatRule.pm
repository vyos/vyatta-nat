#
# Module: SrcNatRule.pm
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
# Description: Source NAT rule handling library
#
# **** End License ****
#

package Vyatta::SrcNatRule;

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
  _outbound_if  => undef,
  _proto        => undef,
  _exclude      => undef,
  _disable      => undef,
  _log          => undef,
  _outside_addr => {
                    _addr   => undef,
                    _range  => {
                                _start => undef,
                                _stop  => undef,
                               },
                    _port => undef,
                   },
  _is_masq => undef
);

my $type = "SRC";

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
  $self->{_outbound_if} = $config->returnValue("outbound-interface");
  $self->{_proto} = $config->returnValue("protocol");
  $self->{_exclude} = $config->exists("exclude");
  $self->{_disable} = $config->exists("disable");
  $self->{_log} = $config->returnValue("log");
  
  $self->{_outside_addr}->{_addr}
    = $config->returnValue("translation address");
  if (defined($self->{_outside_addr}->{_addr}) && ($self->{_outside_addr}->{_addr} eq "masquerade")) {
    $self->{_is_masq} = 1;
  }
  $self->{_outside_addr}->{_range}->{_start} = undef;
  $self->{_outside_addr}->{_range}->{_stop} = undef;
  if (defined($self->{_outside_addr}->{_addr})
      && $self->{_outside_addr}->{_addr} =~ /^([^-]+)-([^-]+)$/) {
    $self->{_outside_addr}->{_range}->{_start} = $1;
    $self->{_outside_addr}->{_range}->{_stop} = $2;
    $self->{_outside_addr}->{_addr} = undef;
  }
  $self->{_outside_addr}->{_port}
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
  $self->{_outbound_if} = $config->returnOrigValue("outbound-interface");
  $self->{_proto} = $config->returnOrigValue("protocol");
  $self->{_exclude} = $config->existsOrig("exclude");
  $self->{_disable} = $config->existsOrig("disable");
  $self->{_log} = $config->returnOrigValue("log");
  
  $self->{_outside_addr}->{_addr}
    = $config->returnOrigValue("translation address");
  if (defined($self->{_outside_addr}->{_addr}) && ($self->{_outside_addr}->{_addr} eq "masquerade")) {
    $self->{_is_masq} = 1;
  }
  $self->{_outside_addr}->{_range}->{_start} = undef;
  $self->{_outside_addr}->{_range}->{_stop} = undef;
  if (defined($self->{_outside_addr}->{_addr})
      && $self->{_outside_addr}->{_addr} =~ /^([^-]+)-([^-]+)$/) {
    $self->{_outside_addr}->{_range}->{_start} = $1;
    $self->{_outside_addr}->{_range}->{_stop} = $2;
    $self->{_outside_addr}->{_addr} = undef;
  }
  $self->{_outside_addr}->{_port}
    = $config->returnOrigValue("translation port");

  $src->setupOrig("$level source");
  $dst->setupOrig("$level destination");

  return 0;
}

# returns (error, @rules)
sub rule_str {
  my ($self) = @_;
  my $rule_str = "";
  my $can_use_port = 1;
  my $jump_target = '';
  my $jump_param  = '';
  my $log_modifier = '';
  my $use_netmap = 0;
  my $tcp_and_udp = 0; 

  if (!defined($self->{_proto}) ||
      (($self->{_proto} ne "tcp_udp") 
        && ($self->{_proto} ne "tcp") && ($self->{_proto} ne "6")
        && ($self->{_proto} ne "udp") && ($self->{_proto} ne "17"))) {
    $can_use_port = 0;
  }

    if ($self->{_exclude}) {
      $jump_target = 'RETURN';
      $log_modifier = 'EXCL';
    } elsif (defined($self->{_is_masq})) {
      $jump_target = 'MASQUERADE';
      $log_modifier = 'MASQ';
    } else {
      $jump_target = 'SNAT';
    }

    if (defined($self->{_outbound_if})) {
      if ($self->{_outbound_if} ne "any") {
        $rule_str .= " -o $self->{_outbound_if}";
      }
    } else {
      # "masquerade" requires outbound_if.
      # also make this a requirement for "source" to prevent users from
      # inadvertently NATing loopback traffic.
      return ('outbound-interface not specified', undef);
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

    my $to_src = '';
    if (defined($self->{_outside_addr}->{_addr})) {

      # Check translation address
      my $addr = $self->{_outside_addr}->{_addr};
      if (defined($self->{_is_masq})) {
        # It's masquerade rule, outside address will not be used anyway
        1;
      } elsif ($addr =~ m/\//) {
         # Translation address is a probably x.x.x.x/y subnet thus it's a *-to-many rule
         # Target will be NETMAP
         return ("\"$addr\" is not a valid IPv4net address", undef)
         if (!Vyatta::TypeChecker::validateType('ipv4net', $addr, 1));
         $to_src .= $addr;
         $use_netmap = 1;
      } else {
         return ("\"$addr\" is not a valid IP address", undef)
         if (!Vyatta::TypeChecker::validateType('ipv4', $addr, 1));

         print("Warning: IP address $addr does not exist on the system!\n")
	     if !(is_local_address($addr));
	     
         $to_src .= $addr;
      }
    } elsif (defined($self->{_outside_addr}->{_range}->{_start})
             && defined($self->{_outside_addr}->{_range}->{_stop})) {
      my $start = $self->{_outside_addr}->{_range}->{_start};
      my $stop = $self->{_outside_addr}->{_range}->{_stop};
      return ("\"$start-$stop\" is not a valid IP range", undef)
        if (!Vyatta::TypeChecker::validateType('ipv4', $start, 1)
            || !Vyatta::TypeChecker::validateType('ipv4', $stop, 1));
      $to_src .= "$start-$stop";
    }
   
    if (defined($self->{_outside_addr}->{_port})) {
      if (!$can_use_port) {
        return ("ports can only be specified when protocol is \"tcp\" "
		. "\"udp\" or \"tcp_udp\" (currently \"$self->{_proto}\")", undef);
      }
      if ($use_netmap) {
        return ("Cannot use ports with an IPv4net type translation address as it " . 
                "statically maps a whole network of addresses onto another " .
                "network of addresses", undef);
      }

      if (!defined($self->{_is_masq})) {
        $to_src .= ":";
      }
      my ($success, $err) = (undef, undef);
      my $port = $self->{_outside_addr}->{_port};
      if ($port =~ /-/) {
        ($success, $err)
          = Vyatta::Misc::isValidPortRange($port, '-');
        return ($err, undef) if (!defined($success));
      } elsif ($port =~ /^\d/) {
        ($success, $err)
          = Vyatta::Misc::isValidPortNumber($port);
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
      $to_src .= "$port";
    }
    
    if ($self->{_exclude}) {
      # translation address has no effect for "exclude" rules
    } elsif ($to_src ne '') {
      if (defined($self->{_is_masq})) {
        $jump_param .= " --to-ports $to_src";
      } else {
        if ($use_netmap) {
         # replace "SNAT" with "NETMAP"
         $jump_target = 'NETMAP';
         $jump_param .= " --to $to_src";
        } else {
           $jump_param .= " --to-source $to_src";
        }
      }
    } elsif (!defined($self->{_is_masq})) {
      return ('translation address not specified', undef);
    }


  # source rule string
  my ($src_str, $src_err) = $src->rule();
  return ($src_err, undef) if (!defined($src_str));
  
  # destination rule string
  my ($dst_str, $dst_err) = $dst->rule();
  return ($dst_err, undef) if (!defined($dst_str));

  # if using netmap then source address should have the same prefix
  # as the outside|inside address depending on the whether the type is src|dst
  if ($use_netmap) {

    if (!defined $src->{_network}){
      return ("\nsource address needs to be defined as a subnet with the same network prefix as translation address" .
              "\nwhen translation address is defined with a prefix for static network mapping "
              , undef);
    }

    my $outside_addr_mask = $self->{_outside_addr}->{_addr};
    my $src_addr_mask = $src->{_network};
    $outside_addr_mask =~ s/.+\///;
    $src_addr_mask =~ s/.+\///;

    if (!($outside_addr_mask == $src_addr_mask)) {
      return ("\nsource address should be a subnet with the same network prefix as translation address" .
              "\nwhen translation address is defined with a prefix for static network mapping "
              , undef);
    }

    if ($src->{_network} =~ /\!/) {
      return ("\ncannot define a negated source address when translation address" .
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
  $rule_str .= " $src_dst_str" . " -m comment --comment " . $comment;
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
  "out_if[$self->{_outbound_if}] " .
  "proto[$self->{_proto}] " .
  "outaddr[$self->{_outside_addr}->{_addr}] " .
  "outrange[$self->{_outside_addr}->{_range}->{_start}-" .
  "$self->{_outside_addr}->{_range}->{_stop}]" .
  "outp[$self->{_outside_addr}->{_port}] ";
  
  return $str;
}

sub outputXml {
  my ($self, $fh) = @_;
  outputXmlElem("out_interface", $self->{_outbound_if}, $fh);
  outputXmlElem("out_addr", $self->{_outside_addr}->{_addr}, $fh);
  outputXmlElem("out_addr_start", $self->{_outside_addr}->{_range}->{_start},
                $fh);
  outputXmlElem("out_addr_stop", $self->{_outside_addr}->{_range}->{_stop},
                $fh);
  outputXmlElem("out_port", $self->{_outside_addr}->{_port}, $fh);
 
  $src->outputXml("src", $fh);
  $dst->outputXml("dst", $fh);
  # no proto? ($self->{_proto})
}

1;

