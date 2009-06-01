package Vyatta::NatRule;

use strict;
use lib "/opt/vyatta/share/perl5";
require Vyatta::Config;
require Vyatta::IpTables::AddressFilter;
use Vyatta::Misc;
use Vyatta::TypeChecker;

my $src = new Vyatta::IpTables::AddressFilter;
my $dst = new Vyatta::IpTables::AddressFilter;

my %fields = (
  _rule_number  => undef,
  _type	        => undef,
  _orig_type    => undef,
  _inbound_if   => undef,
  _outbound_if  => undef,
  _proto        => undef,
  _exclude      => undef,
  _log          => undef,
  _inside_addr  => {
                    _addr => undef,
                    _range  => {
                                _start => undef,
                                _stop  => undef,
                               },
                    _port => undef,
                   },
  _outside_addr => {
                    _addr   => undef,
                    _range  => {
                                _start => undef,
                                _stop  => undef,
                               },
                    _port => undef,
                   },
);

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
  $self->{_type} = $config->returnValue("type");
  $self->{_orig_type} = $config->returnOrigValue("type");
  $self->{_inbound_if} = $config->returnValue("inbound-interface");
  $self->{_outbound_if} = $config->returnValue("outbound-interface");
  $self->{_proto} = $config->returnValue("protocol");
  $self->{_exclude} = $config->exists("exclude");
  $self->{_log} = $config->returnValue("log");
  
  $self->{_inside_addr}->{_addr}
    = $config->returnValue("inside-address address");
  $self->{_inside_addr}->{_range}->{_start} = undef;
  $self->{_inside_addr}->{_range}->{_stop} = undef;
  if (defined($self->{_inside_addr}->{_addr})
      && $self->{_inside_addr}->{_addr} =~ /^([^-]+)-([^-]+)$/) {
    $self->{_inside_addr}->{_range}->{_start} = $1;
    $self->{_inside_addr}->{_range}->{_stop} = $2;
    $self->{_inside_addr}->{_addr} = undef;
  }
  $self->{_inside_addr}->{_port}
    = $config->returnValue("inside-address port");
  
  $self->{_outside_addr}->{_addr}
    = $config->returnValue("outside-address address");
  $self->{_outside_addr}->{_range}->{_start} = undef;
  $self->{_outside_addr}->{_range}->{_stop} = undef;
  if (defined($self->{_outside_addr}->{_addr})
      && $self->{_outside_addr}->{_addr} =~ /^([^-]+)-([^-]+)$/) {
    $self->{_outside_addr}->{_range}->{_start} = $1;
    $self->{_outside_addr}->{_range}->{_stop} = $2;
    $self->{_outside_addr}->{_addr} = undef;
  }
  $self->{_outside_addr}->{_port}
    = $config->returnValue("outside-address port");

  $src->setup("$level source");
  $dst->setup("$level destination");

  return 0;
}

sub setupOrig {
  my ( $self, $level ) = @_;
  my $config = new Vyatta::Config;

  $config->setLevel("$level");

  $self->{_rule_number} = $config->returnParent("..");
  $self->{_type} = $config->returnOrigValue("type");
  $self->{_orig_type} = $config->returnOrigValue("type");
  $self->{_inbound_if} = $config->returnOrigValue("inbound-interface");
  $self->{_outbound_if} = $config->returnOrigValue("outbound-interface");
  $self->{_proto} = $config->returnOrigValue("protocol");
  $self->{_exclude} = $config->existsOrig("exclude");
  $self->{_log} = $config->returnOrigValue("log");
  
  $self->{_inside_addr}->{_addr}
    = $config->returnOrigValue("inside-address address");
  $self->{_inside_addr}->{_range}->{_start} = undef;
  $self->{_inside_addr}->{_range}->{_stop} = undef;
  if (defined($self->{_inside_addr}->{_addr})
      && $self->{_inside_addr}->{_addr} =~ /^([^-]+)-([^-]+)$/) {
    $self->{_inside_addr}->{_range}->{_start} = $1;
    $self->{_inside_addr}->{_range}->{_stop} = $2;
    $self->{_inside_addr}->{_addr} = undef;
  }
  $self->{_inside_addr}->{_port}
    = $config->returnOrigValue("inside-address port");
  
  $self->{_outside_addr}->{_addr}
    = $config->returnOrigValue("outside-address address");
  $self->{_outside_addr}->{_range}->{_start} = undef;
  $self->{_outside_addr}->{_range}->{_stop} = undef;
  if (defined($self->{_outside_addr}->{_addr})
      && $self->{_outside_addr}->{_addr} =~ /^([^-]+)-([^-]+)$/) {
    $self->{_outside_addr}->{_range}->{_start} = $1;
    $self->{_outside_addr}->{_range}->{_stop} = $2;
    $self->{_outside_addr}->{_addr} = undef;
  }
  $self->{_outside_addr}->{_port}
    = $config->returnOrigValue("outside-address port");

  $src->setupOrig("$level source");
  $dst->setupOrig("$level destination");

  return 0;
}

sub get_num_ipt_rules {
  my $self = shift;
  my $ipt_rules = 1;
  if ("$self->{_log}" eq 'enable') {
      $ipt_rules++;
  }
  return $ipt_rules;
}

my %nat_type_hash = (
  'SNAT'       => 'SNAT',
  'DNAT'       => 'DNAT',
  'MASQUERADE' => 'MASQ',
  'RETURN'     => 'EXCLUDE',
  'NETMAP'     => 'NETMAP',
);

sub get_log_prefix {
  my ($rule_num, $jump_target) = @_;

  # In iptables it allows a 29 character log_prefix, but we ideally
  # want to include "[nat-type-$rule_num] "
  #                  1 3 1  7    1   4  1 1  = 19 
  # so no truncation is needed.
  my $nat_type = $nat_type_hash{$jump_target};
  my $log_prefix  = "[NAT-$rule_num-$nat_type] ";
  return $log_prefix;
}

# returns (error, @rules)
sub rule_str {
  my ($self) = @_;
  my $rule_str = "";
  my $can_use_port = 1;
  my $jump_target = '';
  my $jump_param  = '';
  my $use_netmap = 0;

  if (!defined($self->{_proto}) ||
      (($self->{_proto} ne "tcp") && ($self->{_proto} ne "6")
       && ($self->{_proto} ne "udp") && ($self->{_proto} ne "17"))) {
    $can_use_port = 0;
  }
  if (($self->{_type} eq "source") || ($self->{_type} eq "masquerade")) {
    return ('cannot specify inbound interface with '
                   . '"masquerade" or "source" rules', undef)
      if (defined($self->{_inbound_if}));

    if (defined($self->{_inside_addr}->{_addr}) || 
	defined($self->{_inside_addr}->{_port})	|| 
	(defined($self->{_inside_addr}->{_range}->{_start}) 
		&& defined($self->{_inside_addr}->{_range}->{_stop}))) {
      print "NAT configuration warning:\n'inside-address' is not a relevant option for 'type source'\n";
    }

    if ($self->{_exclude}) {
      $jump_target = 'RETURN';
    } elsif ($self->{_type} eq "masquerade") {
      $jump_target = 'MASQUERADE';
    } else {
      $jump_target = 'SNAT';
    }
    if (defined($self->{_outbound_if})) {
      $rule_str .= " -o $self->{_outbound_if}";
    } else {
      # "masquerade" requires outbound_if.
      # also make this a requirement for "source" to prevent users from
      # inadvertently NATing loopback traffic.
      return ('outbound-interface not specified', undef);
    }

    if (defined($self->{_proto})) {
      my $str = $self->{_proto};
      $str =~ s/^\!(.*)$/! $1/;
      $rule_str .= " -p $str";
    }

    my $to_src = '';
    if (defined($self->{_outside_addr}->{_addr})) {
      my $addr = $self->{_outside_addr}->{_addr};
      if ($addr =~ m/\//) {
         return ("\"$addr\" is not a valid IPv4net address", undef)
         if (!Vyatta::TypeChecker::validateType('ipv4net', $addr, 1));
         $to_src .= $addr;
         $use_netmap = 1;
      } else {
         return ("\"$addr\" is not a valid IP address", undef)
         if (!Vyatta::TypeChecker::validateType('ipv4', $addr, 1));
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
   
    if (($to_src ne "") && ($self->{_type} eq "masquerade")) {
      return ("cannot specify outside IP address with \"masquerade\"", undef);
    }

    if (defined($self->{_outside_addr}->{_port})) {
      if (!$can_use_port) {
        return ("ports can only be specified when protocol is \"tcp\" "
		. "or \"udp\" (currently \"$self->{_proto}\")", undef);
      }
      if ($use_netmap) {
        return ("Cannot use ports with an IPv4net type outside-address as it " . 
                "statically maps a whole network of addresses onto another " .
                "network of addresses", undef);
      }
      if ($self->{_type} ne "masquerade") {
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
	($success, $err) = Vyatta::Misc::isValidPortName($port);
        return ($err, undef) if !defined $success ;
	$port = getservbyname($port, $self->{_proto});
      }
      $to_src .= "$port";
    }
    
    if ($self->{_exclude}) {
      # outside-address has no effect for "exclude" rules
    } elsif ($to_src ne '') {
      if ($self->{_type} eq "masquerade") {
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
    } elsif ($self->{_type} ne "masquerade") {
      return ('outside-address not specified', undef);
    }
  } elsif ($self->{_type} eq "destination") {
    # type is destination
    return ('cannot specify outbound interface with "destination" rules', undef)
	if (defined($self->{_outbound_if}));

    if (defined($self->{_outside_addr}->{_addr}) ||
        defined($self->{_outside_addr}->{_port}) ||
        (defined($self->{_outside_addr}->{_range}->{_start})
                && defined($self->{_outside_addr}->{_range}->{_stop}))) {
      print "NAT configuration warning:\n'outside-address' is not a relevant option for 'type destination'\n";
    }

    if ($self->{_exclude}) {
      $jump_target = 'RETURN';
    } else {
      $jump_target = 'DNAT';
    }
  
    if (defined($self->{_inbound_if})) {
      $rule_str .= " -i $self->{_inbound_if}";
    } else {
      # make this a requirement to prevent users from
      # inadvertently NATing loopback traffic.
      return ('inbound-interface not specified', undef);
    }
  
    if (defined($self->{_proto})) {
      $rule_str .= " -p $self->{_proto}";
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
		. "or \"udp\" (currently \"$self->{_proto}\")", undef);
      }
      if ($use_netmap) {
	return ("Cannot use ports with an IPv4net type outside-address as it " 
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
	($success, $err) = Vyatta::Misc::isValidPortName($port);
        return ($err, undef) if (!defined($success));
	$port = getservbyname($port, $self->{_proto});
      }
      $to_dst .= ":$port";
    }
    
    if ($self->{_exclude}) {
      # inside-address has no effect for "exclude" rules
    } elsif ($to_dst ne "") {
        if ($use_netmap) {
         # replace "DNAT" with "NETMAP"
         $jump_target = 'NETMAP';
         $jump_param .= " $to_dst";
        } else {
	    $jump_param .= " $to_dst";
        }
    } else {
      return ("inside-address not specified", undef);
    }
  } else {
    return ("rule type not specified/valid", undef);
  }

  # source rule string
  my ($src_str, $src_err) = $src->rule();
  return ($src_err, undef) if (!defined($src_str));
  
  # destination rule string
  my ($dst_str, $dst_err) = $dst->rule();
  return ($dst_err, undef) if (!defined($dst_str));

  if ((grep /multiport/, $src_str) || (grep /multiport/, $dst_str)) {
    if ((grep /sport/, $src_str) && (grep /dport/, $dst_str)) {
      return ('cannot specify multiple ports when both source and destination '
              . 'ports are specified', undef);
    }
  }

  # if using netmap then source|destination address should have the same prefix
  # as the outside|inside address depending on the whether the type is src|dst
  if ($self->{_type} eq "source" && $use_netmap) {

    if (!defined $src->{_network}){
      return ("\nsource address needs to be defined as a subnet with the same network prefix as outside-address" .
              "\nwhen outside-address is defined with a prefix for static network mapping "
              , undef);
    }

    my $outside_addr_mask = $self->{_outside_addr}->{_addr};
    my $src_addr_mask = $src->{_network};
    $outside_addr_mask =~ s/.+\///;
    $src_addr_mask =~ s/.+\///;

    if (!($outside_addr_mask == $src_addr_mask)) {
      return ("\nsource address should be a subnet with the same network prefix as outside-address" .
              "\nwhen outside-address is defined with a prefix for static network mapping "
              , undef);
    }

    if ($src->{_network} =~ /\!/) {
      return ("\ncannot define a negated source address when outside-address" .
              "\nis defined with a prefix for static network mapping "
              , undef);

    }
  } elsif ($self->{_type} eq "destination" && $use_netmap) {

    if (!defined $dst->{_network}){
      return ("\ndestination address needs to be defined as a subnet with the same network prefix as inside-address" .
              "\nwhen inside-address is defined with a prefix for static network mapping "
              , undef);
    }

    my $inside_addr_mask = $self->{_inside_addr}->{_addr};
    my $dst_addr_mask = $dst->{_network};
    $inside_addr_mask =~ s/.+\///;
    $dst_addr_mask =~ s/.+\///;

    if (!($inside_addr_mask == $dst_addr_mask)) {
      return ("\ndestination address should be a subnet with the same network prefix as inside-address" .
              "\nwhen inside-address is defined with a prefix for static network mapping"
              , undef);
    }

    if ($dst->{_network} =~ /\!/) {
      return ("\ncannot define a negated destination address when inside-address" .
              "\nis defined with a prefix for static network mapping "
              , undef);

    }
  }

  $rule_str .= " $src_str $dst_str";
  if ("$self->{_log}" eq "enable") {
    my $log_rule   = $rule_str;
    my $rule_num = $self->{_rule_number};
    my $log_prefix = get_log_prefix($rule_num, $jump_target);
    $log_rule     .= " -j LOG --log-prefix \"$log_prefix\" ";
    $rule_str     .= " -j $jump_target $jump_param";
    return (undef, $log_rule, $rule_str);
  } else {
    $rule_str .= " -j $jump_target $jump_param";
    return (undef, $rule_str);
  }
}

sub orig_type {
  my ($self) = @_;
  return "source" if ($self->{_orig_type} eq "masquerade");
  return $self->{_orig_type};
}

sub new_type {
  my ($self) = @_;
  return "source" if ($self->{_type} eq "masquerade");
  return $self->{_type};
}

sub print_str {
  my ($self) = @_;
  my $str =
  "type[$self->{_type}] " .
  "in_if[$self->{_inbound_if}] out_if[$self->{_outbound_if}] " .
  "proto[$self->{_proto}] " .
  "inaddr[$self->{_inside_addr}->{_addr}] " .
  "inrange[$self->{_inside_addr}->{_range}->{_start}-" .
  "$self->{_inside_addr}->{_range}->{_stop}] " .
  "inp[$self->{_inside_addr}->{_port}] " .
  "outaddr[$self->{_outside_addr}->{_addr}] " .
  "outrange[$self->{_outside_addr}->{_range}->{_start}-" .
  "$self->{_outside_addr}->{_range}->{_stop}]" .
  "outp[$self->{_outside_addr}->{_port}] ";
  
  return $str;
}

sub outputXmlElem {
  my ($name, $value, $fh) = @_;
  print $fh "    <$name>$value</$name>\n";
}

sub outputXml {
  my ($self, $fh) = @_;
  outputXmlElem("type", $self->{_type}, $fh);
  outputXmlElem("in_interface", $self->{_inbound_if}, $fh);
  outputXmlElem("out_interface", $self->{_outbound_if}, $fh);
  outputXmlElem("in_addr", $self->{_inside_addr}->{_addr}, $fh);
  outputXmlElem("in_addr_start", $self->{_inside_addr}->{_range}->{_start},
                $fh);
  outputXmlElem("in_addr_stop", $self->{_inside_addr}->{_range}->{_stop},
                $fh);
  outputXmlElem("in_port", $self->{_inside_addr}->{_port}, $fh);
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

# Local Variables:
# mode: perl
# indent-tabs-mode: nil
# perl-indent-level: 2
# End:
