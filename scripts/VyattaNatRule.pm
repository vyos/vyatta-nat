package VyattaNatRule;

use strict;
use lib "/opt/vyatta/share/perl5/";
use VyattaConfig;
use VyattaMisc;
use VyattaTypeChecker;

my %fields = (
  _type	        => undef,
  _orig_type    => undef,
  _inbound_if   => undef,
  _outbound_if  => undef,
  _proto        => undef,
  _exclude      => undef,
  _source       => {
                    _addr       => undef,
                    _net        => undef,
                    _port       => undef,
                   },
  _destination  => {
                    _addr       => undef,
                    _net        => undef,
                    _port       => undef,
                   },
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
  my $config = new VyattaConfig;

  $config->setLevel("$level");

  $self->{_type} = $config->returnValue("type");
  $self->{_orig_type} = $config->returnOrigValue("type");
  $self->{_inbound_if} = $config->returnValue("inbound-interface");
  $self->{_outbound_if} = $config->returnValue("outbound-interface");
  $self->{_proto} = $config->returnValue("protocol");
  $self->{_exclude} = $config->exists("exclude");
  
  $self->{_source}->{_net} = undef;
  $self->{_source}->{_addr} = $config->returnValue("source address");
  if (defined($self->{_source}->{_addr})
      && ($self->{_source}->{_addr} =~ /\//)) {
    $self->{_source}->{_net} = $self->{_source}->{_addr};
    $self->{_source}->{_addr} = undef;
  }
  $self->{_source}->{_port} = $config->returnValue("source port");

  $self->{_destination}->{_net} = undef;
  $self->{_destination}->{_addr} = $config->returnValue("destination address");
  if (defined($self->{_destination}->{_addr})
      && ($self->{_destination}->{_addr} =~ /\//)) {
    $self->{_destination}->{_net} = $self->{_destination}->{_addr};
    $self->{_destination}->{_addr} = undef;
  }
  $self->{_destination}->{_port} = $config->returnValue("destination port");
  
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

  return 0;
}

sub setupOrig {
  my ( $self, $level ) = @_;
  my $config = new VyattaConfig;

  $config->setLevel("$level");

  $self->{_type} = $config->returnOrigValue("type");
  $self->{_orig_type} = $config->returnOrigValue("type");
  $self->{_inbound_if} = $config->returnOrigValue("inbound-interface");
  $self->{_outbound_if} = $config->returnOrigValue("outbound-interface");
  $self->{_proto} = $config->returnOrigValue("protocol");
  $self->{_exclude} = $config->existsOrig("exclude");
  
  $self->{_source}->{_net} = undef;
  $self->{_source}->{_addr} = $config->returnOrigValue("source address");
  if (defined($self->{_source}->{_addr})
      && ($self->{_source}->{_addr} =~ /\//)) {
    $self->{_source}->{_net} = $self->{_source}->{_addr};
    $self->{_source}->{_addr} = undef;
  }
  $self->{_source}->{_port} = $config->returnOrigValue("source port");

  $self->{_destination}->{_net} = undef;
  $self->{_destination}->{_addr}
    = $config->returnOrigValue("destination address");
  if (defined($self->{_destination}->{_addr})
      && ($self->{_destination}->{_addr} =~ /\//)) {
    $self->{_destination}->{_net} = $self->{_destination}->{_addr};
    $self->{_destination}->{_addr} = undef;
  }
  $self->{_destination}->{_port}
    = $config->returnOrigValue("destination port");
  
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

  return 0;
}

# returns (rule, error)
sub rule_str {
  my ($self) = @_;
  my $rule_str = "";
  my $can_use_port = 1;

  if (!defined($self->{_proto}) ||
      (($self->{_proto} ne "tcp") && ($self->{_proto} ne "6")
       && ($self->{_proto} ne "udp") && ($self->{_proto} ne "17"))) {
    $can_use_port = 0;
  }
  if (($self->{_type} eq "source") || ($self->{_type} eq "masquerade")) {
    if ($self->{_exclude}) {
      $rule_str .= "-j RETURN";
    } elsif ($self->{_type} eq "masquerade") {
      $rule_str .= "-j MASQUERADE";
    } else {
      $rule_str .= "-j SNAT";
    }
    if (defined($self->{_outbound_if})) {
      $rule_str .= " -o $self->{_outbound_if}";
    } else {
      # "masquerade" requires outbound_if.
      # also make this a requirement for "source" to prevent users from
      # inadvertently NATing loopback traffic.
      return (undef, "outbound-interface not specified");
    }

    if (defined($self->{_proto})) {
      my $str = $self->{_proto};
      $str =~ s/^\!(.*)$/! $1/;
      $rule_str .= " -p $str";
    }

    my $to_src = '';
    if (defined($self->{_outside_addr}->{_addr})) {
      my $addr = $self->{_outside_addr}->{_addr};
      return (undef, "\"$addr\" is not a valid IP address")
        if (!VyattaTypeChecker::validateType('ipv4', $addr, 1));
      $to_src .= $addr;
    } elsif (defined($self->{_outside_addr}->{_range}->{_start})
             && defined($self->{_outside_addr}->{_range}->{_stop})) {
      my $start = $self->{_outside_addr}->{_range}->{_start};
      my $stop = $self->{_outside_addr}->{_range}->{_stop};
      return (undef, "\"$start-$stop\" is not a valid IP range")
        if (!VyattaTypeChecker::validateType('ipv4', $start, 1)
            || !VyattaTypeChecker::validateType('ipv4', $stop, 1));
      $to_src .= "$start-$stop";
    }
   
    if (($to_src ne "") && ($self->{_type} eq "masquerade")) {
      return (undef, "cannot specify outside IP address with \"masquerade\"");
    }

    if (defined($self->{_outside_addr}->{_port})) {
      if (!$can_use_port) {
        return (undef, "ports can only be specified when protocol is \"tcp\" "
                       . "or \"udp\" (currently \"$self->{_proto}\")");
      }
      if ($self->{_type} ne "masquerade") {
        $to_src .= ":";
      }
      my ($success, $err) = (undef, undef);
      if ($self->{_outside_addr}->{_port} =~ /-/) {
        ($success, $err)
          = VyattaMisc::isValidPortRange($self->{_outside_addr}->{_port}, '-');
        return (undef, $err) if (!defined($success));
      } else {
        ($success, $err)
          = VyattaMisc::isValidPortNumber($self->{_outside_addr}->{_port});
        return (undef, $err) if (!defined($success));
      }
      $to_src .= "$self->{_outside_addr}->{_port}";
    }
    
    if ($to_src ne "") {
      if ($self->{_type} eq "masquerade") {
        $rule_str .= " --to-ports $to_src";
      } else {
        $rule_str .= " --to-source $to_src";
      }
    } elsif ($self->{_type} ne "masquerade") {
      return (undef, "outside-address not specified");
    }
  } else {
    # type is destination
    if ($self->{_exclude}) {
      $rule_str .= "-j RETURN";
    } else {
      $rule_str .= "-j DNAT";
    }
  
    if (defined($self->{_inbound_if})) {
      $rule_str .= " -i $self->{_inbound_if}";
    } else {
      # make this a requirement to prevent users from
      # inadvertently NATing loopback traffic.
      return (undef, "inbound-interface not specified");
    }
  
    if (defined($self->{_proto})) {
      $rule_str .= " -p $self->{_proto}";
    }

    my $to_dst = " --to-destination ";
    if (defined($self->{_inside_addr}->{_addr})) {
      my $addr = $self->{_inside_addr}->{_addr};
      return (undef, "\"$addr\" is not a valid IP address")
        if (!VyattaTypeChecker::validateType('ipv4', $addr, 1));
      $to_dst .= $addr;
    } elsif (defined($self->{_inside_addr}->{_range}->{_start})
             && defined($self->{_inside_addr}->{_range}->{_stop})) {
      my $start = $self->{_inside_addr}->{_range}->{_start};
      my $stop = $self->{_inside_addr}->{_range}->{_stop};
      return (undef, "\"$start-$stop\" is not a valid IP range")
        if (!VyattaTypeChecker::validateType('ipv4', $start, 1)
            || !VyattaTypeChecker::validateType('ipv4', $stop, 1));
      $to_dst .= "$start-$stop";
    } 
    
    if (defined($self->{_inside_addr}->{_port})) {
      if (!$can_use_port) {
        return (undef, "ports can only be specified when protocol is \"tcp\" "
                       . "or \"udp\" (currently \"$self->{_proto}\")");
      }
      my ($success, $err) = (undef, undef);
      if ($self->{_inside_addr}->{_port} =~ /-/) {
        ($success, $err)
          = VyattaMisc::isValidPortRange($self->{_inside_addr}->{_port}, '-');
        return (undef, $err) if (!defined($success));
      } else {
        ($success, $err)
          = VyattaMisc::isValidPortNumber($self->{_inside_addr}->{_port});
        return (undef, $err) if (!defined($success));
      }
      $to_dst .= ":$self->{_inside_addr}->{_port}";
    }
    
    if ($to_dst ne " --to-destination ") {
      $rule_str .= $to_dst;
    } else {
      return (undef, "inside-address not specified");
    }
  }

  # source port(s)
  my ($port_str, $port_err)
    = VyattaMisc::getPortRuleString($self->{_source}->{_port},
                                    $can_use_port, "s", $self->{_proto});
  return (undef, $port_err) if (!defined($port_str));
  $rule_str .= $port_str;
  
  # destination port(s)
  ($port_str, $port_err)
    = VyattaMisc::getPortRuleString($self->{_destination}->{_port},
                                    $can_use_port, "d", $self->{_proto});
  return (undef, $port_err) if (!defined($port_str));
  $rule_str .= $port_str;

  if (defined($self->{_source}->{_addr})) {
    my $str = $self->{_source}->{_addr};
    return (undef, "\"$str\" is not a valid IP address")
      if (!VyattaTypeChecker::validateType('ipv4_negate', $str, 1));
    $str =~ s/^\!(.*)$/! $1/;
    $rule_str .= " -s $str";
  } elsif (defined($self->{_source}->{_net})) {
    my $str = $self->{_source}->{_net};
    return (undef, "\"$str\" is not a valid IP subnet")
      if (!VyattaTypeChecker::validateType('ipv4net_negate', $str, 1));
    $str =~ s/^\!(.*)$/! $1/;
    $rule_str .= " -s $str";
  }
 
  if (defined($self->{_destination}->{_addr})) {
    my $str = $self->{_destination}->{_addr};
    return (undef, "\"$str\" is not a valid IP address")
      if (!VyattaTypeChecker::validateType('ipv4_negate', $str, 1));
    $str =~ s/^\!(.*)$/! $1/;
    $rule_str .= " -d $str";
  } elsif (defined($self->{_destination}->{_net})) {
    my $str = $self->{_destination}->{_net};
    return (undef, "\"$str\" is not a valid IP subnet")
      if (!VyattaTypeChecker::validateType('ipv4net_negate', $str, 1));
    $str =~ s/^\!(.*)$/! $1/;
    $rule_str .= " -d $str";
  }

  return ($rule_str, "");
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
  "proto[$self->{_proto}] saddr[$self->{_source}->{_addr}] ".
  "snet[$self->{_source}->{_net}] sp[@{$self->{_source}->{_port}}] ".
  "daddr[$self->{_destination}->{_addr}] " .
  "dnet[$self->{_destination}->{_net}] " .
  "dp[@{$self->{_destination}->{_port}}] " .
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
  outputXmlElem("src_addr", $self->{_source}->{_addr}, $fh);
  outputXmlElem("src_network", $self->{_source}->{_net}, $fh);
  outputXmlElem("src_ports", $self->{_source}->{_port}, $fh);
  outputXmlElem("dst_addr", $self->{_destination}->{_addr}, $fh);
  outputXmlElem("dst_network", $self->{_destination}->{_net}, $fh);
  outputXmlElem("dst_ports", $self->{_destination}->{_port}, $fh);
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
  
  # no proto? ($self->{_proto})
}

1;

