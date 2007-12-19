package VyattaNatRule;

use strict;
use lib "/opt/vyatta/share/perl5/";
use VyattaConfig;

my %fields = (
  _type	        => undef,
  _orig_type    => undef,
  _inbound_if   => undef,
  _outbound_if  => undef,
  _proto        => undef,
  _source       => {
                    _addr       => undef,
                    _net        => undef,
                    _port_num   => undef,
                    _port_name  => undef,
                    _port_range => {
                                    _start => undef,
                                    _stop  => undef,
                                   },
                   },
  _destination  => {
                    _addr       => undef,
                    _net        => undef,
                    _port_num   => undef,
                    _port_name  => undef,
                    _port_range => {
                                    _start => undef,
                                    _stop  => undef,
                                   },
                   },
  _inside_addr  => {
                    _addr => undef,
                    _range  => {
                                _start => undef,
                                _stop  => undef,
                               },
                    _port_num   => undef,
                    _port_range => {
                                    _start => undef,
                                    _stop  => undef,
                                   },
                   },
  _outside_addr => {
                    _addr   => undef,
                    _range  => {
                                _start => undef,
                                _stop  => undef,
                               },
                    _port_num   => undef,
                    _port_range => {
                                    _start => undef,
                                    _stop  => undef,
                                   },
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
  $self->{_proto} = $config->returnValue("protocols");
  
  $self->{_source}->{_addr} = $config->returnValue("source address");
  $self->{_source}->{_net} = $config->returnValue("source network");
  my @tmp = $config->returnValues("source port-number");
  $self->{_source}->{_port_num} = [ @tmp ];
  @tmp = $config->returnValues("source port-name");
  $self->{_source}->{_port_name} = [ @tmp ];
  $self->{_source}->{_port_range}->{_start}
    = $config->returnValue("source port-range start");
  $self->{_source}->{_port_range}->{_stop}
    = $config->returnValue("source port-range stop");

  $self->{_destination}->{_addr} = $config->returnValue("destination address");
  $self->{_destination}->{_net} = $config->returnValue("destination network");
  @tmp = $config->returnValues("destination port-number");
  $self->{_destination}->{_port_num} = [ @tmp ];
  @tmp = $config->returnValues("destination port-name");
  $self->{_destination}->{_port_name} = [ @tmp ];
  $self->{_destination}->{_port_range}->{_start}
    = $config->returnValue("destination port-range start");
  $self->{_destination}->{_port_range}->{_stop}
    = $config->returnValue("destination port-range stop");
  
  $self->{_inside_addr}->{_addr}
    = $config->returnValue("inside-address address");
  $self->{_inside_addr}->{_range}->{_start}
    = $config->returnValue("inside-address range start");
  $self->{_inside_addr}->{_range}->{_stop}
    = $config->returnValue("inside-address range stop");
  $self->{_inside_addr}->{_port_num}
    = $config->returnValue("inside-address port-number");
  $self->{_inside_addr}->{_port_range}->{_start}
    = $config->returnValue("inside-address port-range start");
  $self->{_inside_addr}->{_port_range}->{_stop}
    = $config->returnValue("inside-address port-range stop");
  
  $self->{_outside_addr}->{_addr}
    = $config->returnValue("outside-address address");
  $self->{_outside_addr}->{_range}->{_start}
    = $config->returnValue("outside-address range start");
  $self->{_outside_addr}->{_range}->{_stop}
    = $config->returnValue("outside-address range stop");
  $self->{_outside_addr}->{_port_num}
    = $config->returnValue("outside-address port-number");
  $self->{_outside_addr}->{_port_range}->{_start}
    = $config->returnValue("outside-address port-range start");
  $self->{_outside_addr}->{_port_range}->{_stop}
    = $config->returnValue("outside-address port-range stop");

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
  $self->{_proto} = $config->returnOrigValue("protocols");
  
  $self->{_source}->{_addr} = $config->returnOrigValue("source address");
  $self->{_source}->{_net} = $config->returnOrigValue("source network");
  my @tmp = $config->returnOrigValues("source port-number");
  $self->{_source}->{_port_num} = [ @tmp ];
  @tmp = $config->returnOrigValues("source port-name");
  $self->{_source}->{_port_name} = [ @tmp ];
  $self->{_source}->{_port_range}->{_start}
    = $config->returnOrigValue("source port-range start");
  $self->{_source}->{_port_range}->{_stop}
    = $config->returnOrigValue("source port-range stop");

  $self->{_destination}->{_addr}
    = $config->returnOrigValue("destination address");
  $self->{_destination}->{_net}
    = $config->returnOrigValue("destination network");
  @tmp = $config->returnOrigValues("destination port-number");
  $self->{_destination}->{_port_num} = [ @tmp ];
  @tmp = $config->returnOrigValues("destination port-name");
  $self->{_destination}->{_port_name} = [ @tmp ];
  $self->{_destination}->{_port_range}->{_start}
    = $config->returnOrigValue("destination port-range start");
  $self->{_destination}->{_port_range}->{_stop}
    = $config->returnOrigValue("destination port-range stop");
  
  $self->{_inside_addr}->{_addr}
    = $config->returnOrigValue("inside-address address");
  $self->{_inside_addr}->{_range}->{_start}
    = $config->returnOrigValue("inside-address range start");
  $self->{_inside_addr}->{_range}->{_stop}
    = $config->returnOrigValue("inside-address range stop");
  $self->{_inside_addr}->{_port_num}
    = $config->returnOrigValue("inside-address port-number");
  $self->{_inside_addr}->{_port_range}->{_start}
    = $config->returnOrigValue("inside-address port-range start");
  $self->{_inside_addr}->{_port_range}->{_stop}
    = $config->returnOrigValue("inside-address port-range stop");
  
  $self->{_outside_addr}->{_addr}
    = $config->returnOrigValue("outside-address address");
  $self->{_outside_addr}->{_range}->{_start}
    = $config->returnOrigValue("outside-address range start");
  $self->{_outside_addr}->{_range}->{_stop}
    = $config->returnOrigValue("outside-address range stop");
  $self->{_outside_addr}->{_port_num}
    = $config->returnOrigValue("outside-address port-number");
  $self->{_outside_addr}->{_port_range}->{_start}
    = $config->returnOrigValue("outside-address port-range start");
  $self->{_outside_addr}->{_port_range}->{_stop}
    = $config->returnOrigValue("outside-address port-range stop");

  return 0;
}

sub handle_ports {
  my $num_ref = shift;
  my $name_ref = shift;
  my $pstart = shift;
  my $pstop = shift;
  my $can_use_port = shift;
  my $prefix = shift;
  my $proto = shift;

  my $rule_str = "";
  my ($ports, $prange) = (0, 0);
  my @pnums = @{$num_ref};
  my @pnames = @{$name_ref};
  $ports = ($#pnums + 1) + ($#pnames + 1);

  if (defined($pstart) && defined($pstop)) {
    if ($pstop < $pstart) {
      return (undef, "invalid port range $pstart-$pstop");
    }
    $ports += ($pstop - $pstart + 1);
    $prange = ($pstop - $pstart - 1);
  }
  if (($ports > 0) && (!$can_use_port)) {
    return (undef, "ports can only be specified when protocol is \"tcp\" "
                   . "or \"udp\" (currently \"$proto\")");
  }
  if (($ports - $prange) > 15) {
    return (undef, "source/destination port specification only supports "
                   . "up to 15 ports (port range counts as 2)");
  }
  if ($ports > 1) {
    $rule_str .= " -m multiport --${prefix}ports ";
    my $first = 1;
    if ($#pnums >= 0) {
      my $pstr = join(',', @pnums);
      $rule_str .= "$pstr";
      $first = 0;
    }
    if ($#pnames >= 0) {
      if ($first == 0) {
        $rule_str .= ",";
      }
      my $pstr = join(',', @pnames);
      $rule_str .= "$pstr";
      $first = 0;
    }
    if (defined($pstart) && defined($pstop)) {
      if ($first == 0) {
        $rule_str .= ",";
      }
      if ($pstart == $pstop) {
        $rule_str .= "$pstart";
      } else {
        $rule_str .= "$pstart:$pstop";
      }
      $first = 0;
    }
  } elsif ($ports > 0) {
    $rule_str .= " --${prefix}port ";
    if ($#pnums >= 0) {
      $rule_str .= "$pnums[0]";
    } elsif ($#pnames >= 0) {
      $rule_str .= "$pnames[0]";
    } else {
      # no number, no name, range of 1
      $rule_str .= "$pstart";
    }
  }

  return ($rule_str, undef);
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
    if ($self->{_type} eq "masquerade") {
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

    #my $to_src = " --to-source ";
    my $to_src = "";
    if (defined($self->{_outside_addr}->{_addr})) {
      $to_src .= "$self->{_outside_addr}->{_addr}";
    } elsif (defined($self->{_outside_addr}->{_range}->{_start})
             && defined($self->{_outside_addr}->{_range}->{_stop})) {
      $to_src .= "$self->{_outside_addr}->{_range}->{_start}";
      $to_src .= "-$self->{_outside_addr}->{_range}->{_stop}";
    }
   
    if (($to_src ne "") && ($self->{_type} eq "masquerade")) {
      return (undef, "cannot specify outside IP address with \"masquerade\"");
    }

    if (defined($self->{_outside_addr}->{_port_num})) {
      if (!$can_use_port) {
        return (undef, "ports can only be specified when protocol is \"tcp\" "
                       . "or \"udp\" (currently \"$self->{_proto}\")");
      }
      if ($self->{_type} ne "masquerade") {
        $to_src .= ":";
      }
      $to_src .= "$self->{_outside_addr}->{_port_num}";
    } elsif (defined($self->{_outside_addr}->{_port_range}->{_start})
             && defined($self->{_outside_addr}->{_port_range}->{_stop})) {
      if (!$can_use_port) {
        return (undef, "ports can only be specified when protocol is \"tcp\" "
                       . "or \"udp\" (currently \"$self->{_proto}\")");
      }
      if ($self->{_type} ne "masquerade") {
        $to_src .= ":";
      }
      $to_src .= "$self->{_outside_addr}->{_port_range}->{_start}";
      $to_src .= "-$self->{_outside_addr}->{_port_range}->{_stop}";
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
    $rule_str .= "-j DNAT";
  
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
      $to_dst .= "$self->{_inside_addr}->{_addr}";
    } elsif (defined($self->{_inside_addr}->{_range}->{_start})
             && defined($self->{_inside_addr}->{_range}->{_stop})) {
      $to_dst .= "$self->{_inside_addr}->{_range}->{_start}";
      $to_dst .= "-$self->{_inside_addr}->{_range}->{_stop}";
    } 
    if (defined($self->{_inside_addr}->{_port_num})) {
      if (!$can_use_port) {
        return (undef, "ports can only be specified when protocol is \"tcp\" "
                       . "or \"udp\" (currently \"$self->{_proto}\")");
      }
      $to_dst .= ":$self->{_inside_addr}->{_port_num}";
    } elsif (defined($self->{_inside_addr}->{_port_range}->{_start})
             && defined($self->{_inside_addr}->{_port_range}->{_stop})) {
      if (!$can_use_port) {
        return (undef, "ports can only be specified when protocol is \"tcp\" "
                       . "or \"udp\" (currently \"$self->{_proto}\")");
      }
      $to_dst .= ":$self->{_inside_addr}->{_port_range}->{_start}";
      $to_dst .= "-$self->{_inside_addr}->{_port_range}->{_stop}";
    }
    if ($to_dst ne " --to-destination ") {
      $rule_str .= $to_dst;
    } else {
      return (undef, "inside-address not specified");
    }
  }

  # source port(s)
  my ($port_str, $port_err)
    = handle_ports($self->{_source}->{_port_num},
                   $self->{_source}->{_port_name},
                   $self->{_source}->{_port_range}->{_start},
                   $self->{_source}->{_port_range}->{_stop},
                   $can_use_port, "s", $self->{_proto});
  return (undef, $port_err) if (!defined($port_str));
  $rule_str .= $port_str;
  
  # destination port(s)
  ($port_str, $port_err)
    = handle_ports($self->{_destination}->{_port_num},
                   $self->{_destination}->{_port_name},
                   $self->{_destination}->{_port_range}->{_start},
                   $self->{_destination}->{_port_range}->{_stop},
                   $can_use_port, "d", $self->{_proto});
  return (undef, $port_err) if (!defined($port_str));
  $rule_str .= $port_str;

  if (defined($self->{_source}->{_addr})) {
    my $str = $self->{_source}->{_addr};
    $str =~ s/^\!(.*)$/! $1/;
    $rule_str .= " -s $str";
  } elsif (defined($self->{_source}->{_net})) {
    my $str = $self->{_source}->{_net};
    $str =~ s/^\!(.*)$/! $1/;
    $rule_str .= " -s $str";
  }
 
  if (defined($self->{_destination}->{_addr})) {
    my $str = $self->{_destination}->{_addr};
    $str =~ s/^\!(.*)$/! $1/;
    $rule_str .= " -d $str";
  } elsif (defined($self->{_destination}->{_net})) {
    my $str = $self->{_destination}->{_net};
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
  "snet[$self->{_source}->{_net}] spnum[@{$self->{_source}->{_port_num}}] ".
  "spname[@{$self->{_source}->{_port_name}}] " .
  "sprange[$self->{_source}->{_port_range}->{_start}" .
  "-$self->{_source}->{_port_range}->{_stop}] " .
  "daddr[$self->{_destination}->{_addr}] " .
  "dnet[$self->{_destination}->{_net}] " .
  "dpnum[@{$self->{_destination}->{_port_num}}] " .
  "dpname[@{$self->{_destination}->{_port_name}}] " .
  "dprange[$self->{_destination}->{_port_range}->{_start}-" .
  "$self->{_destination}->{_port_range}->{_stop}] " .
  "inaddr[$self->{_inside_addr}->{_addr}] " .
  "inrange[$self->{_inside_addr}->{_range}->{_start}-" .
  "$self->{_inside_addr}->{_range}->{_stop}] " .
  "inp[$self->{_inside_addr}->{_port_num}] " .
  "inprange[$self->{_inside_addr}->{_port_range}->{_start}-" .
  "$self->{_inside_addr}->{_port_range}->{_stop}] " .
  "outaddr[$self->{_outside_addr}->{_addr}] " .
  "outrange[$self->{_outside_addr}->{_range}->{_start}-" .
  "$self->{_outside_addr}->{_range}->{_stop}]";
  "outp[$self->{_outside_addr}->{_port_num}] " .
  "outprange[$self->{_outside_addr}->{_port_range}->{_start}-" .
  "$self->{_outside_addr}->{_port_range}->{_stop}] " .

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
  outputXmlElem("src_ports", join(',', @{$self->{_source}->{_port_num}}), $fh);
  outputXmlElem("src_ports_apps", join(',', @{$self->{_source}->{_port_name}}),
                $fh);
  outputXmlElem("src_port_start", $self->{_source}->{_port_range}->{_start},
                $fh);
  outputXmlElem("src_port_stop", $self->{_source}->{_port_range}->{_stop},
                $fh);
  outputXmlElem("dst_addr", $self->{_destination}->{_addr}, $fh);
  outputXmlElem("dst_network", $self->{_destination}->{_net}, $fh);
  outputXmlElem("dst_ports", join(',', @{$self->{_destination}->{_port_num}}),
                $fh);
  outputXmlElem("dst_ports_apps",
                join(',', @{$self->{_destination}->{_port_name}}), $fh);
  outputXmlElem("dst_port_start",
                $self->{_destination}->{_port_range}->{_start}, $fh);
  outputXmlElem("dst_port_stop",
                $self->{_destination}->{_port_range}->{_stop}, $fh);
  outputXmlElem("in_addr", $self->{_inside_addr}->{_addr}, $fh);
  outputXmlElem("in_addr_start", $self->{_inside_addr}->{_range}->{_start},
                $fh);
  outputXmlElem("in_addr_stop", $self->{_inside_addr}->{_range}->{_stop},
                $fh);
  outputXmlElem("in_port", $self->{_inside_addr}->{_port_num}, $fh);
  outputXmlElem("in_port_start",
                $self->{_inside_addr}->{_port_range}->{_start}, $fh);
  outputXmlElem("in_port_stop",
                $self->{_inside_addr}->{_port_range}->{_stop}, $fh);
  outputXmlElem("out_addr", $self->{_outside_addr}->{_addr}, $fh);
  outputXmlElem("out_addr_start", $self->{_outside_addr}->{_range}->{_start},
                $fh);
  outputXmlElem("out_addr_stop", $self->{_outside_addr}->{_range}->{_stop},
                $fh);
  outputXmlElem("out_port", $self->{_outside_addr}->{_port_num}, $fh);
  outputXmlElem("out_port_start",
                $self->{_outside_addr}->{_port_range}->{_start}, $fh);
  outputXmlElem("out_port_stop",
                $self->{_outside_addr}->{_port_range}->{_stop}, $fh);
  
  # no proto? ($self->{_proto})
}

