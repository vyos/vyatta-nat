#!/usr/bin/perl
#
# Module: vyatta-update-bidirectional-nat.pl
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
# Author: davidegianino@fico.com
# Date: 2016
# Description: Script to update iptables bidirectional NAT rules
#
# **** End License ****
#

{
package configHelper;
use Data::Dumper;

sub _canonicalPath {
  my ($self, $ppath) = @_;
  my $path = join(" ", map { length($_) ? $_ : () } $self->{_level}, $ppath);
  $path =~ s/ ?\.\.$//;
  my @pth = split(/ /, $path);
  my @ret;
  for my $node (@pth) { $node eq ".." ? pop(@ret) : push(@ret, $node); }
  return join(" ", @ret);
}

sub setLevel {
  my ($self, $level) = @_;
  $self->{_level} = $level;
}

sub returnParent {
  my ($self, $ppath) = @_;
  my $path = $self->_canonicalPath($ppath);
  my @nodes = split(/ /, $path);
  my $parent = pop(@nodes);
  return $parent;
}

sub returnValue {
  my ($self, $ppath) = @_;
  my $path = $self->_canonicalPath($ppath);
  my $ret = $self->{$path};
  return $ret;
}

sub exists {
  my ($self, $ppath) = @_;
  my $path = $self->_canonicalPath($ppath);
  return 1 if(exists($self->{$path}) && $self->{$path});
  return undef;
}
}

use strict;
use lib "/opt/vyatta/share/perl5/";
use Vyatta::Config;
use Vyatta::NatRuleCommon;
use Vyatta::SrcNatRule;
use Vyatta::DstNatRule;
use Vyatta::IpTables::Mgr;
use Data::Dumper;

my $debug = 1;
my $IPTABLES = "/sbin/iptables";
my $config = new Vyatta::Config;
my $ipt_rulenum_snat = 2;
my $ipt_rulenum_dnat = 2;

sub raw_cleanup {
  # remove the conntrack setup.
  ipt_disable_conntrack('iptables', 'NAT_CONNTRACK');
}

sub is_level_deleted {
  my ($level) = @_;
  $config->setLevel($level);
  my %rules = $config->listNodeStatus();
  for my $rule (keys %rules) {
    return 0 if ($rules{$rule} ne "deleted");
  }
  return 1;
}

sub instantiate_config_helper {
  my ($rule, $ruleStatus, $ruleClass, $proto, $port) = @_;
  my $returnValueFunc_xlate = {added=>"returnValue", deleted=>"returnOrigValue"};
  my $existsFunc_xlate = {added=>"exists", deleted=>"existsOrig"};
  my $level_xlate = {
    "Vyatta::SrcNatRule"=>"nat source rule $rule",
    "Vyatta::DstNatRule"=>"nat destination rule $rule"};
  my $returnValueFunc = $returnValueFunc_xlate->{$ruleStatus};
  my $existsFunc = $existsFunc_xlate->{$ruleStatus};
  my $level = $level_xlate->{$ruleClass};
  my $cfg = {
    "_is_bidirectional" => 1,
    "_ruleClass" => $ruleClass,
    "_ruleNumber" => $rule,
    "$level log" => $config->$returnValueFunc("log"),
  };

  $cfg->{"$level exclude"} = 1 if($config->$existsFunc("exclude"));
  $cfg->{"$level disable"} = 1 if($config->$existsFunc("disable"));
  $cfg->{"$level protocol"} = $proto if(defined($proto));
  $cfg->{"$level translation port"} = $port if(defined($port));

  if($ruleClass eq "Vyatta::SrcNatRule") {
    $cfg->{"$level outbound-interface"} = $config->$returnValueFunc("interface");
    $cfg->{"$level source address"} = $config->$returnValueFunc("outbound-address");
    $cfg->{"$level source port"} = $port if(defined($port));
    $cfg->{"$level translation address"} = $config->$returnValueFunc("inbound-address");
  } elsif($ruleClass eq "Vyatta::DstNatRule") {
    $cfg->{"$level inbound-interface"} = $config->$returnValueFunc("interface");
    $cfg->{"$level destination address"} = $config->$returnValueFunc("inbound-address");
    $cfg->{"$level destination port"} = $port if(defined($port));
    $cfg->{"$level translation address"} = $config->$returnValueFunc("outbound-address");
  }

  bless $cfg, "configHelper";
  return $cfg;
}

sub generate_config {
  my ($rule, $ruleStatus, $ruleClass) = @_;
  my $listNodesFunc_xlate = {added=>"listNodes", deleted=>"listOrigNodes"};
  my $returnValueFunc_xlate = {added=>"returnValue", deleted=>"returnOrigValue"};
  my $listNodesFunc = $listNodesFunc_xlate->{$ruleStatus};
  my $returnValueFunc = $returnValueFunc_xlate->{$ruleStatus};

  $config->setLevel("nat bidirectional rule $rule");
  my @protos = $config->$listNodesFunc("protocol");
  my @cfg;

  if(@protos) {
    for my $proto (@protos) {
      my $ports = $config->$returnValueFunc("protocol $proto port");
      if(length($ports)) {
        for my $port (split(/,/, $ports)) {
          push @cfg, instantiate_config_helper($rule, $ruleStatus, $ruleClass, $proto, $port);
        }
      } else {
        push @cfg, instantiate_config_helper($rule, $ruleStatus, $ruleClass, $proto);
      }
    }
  } else {
    push @cfg, instantiate_config_helper($rule, $ruleStatus, $ruleClass);
  }

  return @cfg;
}

sub delete_rule {
  my ($cfg) = @_;
  my $rule_type_xlate = {"Vyatta::SrcNatRule"=>"source", "Vyatta::DstNatRule"=>"destination"};
  my $chain_name_xlate = {"Vyatta::SrcNatRule"=>"POSTROUTING", "Vyatta::DstNatRule"=>"PREROUTING"};
  my $ipt_rulenum_xlate = {"Vyatta::SrcNatRule"=>\$ipt_rulenum_snat, "Vyatta::DstNatRule"=>\$ipt_rulenum_dnat};
  my $orule = "$cfg->{_ruleClass}"->new;
  $orule->setup("nat $rule_type_xlate->{$cfg->{_ruleClass}} rule $cfg->{_ruleNumber}", $cfg);
  my $ipt_rules = $orule->get_num_ipt_rules();
  my $chain_name = $chain_name_xlate->{$cfg->{_ruleClass}};
  my $ipt_rulenum = ${$ipt_rulenum_xlate->{$cfg->{_ruleClass}}};
  my $idx = $ipt_rulenum;

  for (1 .. $ipt_rules) {
    my $cmd = "$IPTABLES -t nat -D $chain_name $idx";
    print OUT "$cmd\n";
    exit(1) if(system($cmd));
  }
}

sub add_rule {
  my ($cfg) = @_;
  my $nrule = "$cfg->{_ruleClass}"->new;
  my $rule_type_xlate = {"Vyatta::SrcNatRule"=>"source", "Vyatta::DstNatRule"=>"destination"};
  $nrule->setup("nat $rule_type_xlate->{$cfg->{_ruleClass}} rule $cfg->{_ruleNumber}", $cfg);

  my ($err, @rule_strs) = $nrule->rule_str();

  if (defined $err) {
    # rule check failed => return error
    print OUT "Bidirectional NAT configuration error in rule $cfg->{_ruleNumber}: $err\n";
    print STDERR "Bidirectional NAT configuration error in rule $cfg->{_ruleNumber}: $err\n";
    exit 5;
  }

  my $chain_name_xlate = {"Vyatta::SrcNatRule"=>"POSTROUTING", "Vyatta::DstNatRule"=>"PREROUTING"};
  my $ipt_rulenum_xlate = {"Vyatta::SrcNatRule"=>\$ipt_rulenum_snat, "Vyatta::DstNatRule"=>\$ipt_rulenum_dnat};
  my $chain_name = $chain_name_xlate->{$cfg->{_ruleClass}};
  my $ipt_rulenum_ref = $ipt_rulenum_xlate->{$cfg->{_ruleClass}};

  foreach my $rule_str (@rule_strs) {
    next if !defined $rule_str;
    my $cmd = "$IPTABLES -t nat -I $chain_name ${$ipt_rulenum_xlate->{$cfg->{_ruleClass}}} $rule_str";
    print OUT "$cmd\n";
    exit(1) if(system($cmd));
    $$ipt_rulenum_ref++;
  }
}

sub skip_iptrules {
  my ($ruleClass, $ruleNumber, $cfg) = @_;
  my $nrule = "$ruleClass"->new;
  my $rule_type_xlate = {"Vyatta::SrcNatRule"=>"source", "Vyatta::DstNatRule"=>"destination"};
  my $ipt_rulenum_xlate = {"Vyatta::SrcNatRule"=>\$ipt_rulenum_snat, "Vyatta::DstNatRule"=>\$ipt_rulenum_dnat};
  my $ipt_rulenum_ref = $ipt_rulenum_xlate->{$ruleClass};
  $nrule->setup("nat $rule_type_xlate->{$ruleClass} rule $ruleNumber", $cfg);
  $$ipt_rulenum_ref += $nrule->get_num_ipt_rules();
}

open(OUT, $debug ? ">>/tmp/nat" : ">>/dev/null") or exit 1;

if(is_level_deleted("nat destination rule")
&& is_level_deleted("nat source rule")
&& is_level_deleted("nat bidirectional rule")) {
  raw_cleanup();
  exit 0;
}

## it seems that "multiport" does not like port range (p1:p2) if nobody has
## touched the nat table yet after reboot!?
system("$IPTABLES -t nat -L -n >& /dev/null");

# we have some nat rule(s). make sure conntrack is enabled.
ipt_enable_conntrack('iptables', 'NAT_CONNTRACK');

# skip existing SNAT and DNAT iptables rules
$config->setLevel("nat");
for my $rule ($config->listNodes("source rule")) {
  skip_iptrules("Vyatta::SrcNatRule", $rule, $config);
}
for my $rule ($config->listNodes("destination rule")) {
  skip_iptrules("Vyatta::DstNatRule", $rule, $config);
}

$config->setLevel("nat bidirectional rule");
my %rules = $config->listNodeStatus();
sub numerically { $a <=> $b; }
my @rule_keys = sort numerically keys %rules;
my $error = 0;

for my $rule (@rule_keys) {
  my $ruleStatus = $rules{$rule};

  print OUT "$rule: $rules{$rule}\n";
  my $tmp = `iptables -L -nv --line -t nat`;
  print OUT "iptables before:\n$tmp\n";

  if($ruleStatus eq "static") {
    foreach my $cfg (
    generate_config($rule, "added", "Vyatta::SrcNatRule"),
    generate_config($rule, "added", "Vyatta::DstNatRule")) {
      skip_iptrules($cfg->{_ruleClass}, $cfg->{_ruleNumber}, $cfg);
    }
  }

  if ($ruleStatus eq "deleted" || $ruleStatus eq "changed") {
    foreach my $cfg (
    generate_config($rule, "deleted", "Vyatta::SrcNatRule"),
    generate_config($rule, "deleted", "Vyatta::DstNatRule")) {
      delete_rule($cfg);
    }
  }

  if ($ruleStatus eq "added" || $ruleStatus eq "changed") {
    $config->setLevel("nat bidirectional rule $rule");
    my @required = qw(inbound-address interface outbound-address);
    my @missing = grep { !$config->exists("$_") } @required;

    if(@missing) {
      print STDERR "Bidirectional NAT configuration error in rule $rule: "
        .join(", ", @missing)." not specified\n";
      $error = 1;
    } else {
      foreach my $cfg (
      generate_config($rule, "added", "Vyatta::SrcNatRule"),
      generate_config($rule, "added", "Vyatta::DstNatRule")) {
        add_rule($cfg);
      }
    }
  }
}

close OUT;
exit $error;

# Local Variables:
# mode: perl
# indent-tabs-mode: nil
# perl-indent-level: 2
# End:
