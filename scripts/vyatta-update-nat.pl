#!/usr/bin/perl

use strict;
use lib "/opt/vyatta/share/perl5/";
use Vyatta::Config;
use Vyatta::NatRule;

sub numerically { $a <=> $b; }

sub raw_cleanup {
  # remove the conntrack setup.
  my @lines
    = `iptables -t raw -L PREROUTING -vn --line-numbers | egrep ^[0-9]`;
  foreach (@lines) {
    my ($num, $ignore, $ignore, $chain, $ignore, $ignore, $in, $out,
        $ignore, $ignore) = split /\s+/;
    if ($chain eq "NAT_CONNTRACK") {
      system("iptables -t raw -D PREROUTING $num");
      system("iptables -t raw -D OUTPUT $num");
      system("iptables -t raw -F NAT_CONNTRACK");
      system("iptables -t raw -X NAT_CONNTRACK");
      last;
    }
  }
}

my $config = new Vyatta::Config;
$config->setLevel("service nat rule");
my %rules = $config->listNodeStatus();
my $rule;
my $debug = 0;
if ($debug) {
  open(OUT, ">>/tmp/nat") or exit 1;
} else {
  open(OUT, ">>/dev/null") or exit 1;
}
my %ipt_rulenum = (
                    source      => 2,
                    destination => 1,
                  );
my %chain_name = (
                  source      => "POSTROUTING",
                  destination => "PREROUTING",
                 );
print OUT "========= nat list =========\n";
my @rule_keys = sort numerically keys %rules;
if ($#rule_keys < 0) {
  raw_cleanup();
 
  exit 0;
}

## it seems that "multiport" does not like port range (p1:p2) if nobody has
## touched the nat table yet after reboot!?
system("iptables -t nat -L -n >& /dev/null");

# we have some nat rule(s). make sure conntrack is enabled.
system("iptables -t raw -L NAT_CONNTRACK -n >& /dev/null");
if ($? >> 8) {
  # NAT_CONNTRACK chain does not exist yet. set up conntrack.
  system("iptables -t raw -N NAT_CONNTRACK");
  # this enables conntrack for all packets. potentially we can add more rules
  # to the NAT_CONNTRACK chain for finer-grained control over which packets
  # are tracked.
  system("iptables -t raw -A NAT_CONNTRACK -j ACCEPT");
  system("iptables -t raw -I PREROUTING 1 -j NAT_CONNTRACK");
  system("iptables -t raw -I OUTPUT 1 -j NAT_CONNTRACK");
}

my $all_deleted = 1;
for $rule (@rule_keys) {
  print OUT "$rule: $rules{$rule}\n";
  my $tmp = `iptables -L -nv --line -t nat`;
  print OUT "iptables before:\n$tmp\n";
  my $nrule = new Vyatta::NatRule;
  $nrule->setup("service nat rule $rule");
  my $otype = $nrule->orig_type();
  my $ntype = $nrule->new_type();
  if ((defined($otype) && $otype ne "source" && $otype ne "destination")
      || (defined($ntype) && $ntype ne "source" && $ntype ne "destination")) {
    exit 2;
  }

  if ($rules{$rule} ne "deleted") {
    $all_deleted = 0;
  }
 
  my $cmd;
  if ($rules{$rule} eq "static") {
    # $otype and $ntype should be the same
    if (!defined($ntype)) {
      exit 3;
    }
    my $ipt_rules = $nrule->get_num_ipt_rules();
    $ipt_rulenum{$ntype} += $ipt_rules;
    next;
  } elsif ($rules{$rule} eq "deleted") {
    # $ntype should be empty
    if (!defined($otype)) {
      exit 4;
    }
    my $orule = new Vyatta::NatRule;
    $orule->setupOrig("service nat rule $rule");
    my $ipt_rules = $orule->get_num_ipt_rules();
    for (1 .. $ipt_rules) {
      $cmd = "iptables -t nat -D $chain_name{$otype} $ipt_rulenum{$otype}";
      print OUT "$cmd\n";
      if (system($cmd)) {
        exit 1;
      }
    }
    next;
  }
  
  my ($err, @rule_strs) = $nrule->rule_str();
  if (defined $err) {
    # rule check failed => return error
    print OUT "NAT configuration error: $err\n";
    print STDERR "NAT configuration error: $err\n";
    exit 5;
  }
  
  if ($rules{$rule} eq "added") {
    # $otype should be empty
    if (!defined($ntype)) {
      exit 6;
    }
    foreach my $rule_str (@rule_strs) {
      next if !defined $rule_str;
      $cmd = "iptables -t nat -I $chain_name{$ntype} $ipt_rulenum{$ntype} " .
          "$rule_str";
      print OUT "$cmd\n";
      if (system($cmd)) {
        exit 1;
      }
      $ipt_rulenum{$ntype}++;
    }

  } elsif ($rules{$rule} eq "changed") {
    # $otype and $ntype may not be the same
    if (!defined($otype) || !defined($ntype)) {
      exit 7;
    }

    # delete the old rule(s)
    my $orule = new Vyatta::NatRule;
    $orule->setupOrig("service nat rule $rule");
    my $ipt_rules = $orule->get_num_ipt_rules();
    my $idx = $ipt_rulenum{$otype};
    for (1 .. $ipt_rules) {
      $cmd = "iptables -t nat -D $chain_name{$otype} $idx";
      print OUT "$cmd\n";
      if (system($cmd)) {
        exit 1;
      }
    }

    # add the new rule(s)
    foreach my $rule_str (@rule_strs) {
      next if !defined $rule_str;
      $cmd = "iptables -t nat -I $chain_name{$ntype} $ipt_rulenum{$ntype} " .
          "$rule_str";
      print OUT "$cmd\n";
      if (system($cmd)) {
        exit 1;
      }
      $ipt_rulenum{$ntype}++;
    }

  }
}

if ($all_deleted) {
  raw_cleanup();
}

close OUT;
exit 0;

# Local Variables:
# mode: perl
# indent-tabs-mode: nil
# perl-indent-level: 2
# End:
