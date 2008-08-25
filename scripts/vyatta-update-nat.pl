#!/usr/bin/perl

use strict;
use lib "/opt/vyatta/share/perl5/";
use VyattaConfig;
use VyattaNatRule;

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
  
  system('iptables -t nat -A VYATTA_PRE_SNAT_HOOK -j RETURN');
  system('iptables -t nat -A POSTROUTING -j VYATTA_PRE_SNAT_HOOK');
}

my $config = new VyattaConfig;
$config->setLevel("service nat rule");
my %rules = $config->listNodeStatus();
my $rule;
open(OUT, ">>/dev/null") or exit 1;
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
  # no rules (everything is deleted) => flush the nat table & return
  print OUT "iptables -t nat -F\n";
  if (system("iptables -t nat -F")) {
    exit 1;
  }
  
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
  my $nrule = new VyattaNatRule;
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
    $ipt_rulenum{$ntype} += 1;
    next;
  } elsif ($rules{$rule} eq "deleted") {
    # $ntype should be empty
    if (!defined($otype)) {
      exit 4;
    }
    $cmd = "iptables -t nat -D $chain_name{$otype} $ipt_rulenum{$otype}";
    print OUT "$cmd\n";
    if (system($cmd)) {
      exit 1;
    }
    next;
  }
  
  my ($str, $err) = $nrule->rule_str();
  if (!defined($str)) {
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
    $cmd = "iptables -t nat -I $chain_name{$ntype} $ipt_rulenum{$ntype} " .
           "$str";
    print OUT "$cmd\n";
    if (system($cmd)) {
      exit 1;
    }
    $ipt_rulenum{$ntype} += 1;
  } elsif ($rules{$rule} eq "changed") {
    # $otype and $ntype may not be the same
    if (!defined($otype) || !defined($ntype)) {
      exit 7;
    }
    $cmd = "iptables -t nat -I $chain_name{$ntype} $ipt_rulenum{$ntype} " .
           "$str";
    print OUT "$cmd\n";
    if (system($cmd)) {
      exit 1;
    }
    my $idx = $ipt_rulenum{$otype};
    if ($otype eq $ntype) {
      $idx += 1;
    }
    $cmd = "iptables -t nat -D $chain_name{$otype} $idx";
    print OUT "$cmd\n";
    if (system($cmd)) {
      exit 1;
    }
    $ipt_rulenum{$ntype} += 1;
  }
}

if ($all_deleted) {
  system('iptables -t nat -F');
  raw_cleanup();
}

close OUT;
exit 0;

