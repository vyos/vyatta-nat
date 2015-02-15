#!/usr/bin/perl
#
#    vyos-update-nptv6.pl: Update SNPT/DNPT ip6tables rules
#
#    Copyright (C) 2014 VyOS Development Group <maintainers@vyos.net>
#
#    This library is free software; you can redistribute it and/or
#    modify it under the terms of the GNU Lesser General Public
#    License as published by the Free Software Foundation; either
#    version 2.1 of the License, or (at your option) any later version.
#
#    This library is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#    Lesser General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public
#    License along with this library; if not, write to the Free Software
#    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
#    USA

use strict;
use lib "/opt/vyatta/share/perl5/";
use Vyatta::Config;
use VyOS::Nptv6Rule;
use Vyatta::IpTables::Mgr;

my $CONFIG_LEVEL = "nat nptv6";
my $IPTABLES = "/sbin/ip6tables";

sub numerically_desc { $b <=> $a; }

my $config = new Vyatta::Config;

my $all_deleted = 1;

my $rule;
$config->setLevel($CONFIG_LEVEL." rule");
my %rules = $config->listNodeStatus();
for $rule (keys %rules) {
  if ($rules{$rule} ne "deleted") {
    $all_deleted = 0;
  }
}

my $debug = 0;
if ($debug) {
  open(OUT, ">>/tmp/nat") or exit 1;
} else {
  open(OUT, ">>/dev/null") or exit 1;
}

# Send rule to iptables
sub send_iptables {
  my @cmds = @_;
  my $prepend = $IPTABLES . " -t mangle ";
  my $cmd;

  for $cmd (@cmds) {
    print OUT $prepend . ' ' . $cmd . "\n";
    if(system($prepend . ' ' . $cmd)) {
      exit 1;
    }
  }
  return 0;
}

# Clean up function
sub raw_cleanup {
  my @cmds = ("-F VYOS_SNPT_HOOK", "-F VYOS_DNPT_HOOK", "-A VYOS_SNPT_HOOK -j RETURN", "-A VYOS_DNPT_HOOK -j RETURN");
  send_iptables(@cmds);
}

print OUT "========= NPTv6 list =========\n";
my @rule_keys = sort numerically_desc keys %rules;

# No rules, clean up
if ($#rule_keys < 0) {
  raw_cleanup();
  exit 0;
}

my @cmds;
# Loop through all loops, sorted numerically
for $rule (@rule_keys) {
  print OUT "$rule: $rules{$rule}\n";
  my $tmp = `ip6tables -L -nv --line -t mangle`;
  print OUT "iptables before:\n$tmp\n";

  my $nrule = new VyOS::Nptv6Rule;
  $nrule->setup($CONFIG_LEVEL." rule $rule");

  if ($rules{$rule} eq "deleted" || $nrule->is_disabled()) {
    next;
  }
 
  my ($err, $snpt_rule, $dnpt_rule) = $nrule->rule_str();
  if (defined $err) {
    # rule check failed => return error
    print OUT "NPT configuration error in rule $rule: $err\n";
    print STDERR "NPT configuration error in rule $rule: $err\n";
    exit 5;
  }
  
  push(@cmds, $snpt_rule);
  push(@cmds, $dnpt_rule);
}

raw_cleanup();
send_iptables(@cmds);

close OUT;
exit 0;

# Local Variables:
# mode: perl
# indent-tabs-mode: nil
# perl-indent-level: 2
# End:
