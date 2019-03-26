#
#    VyOS::Nptv6Rule: Update SNPT/DNPT ip6tables rules
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


package VyOS::Nptv6Rule;

use strict;
use lib "/opt/vyatta/share/perl5";
require Vyatta::Config;
require Vyatta::IpTables::AddressFilter;
use Vyatta::Misc;
use Vyatta::TypeChecker;

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(is_disabled rule_str);

my %fields = (
  _rule_number  => undef,
  _outside_if   => undef,
  _inside_pfx   => undef,
  _outside_pfx  => undef,
  _disable      => undef,
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
  $self->{_outside_if} = $config->returnValue("outbound-interface");
  $self->{_inside_pfx} = $config->returnValue("source prefix");
  $self->{_outside_pfx} = $config->returnValue("translation prefix");

  $self->{_disable} = $config->exists("disable");

  return 0;
}

# Make SNPT ip6tables string
# POSTROUTING
# ip6tables -t nat -I VYOS_SNPT_HOOK -s inside-pfx -o outside-if -j NETMAP --to outside-pfx
sub make_snpt_string {
  my ($self) = @_;
  my $snpt_str = "";

  # Construct ip6tables string
  $snpt_str .= "-I VYOS_SNPT_HOOK ";
  $snpt_str .= "-s ";
  $snpt_str .= $self->{_inside_pfx};
  if(defined($self->{_outside_if})) {
    $snpt_str .= " -o ";
    $snpt_str .= $self->{_outside_if};
  }
  $snpt_str .= " -j NETMAP ";
  $snpt_str .= " --to ";
  $snpt_str .= $self->{_outside_pfx};

  return $snpt_str; 
}

# Make DNPT ip6tables string
# PREROUTING
# ip6tables -t nat -I VYOS_DNPT_HOOK -d outside-pfx -i outside-if -j NETMAP --to inside-pfx
sub make_dnpt_string {
  my ($self) = @_;
  my $dnpt_str = "";

  # Construct ip6tables string
  $dnpt_str .= "-I VYOS_DNPT_HOOK ";
  $dnpt_str .= "-d ";
  $dnpt_str .= $self->{_outside_pfx};
  if(defined($self->{_outside_if})) {
    $dnpt_str .= " -i ";
    $dnpt_str .= $self->{_outside_if};
  }
  $dnpt_str .= " -j NETMAP ";
  $dnpt_str .= " --to ";
  $dnpt_str .= $self->{_inside_pfx};

  return $dnpt_str;
}

# Tests if the rule is valid, returns false if valid, returns error string if invalid
sub is_invalid {
  my ($self) = @_;

  # Validate prefixes
  if(!defined($self->{_inside_pfx}) || $self->{_inside_pfx} eq '') {
    return "inside-prefix must be set";
  }

  if(!defined($self->{_outside_pfx}) || $self->{_outside_pfx} eq '') {
    return "outside-prefix must be set";
  }

  if(!Vyatta::TypeChecker::validateType('ipv6net', $self->{_inside_pfx}, 1)) {
    return "inside-prefix is not a valid prefix";
  }

  if(!Vyatta::TypeChecker::validateType('ipv6net', $self->{_outside_pfx}, 1)) {
    return "outside-prefix is not a valid prefix";
  }
  
  return 0;
}

# Returns an array of ip6tables parameters (SNPT, DNPT)
sub rule_str {
  my ($self) = @_;
  my $err;

  $err = $self->is_invalid();
  if($err ne 0) {
    return ($err, undef, undef);
  }

  return (undef, $self->make_snpt_string(), $self->make_dnpt_string());
}

sub is_disabled {
  my $self = shift;
  return 1 if defined $self->{_disable};
  return 0;
}

1;

