cfgdir = $(datadir)/vyatta-cfg/templates
opdir = $(datadir)/vyatta-op/templates
share_perl5dir = $(datadir)/perl5/Vyatta
bin_sudo_usersdir = $(bindir)/sudo-users
curverdir = $(sysconfdir)/config-migrate/current

sbin_SCRIPTS = scripts/vyatta-update-dst-nat.pl
sbin_SCRIPTS += scripts/vyatta-update-src-nat.pl
sbin_SCRIPTS += scripts/vyatta-show-nat-statistics.pl
sbin_SCRIPTS += scripts/vyatta-show-nat-rules.pl
sbin_SCRIPTS += scripts/vyatta-clear-nat-counters.pl

bin_sudo_users_SCRIPTS = scripts/vyatta-nat-translations.pl

share_perl5_DATA = lib/Vyatta/NatRuleCommon.pm
share_perl5_DATA += lib/Vyatta/DstNatRule.pm
share_perl5_DATA += lib/Vyatta/SrcNatRule.pm
curver_DATA = cfg-version/nat@4

cpiop = find  . ! -regex '\(.*~\|.*\.bak\|.*\.swp\|.*\#.*\#\)' -print0 | \
	cpio -0pd

install-exec-hook:
	mkdir -p $(DESTDIR)$(cfgdir)
	cd templates-cfg; $(cpiop) $(DESTDIR)$(cfgdir)
	mkdir -p $(DESTDIR)$(opdir)
	cd templates-op; $(cpiop) $(DESTDIR)$(opdir)
