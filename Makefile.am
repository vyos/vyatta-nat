cfgdir = $(datadir)/vyatta-cfg/templates
opdir = $(datadir)/vyatta-op/templates
xsldir = $(datadir)/xsl
share_perl5dir = $(datadir)/perl5/Vyatta
bin_sudo_usersdir = $(bindir)/sudo-users
curverdir = $(sysconfdir)/config-migrate/current

sbin_SCRIPTS = scripts/vyatta-update-nat.pl
sbin_SCRIPTS += scripts/vyatta-show-nat.pl
sbin_SCRIPTS += scripts/vyatta-show-nat-rules.pl
sbin_SCRIPTS += scripts/vyatta-clear-nat-counters.pl

bin_sudo_users_SCRIPTS  = scripts/vyatta-clear-nat
bin_sudo_users_SCRIPTS += scripts/vyatta-nat-translations.pl

share_perl5_DATA = lib/Vyatta/NatRule.pm
curver_DATA = cfg-version/nat@3

cpiop = find  . ! -regex '\(.*~\|.*\.bak\|.*\.swp\|.*\#.*\#\)' -print0 | \
	cpio -0pd

install-exec-hook:
	mkdir -p $(DESTDIR)$(cfgdir)
	cd templates-cfg; $(cpiop) $(DESTDIR)$(cfgdir)
	mkdir -p $(DESTDIR)$(opdir)
	cd templates-op; $(cpiop) $(DESTDIR)$(opdir)
	mkdir -p $(DESTDIR)$(xsldir)
	cd xsl; $(cpiop) $(DESTDIR)$(xsldir)
