cfgdir = $(datadir)/vyatta-cfg/templates
opdir = $(datadir)/vyatta-op/templates
xsldir = $(datadir)/xsl
share_perl5dir = $(datadir)/perl5
bin_sudo_usersdir = $(bindir)/sudo-users

sbin_SCRIPTS = scripts/vyatta-update-nat.pl
bin_sudo_users_SCRIPTS = scripts/vyatta-show-nat.pl

share_perl5_DATA = scripts/VyattaNatRule.pm

cpiop = find  . ! -regex '\(.*~\|.*\.bak\|.*\.swp\|.*\#.*\#\)' -print0 | \
	cpio -0pd

install-exec-hook:
	mkdir -p $(DESTDIR)$(cfgdir)
	cd templates-cfg; $(cpiop) $(DESTDIR)$(cfgdir)
	mkdir -p $(DESTDIR)$(opdir)
	cd templates-op; $(cpiop) $(DESTDIR)$(opdir)
	mkdir -p $(DESTDIR)$(xsldir)
	cd xsl; $(cpiop) $(DESTDIR)$(xsldir)
