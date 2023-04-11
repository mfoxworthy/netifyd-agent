# Netify Agent "systemd" Automake File
# Copyright (C) 2016-2022 eGloo Incorporated
#
# This is free software, licensed under the GNU General Public License v3.

SYSTEMDFILES = env.sh exec-pre.sh netifyd.conf netifyd.service
SYSTEMDFILES_IN = env.sh.in exec-pre.sh.in netifyd.conf.in netifyd.service.in

sharedatadir = $(datadir)/netifyd

if HAVE_SYSTEMD
systemdsystemunit_DATA = netifyd.service
tmpfiles_DATA = netifyd.conf
sharedata_DATA = env.sh exec-pre.sh
endif

BUILT_SOURCES = $(SYSTEMDFILES)
CLEANFILES = $(SYSTEMDFILES)
EXTRA_DIST = $(SYSTEMDFILES_IN)

%: %.in
	$(SED) \
		-e 's|[@]datadir@|$(datadir)|g' \
		-e 's|[@]libdir@|$(libdir)|g' \
		-e 's|[@]PACKAGE_NAME@|$(PACKAGE_NAME)|g' \
		-e 's|[@]PACKAGE_TARNAME@|$(PACKAGE_TARNAME)|g' \
		-e 's|[@]sbindir@|$(sbindir)|g' \
		-e 's|[@]volatilestatedir@|$(volatilestatedir)|g' \
		< "$<" > "$@"

install-data-hook:
	-chmod a+x $(DESTDIR)$(sharedatadir)/*.sh
