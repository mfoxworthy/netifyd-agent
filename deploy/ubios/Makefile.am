# Netify Agent Deploy Automake File for EdgeOS
# Copyright (C) 2016-2022 eGloo Incorporated
#
# This is free software, licensed under the GNU General Public License v3.

TEMPLATEFILES = netifyd.conf netifyd.init
TEMPLATEFILES_IN = netifyd.conf.in netifyd.init.in

BUILT_SOURCES = $(TEMPLATEFILES)
CLEANFILES = $(TEMPLATEFILES)
EXTRA_DIST = $(TEMPLATEFILES_IN)

%: %.in
	$(SED) \
		-e 's|[@]datadir@|$(datadir)/$(PACKAGE_TARNAME)|g' \
		-e 's|[@]PACKAGE_TARNAME@|$(PACKAGE_TARNAME)|g' \
		-e 's|[@]sbindir@|$(sbindir)|g' \
		-e 's|[@]volatilestatedir@|$(volatilestatedir)|g' \
		< "$<" > "$@"
