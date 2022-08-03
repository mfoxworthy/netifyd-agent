# Netify Agent RPM Automake File
# Copyright (C) 2022 eGloo Incorporated

RPMFILES = netifyd.spec
RPMFILES_IN = netifyd.spec.in

BUILT_SOURCES = $(RPMFILES)
CLEANFILES = $(RPMFILES)
EXTRA_DIST = $(RPMFILES_IN)

%: %.in
	$(SED) \
		-e 's|[@]PACKAGE_BUGREPORT@|$(PACKAGE_BUGREPORT)|g' \
		-e 's|[@]PACKAGE_NAME@|$(PACKAGE_NAME)|g' \
		-e 's|[@]PACKAGE_TARNAME@|$(PACKAGE_TARNAME)|g' \
		-e 's|[@]PACKAGE_URL@|$(PACKAGE_URL)|g' \
		-e 's|[@]PACKAGE_VERSION@|$(PACKAGE_VERSION)|g' \
		< "$<" > "$@"
