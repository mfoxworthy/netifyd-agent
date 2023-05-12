# Netify Agent Top-Level Automake File
# Copyright (C) 2016-2022 eGloo Incorporated
#
# This is free software, licensed under the GNU General Public License v3.

DEBUG_HOST := root@gw.sokoloski.ca

AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

SUBDIRS_EXTRA =
if USE_LIBTCMALLOC_BUNDLED
SUBDIRS_EXTRA += libs/gperftools
endif

SUBDIRS = libs/inih libs/ndpi $(SUBDIRS_EXTRA) include src deploy doc tests
DIST_SUBDIRS = $(SUBDIRS)

EXTRA_DIST = LICENSE autogen.sh debian/compat \
	util/generate-json-include.sh util/generate-protocol-csv.sh \
	libs/gperftools

DISTCHECK_CONFIGURE_FLAGS = \
	--with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir) \
	--with-tmpfilesdir=$$dc_install_base/$(tmpfilesdir)

pkgconfig_DATA = lib@PACKAGE_TARNAME@.pc

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(volatilestatedir)
	$(MKDIR_P) $(DESTDIR)$(persistentstatedir)/plugins.d
	$(MKDIR_P) $(DESTDIR)$(persistentstatedir)/domains.d

uninstall-local:
	rmdir $(DESTDIR)$(volatilestatedir)
	rmdir $(DESTDIR)$(persistentstatedir)/plugins.d
	rmdir $(DESTDIR)$(persistentstatedir)/domains.d

dist-git:
	rm -f $(PACKAGE)-$(VERSION).tar*
	git archive --prefix=$(PACKAGE)-$(VERSION)/ --output=$(PACKAGE)-$(VERSION).tar HEAD
	p=`pwd`; (echo .; git submodule foreach) | while read entering path; do \
		temp="$${path%\'}"; \
		temp="$${temp#\'}"; \
		path=$$temp; \
		[ "$$path" = "" ] && continue; \
		(cd $$path && \
			git archive --prefix=$(PACKAGE)-$(VERSION)/$$path/ --output=/tmp/$(PACKAGE)-submodule.tar HEAD && \
			$(AMTAR) --concatenate --file="$$p/$(PACKAGE)-$(VERSION).tar" /tmp/$(PACKAGE)-submodule.tar && \
			rm -f /tmp/$(PACKAGE)-submodule.tar \
		); \
	done
	gzip $(PACKAGE)-$(VERSION).tar

netifyd-CentOS_8.spec: netifyd.spec
	grep -v 'gperftools-devel' netifyd.spec > netifyd-CentOS_8.spec

deploy-rpm:
	$(MAKE) dist-gzip
	cp -v $(PACKAGE)-$(VERSION).tar.gz ~/rpmbuild/SOURCES/
	rpmbuild -ba $(PACKAGE).spec

deploy-freebsd-common:
	./autogen.sh \
		./configure \
			--disable-conntrack \
			--disable-inotify
	$(MAKE) -C deploy
	rm -rf deploy/freebsd/work
	$(MAKE) dist-gzip
	sudo cp -v $(PACKAGE)-$(VERSION).tar.gz /usr/ports/distfiles/

deploy-freebsd-build:
	make -C deploy/freebsd clean
	make -C deploy/freebsd makesum
	make -C deploy/freebsd package DISABLE_VULNERABILITIES=yes
	-ls -lh deploy/freebsd/work/pkg/*.{txz,pkg}

deploy-freebsd-10x: deploy-freebsd-common
	cp deploy/freebsd/Makefile-10x deploy/freebsd/Makefile
	$(MAKE) deploy-freebsd-build

deploy-freebsd-11x: deploy-freebsd-common
	cp deploy/freebsd/Makefile-11x deploy/freebsd/Makefile
	$(MAKE) deploy-freebsd-build

deploy-freebsd-11x-debug: deploy-freebsd-common
	cp deploy/freebsd/Makefile-11x-debug deploy/freebsd/Makefile
	$(MAKE) deploy-freebsd-build

deploy-freebsd-12x: deploy-freebsd-common
	cp deploy/freebsd/Makefile-12x deploy/freebsd/Makefile
	$(MAKE) deploy-freebsd-build

deploy-freebsd: deploy-freebsd-11x
deploy-freebsd-debug: deploy-freebsd-11x-debug

deploy-pfsense:
	make -C deploy/pfsense clean
	make -C deploy/pfsense package DISABLE_VULNERABILITIES=yes
	-ls -lh deploy/freebsd/work/pkg/*.{txz,pkg}

deploy-debug: all
	rsync -av --progress --inplace src/.libs/netifyd $(DEBUG_HOST):/usr/sbin/
	rsync -avl --progress --inplace src/.libs/libnetifyd.so* $(DEBUG_HOST):/usr/lib64/

deploy-debug-archive: all
	mkdir -p /tmp/netifyd-debug/usr/{sbin,lib64}
	cp src/.libs/netifyd /tmp/netifyd-debug/usr/sbin/
	cp src/.libs/libnetifyd.so.0.0.0 /tmp/netifyd-debug/usr/lib64/
	cd /tmp/netifyd-debug && tar -cvzf ../netifyd-debug.tar.gz *
