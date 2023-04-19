# Netify Agent Source Automake File
# Copyright (C) 2016-2022 eGloo Incorporated
#
# This is free software, licensed under the GNU General Public License v3.

AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

AM_YFLAGS = -d
BUILT_SOURCES = nd-flow-criteria.tab.hh

AM_CPPFLAGS = $(CPPFLAGS) -D_GNU_SOURCE \
	-I $(top_srcdir)/include \
	-I $(top_srcdir)/libs/ndpi/src/include -I $(top_srcdir)/libs/inih/cpp \
	$(LIBCURL_CFLAGS) $(ZLIB_CFLAGS) \
	-D_ND_INTERNAL=1 \
	-D'ND_CONF_FILE_NAME="$(sysconfdir)/$(PACKAGE_TARNAME).conf"' \
	-D'ND_DATADIR="$(datadir)/$(PACKAGE_TARNAME)"' \
	-D'ND_PERSISTENT_STATEDIR="$(persistentstatedir)"' \
	-D'ND_PID_FILE_NAME="$(volatilestatedir)/$(PACKAGE_TARNAME).pid"' \
	-D'ND_VOLATILE_STATEDIR="$(volatilestatedir)"'

if USE_LIBTCMALLOC
AM_CPPFLAGS += $(LIBTCMALLOC_CFLAGS)
endif

if USE_CONNTRACK
AM_CPPFLAGS += $(LIBNETFILTER_CONNTRACK_CFLAGS) $(LIBMNL_CFLAGS)
endif

if USE_NFQUEUE
AM_CPPFLAGS += $(LIBNETFILTER_QUEUE_CFLAGS)
endif

lib_LTLIBRARIES = libnetifyd.la
libnetifyd_la_SOURCES = nd-addr.cpp nd-apps.cpp nd-base64.cpp nd-capture.cpp \
	nd-category.cpp nd-config.cpp nd-detection.cpp nd-dhc.cpp nd-fhc.cpp \
	nd-flow.cpp nd-flow-criteria.l nd-flow-criteria.tab.yy nd-flow-map.cpp \
	nd-instance.cpp nd-json.cpp nd-napi.cpp nd-ndpi.cpp nd-protos.cpp \
	nd-risks.cpp nd-sha1.c nd-socket.cpp nd-thread.cpp nd-util.cpp

# https://www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html
libnetifyd_la_LDFLAGS = -version-info 2:1:0
libnetifyd_la_LIBADD = $(top_srcdir)/libs/ndpi/src/lib/libndpi.a $(LIBCURL_LIBS) $(ZLIB_LIBS)

if USE_NETLINK
libnetifyd_la_SOURCES += nd-netlink.cpp
endif

if USE_PLUGINS
libnetifyd_la_SOURCES += nd-plugin.cpp
endif

if USE_CONNTRACK
libnetifyd_la_SOURCES += nd-conntrack.cpp
libnetifyd_la_LIBADD += $(LIBNETFILTER_CONNTRACK_LIBS) $(LIBMNL_LIBS)
endif

if USE_LIBPCAP
libnetifyd_la_SOURCES += nd-capture-pcap.cpp
endif

if USE_TPACKETV3
libnetifyd_la_SOURCES += nd-capture-tpv3.cpp
endif

if USE_NFQUEUE
libnetifyd_la_SOURCES += nd-capture-nfq.cpp
libnetifyd_la_LIBADD += $(LIBNETFILTER_QUEUE_LIBS)
endif

sbin_PROGRAMS = netifyd
netifyd_SOURCES = netifyd.cpp
netifyd_LDADD = ./libnetifyd.la $(top_srcdir)/libs/inih/libini.la $(LIBCURL_LIBS) $(ZLIB_LIBS)

if USE_LIBTCMALLOC
# XXX: Recommended compiler flags
AM_CPPFLAGS += $(LIBTCMALLOC_CFLAGS) -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free
# XXX: It's important that this library be linked after all others.
netifyd_LDADD += $(LIBTCMALLOC_LIBS)
endif

# For debugging ns_initparse
#netifyd_SOURCES += ns-parse.c
