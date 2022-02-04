# Netify Agent Include Automake File
# Copyright (C) 2016-2021 eGloo, Incorporated
#
# This is free software, licensed under the GNU General Public License v3.

AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = nd-json-response-code.txt.in nlohmann pcap-compat radix

netifyincludedir = $(includedir)/netifyd
netifyinclude_HEADERS = nd-base64.h nd-category.h nd-conntrack.h \
	nd-capture.h nd-detection.h nd-dhc.h nd-fhc.h nd-flow.h nd-flow-map.h \
	nd-inotify.h nd-json.h nd-json-response-code.h nd-napi.h nd-ndpi.h \
	nd-netlink.h nd-plugin.h nd-sha1.h nd-sink.h nd-signal.h nd-socket.h \
	nd-tls-alpn.h nd-thread.h nd-util.h netifyd.h

pcapcompatincludedir = $(includedir)/netifyd/pcap-compat
pcapcompatinclude_HEADERS = pcap-compat/sll.h pcap-compat/vlan.h

nlohmannincludedir = $(includedir)/netifyd/nlohmann
nlohmanninclude_HEADERS = nlohmann/json.hpp

radixincludedir = $(includedir)/netifyd/radix
radixinclude_HEADERS = radix/radix_tree.hpp radix/radix_tree_it.hpp \
	radix/radix_tree_node.hpp

BUILT_SOURCES = nd-json-response-code.h
CLEANFILES = nd-json-response-code.h

nd-json-response-code.h: nd-json-response-code.txt.in
	../util/generate-json-include.sh c-response-code >$@
