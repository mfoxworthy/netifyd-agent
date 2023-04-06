#!/bin/bash

: ${OPTION_CONNTRACK:=enable}
: ${OPTION_NETLINK:=enable}
: ${OPTION_PLUGINS:=enable}
: ${OPTION_LIBTCMALLOC:=enable}
: ${OPTION_NFQUEUE:=enable}
: ${OPTION_INSTANCE_SUPPORT:=disable}

echo "Options:"
echo " - CONNTRACK: ${OPTION_CONNTRACK}"
echo " - NETLINK: ${OPTION_NETLINK}"
echo " - PLUGINS: ${OPTION_PLUGINS}"
echo " - LIBTCMALLOC: ${OPTION_LIBTCMALLOC}"
echo " - NFQUEUE: ${OPTION_NFQUEUE}"
echo " - INSTANCE_SUPPORT: ${OPTION_INSTANCE_SUPPORT}"

export CFLAGS="-fasynchronous-unwind-tables -fexceptions -fstack-clash-protection -fstack-protector-strong -g -grecord-gcc-switches -m64 -mtune=generic -O2 -pipe -specs=/usr/lib/rpm/redhat/redhat-hardened-cc1 -Wall -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -Wp,-D_GLIBCXX_ASSERTIONS"
export CXXFLAGS=${CFLAGS}

export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig

./configure \
    --build=x86_64-redhat-linux-gnu \
    --host=x86_64-redhat-linux-gnu \
    --program-prefix= \
    --prefix=/usr \
    --exec-prefix=/usr \
    --bindir=/usr/bin \
    --sbindir=/usr/sbin \
    --sysconfdir=/etc \
    --datadir=/usr/share \
    --includedir=/usr/include \
    --libdir=/usr/lib \
    --libexecdir=/usr/libexec \
    --localstatedir=/var \
    --sharedstatedir=/var/lib \
    --mandir=/usr/share/man \
    --infodir=/usr/share/info \
    --${OPTION_CONNTRACK}-conntrack \
    --${OPTION_NETLINK}-netlink \
    --${OPTION_PLUGINS}-plugins \
    --${OPTION_LIBTCMALLOC}-libtcmalloc \
    --${OPTION_NFQUEUE}-nfqueue \
    --${OPTION_INSTANCE_SUPPORT}-instance-support \
    build_alias=x86_64-redhat-linux-gnu host_alias=x86_64-redhat-linux-gnu
