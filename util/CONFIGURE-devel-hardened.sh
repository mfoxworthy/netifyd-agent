#!/bin/bash

export CFLAGS="-fasynchronous-unwind-tables -fexceptions -fstack-clash-protection -fstack-protector-strong -g -grecord-gcc-switches -m64 -mtune=generic -O2 -pipe -specs=/usr/lib/rpm/redhat/redhat-hardened-cc1 -Wall -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -Wp,-D_GLIBCXX_ASSERTIONS"
export CXXFLAGS=${CFLAGS}

./configure --build=x86_64-redhat-linux-gnu --host=x86_64-redhat-linux-gnu --program-prefix= --prefix=/usr --exec-prefix=/usr --bindir=/usr/bin --sbindir=/usr/sbin --sysconfdir=/etc --datadir=/usr/share --includedir=/usr/include --libdir=/usr/lib --libexecdir=/usr/libexec --localstatedir=/var --sharedstatedir=/var/lib --mandir=/usr/share/man --infodir=/usr/share/info --enable-conntrack --enable-inotify --enable-netlink --enable-plugins --enable-libtcmalloc --disable-jemalloc build_alias=x86_64-redhat-linux-gnu host_alias=x86_64-redhat-linux-gnu
