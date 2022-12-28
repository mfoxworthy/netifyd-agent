#!/bin/bash

export CFLAGS="-fexceptions -g -grecord-gcc-switches -m64 -mtune=generic -pipe -Wall -Werror=format-security -Wp,-D_GLIBCXX_ASSERTIONS"
export CXXFLAGS=${CFLAGS}

./configure --program-prefix= --prefix=/usr --exec-prefix=/usr --bindir=/usr/bin --sbindir=/usr/sbin --sysconfdir=/etc --datadir=/usr/share --includedir=/usr/include --libdir=/usr/lib --libexecdir=/usr/libexec --localstatedir=/var --sharedstatedir=/var/lib --mandir=/usr/share/man --infodir=/usr/share/info --enable-conntrack --enable-inotify --enable-netlink --enable-plugins --disable-libtcmalloc --disable-jemalloc
