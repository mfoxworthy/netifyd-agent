# Netify Agent
# GNU Autoconf configuration

m4_include([m4/ax_pkg_installdir.m4])
m4_include([m4/ax_cxx_compile_stdcxx_0x.m4])
m4_include([m4/ax_cxx_compile_stdcxx_11.m4])

AC_PREREQ([2.68])
AC_INIT([Netify Agent], [4.1.18],
    [https://gitlab.com/netify.ai/public/netify-agent/issues],
    [netifyd], [https://www.netify.ai/])
AM_INIT_AUTOMAKE([1.9 tar-pax])
AC_CONFIG_SRCDIR([src/netifyd.cpp])
AC_CONFIG_SUBDIRS([libs/inih libs/ndpi])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_USE_SYSTEM_EXTENSIONS
AC_CANONICAL_HOST
AC_DEFINE_UNQUOTED([_ND_HOST_CPU], ["${host_cpu}"], [Defines the canonical host.])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AM_PROG_LEX
AC_PROG_YACC
AC_DECL_YYTEXT
AC_CHECK_TOOL([STRIP],[strip])
AM_PROG_LIBTOOL
PKG_PROG_PKG_CONFIG([0.23])
AX_PKG_INSTALLDIR
AC_PATH_PROG([bash], [bash], [false])
AC_PATH_PROG([osc], [osc])
AM_CONDITIONAL([HAVE_OSC], [test x$osc != x])

# Defines we will pass to pkg-config:
ND_DEFINES=""

AS_IF([test "x$ac_cv_path_bash" != "xfalse"], [
    AC_SUBST([ND_PATH_BASH], [$ac_cv_path_bash])
], [
    AC_MSG_ERROR([bash not found.])
])

# Check compiler flags (gnu++11)
AX_CXX_COMPILE_STDCXX_11([ext], [optional])
AS_IF([test "$HAVE_CXX11" = "0"], [AX_CXX_COMPILE_STDCXX_0X])

# Checks for libraries.
AC_CHECK_LIB([pcap],
    [pcap_open_live], [], [AC_MSG_ERROR([libpcap/pcap_open_live() not found.])])
AC_CHECK_LIB([pthread],
    [pthread_create], [], [AC_MSG_ERROR([libpthread/pthread_create() not found.])])
AC_CHECK_LIB([rt],
    [timer_create], [], [AC_MSG_ERROR([librt/timer_create() not found.])])

case "${host_os}" in
    linux*)
        AC_CHECK_LIB([resolv],
            [ns_initparse], [], [AC_MSG_ERROR([libresolv/ns_initparse() not found.])])
        ;;
esac

PKG_CHECK_MODULES([LIBCURL], [libcurl])
PKG_CHECK_MODULES([ZLIB], [zlib])

# Parameters: --with/without
AC_ARG_WITH([systemdsystemunitdir],
     [AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files])],,
     [with_systemdsystemunitdir=auto])
AS_IF([test "x$with_systemdsystemunitdir" = "xyes" -o "x$with_systemdsystemunitdir" = "xauto"], [
     def_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)

     AS_IF([test "x$def_systemdsystemunitdir" = "x"],
   [AS_IF([test "x$with_systemdsystemunitdir" = "xyes"],
    [AC_MSG_ERROR([systemd support requested but pkg-config unable to query systemd package])])
    with_systemdsystemunitdir=no],
   [with_systemdsystemunitdir="$def_systemdsystemunitdir"])])
AS_IF([test "x$with_systemdsystemunitdir" != "xno"],
      [AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])])
AM_CONDITIONAL([HAVE_SYSTEMD], [test "x$with_systemdsystemunitdir" != "xno"])

AC_ARG_WITH([tmpfilesdir],
     [AS_HELP_STRING([--with-tmpfilesdir=DIR], [Directory for systemd tmpfiles configuration])],,
     [with_tmpfilesdir=auto])

AS_IF([test "x$with_tmpfilesdir" = "xyes" -o "x$with_tmpfilesdir" = "xauto"], [
     def_tmpfilesdir=$($PKG_CONFIG --variable=tmpfilesdir systemd)
     AS_IF([test "x$def_tmpfilesdir" = "x"],
   [AS_IF([test "x$with_tmpfilesdir" = "xyes"],
    [AC_MSG_ERROR([tmpfiles support requested but pkg-config unable to query systemd package])])
    with_tmpfilesdir=no],
   [with_tmpfilesdir="$def_tmpfilesdir"])])
AS_IF([test "x$with_tmpfilesdir" != "xno"],
      [AC_SUBST([tmpfilesdir], [$with_tmpfilesdir])])

AC_ARG_WITH([libcurl-zlib],
     [AS_HELP_STRING([--with-libcurl-zlib], [Enable if libcurl is GZIP capable])],,
     [with_libcurl_zlib=yes])

AS_IF([test "x$with_libcurl_zlib" != "xno"], [
    ND_DEFINES+=" -D_ND_WITH_LIBCURL_ZLIB=1"
    AC_DEFINE([_ND_WITH_LIBCURL_ZLIB], [1], [Define if libcurl is GZIP capable.])
])

AC_ARG_WITH([persistentstatedir],
     [AS_HELP_STRING([--with-persistentstatedir=DIR], [Directory for persistent state files])],,
     [with_persistentstatedir=auto])
AS_IF([test "x$with_persistentstatedir" = "xyes" -o "x$with_persistentstatedir" = "xauto"],
    AC_SUBST([persistentstatedir], [$sysconfdir/netify.d]),
    AC_SUBST([persistentstatedir], [$with_persistentstatedir])
)

AC_ARG_WITH([volatilestatedir],
     [AS_HELP_STRING([--with-volatilestatedir=DIR], [Directory for volatile state files])],,
     [with_volatilestatedir=auto])
AS_IF([test "x$with_volatilestatedir" = "xyes" -o "x$with_volatilestatedir" = "xauto"],
    AC_SUBST([volatilestatedir], [$localstatedir/run/$PACKAGE_TARNAME]),
    AC_SUBST([volatilestatedir], [$with_volatilestatedir])
)

AC_ARG_WITH([conntrack-mdata],
     [AS_HELP_STRING([--with-conntrack-mdata], [Extract conntrack IDs and marks.])],,
     [with_conntrack_mdata=no])
AS_IF([test "x$with_conntrack_mdata" = "xyes"],
    AC_DEFINE([_ND_WITH_CONNTRACK_MDATA], [1], [Define to extract conntrack metadata.])
    ND_DEFINES+=" -D_ND_WITH_CONNTRACK_MDATA=1"
)

# Parameters: --enable/disable

AC_ARG_ENABLE([conntrack],
    [AS_HELP_STRING([--enable-conntrack], [Enable connection tracking support [default=yes]])],
    [],
    [enable_conntrack=yes])

AS_IF([test "x$enable_conntrack" = "xyes"], [
    AC_DEFINE([_ND_USE_CONNTRACK], [1],
        [Define to enable connection tracking support.])
    ND_DEFINES+=" -D_ND_USE_CONNTRACK=1"
    AM_CONDITIONAL(USE_CONNTRACK, true)
    PKG_CHECK_MODULES([LIBMNL], [libmnl >= 1.0.3])
    PKG_CHECK_MODULES([LIBNETFILTER_CONNTRACK], [libnetfilter_conntrack >= 1.0.4])
], [
    AM_CONDITIONAL(USE_CONNTRACK, false)
])

AC_ARG_ENABLE([inotify],
    [AS_HELP_STRING([--enable-inotify], [Enable inotify file watch support [default=yes]])],
    [],
    [enable_inotify=yes])

AS_IF([test "x$enable_inotify" = "xyes"], [
    AC_DEFINE([_ND_USE_INOTIFY], [1],
        [Define to enable inotify file watch support.])
    ND_DEFINES+=" -D_ND_USE_INOTIFY=1"
    AM_CONDITIONAL(USE_INOTIFY, true)
    AC_CHECK_HEADERS([sys/inotify.h], [], AC_MSG_ERROR([inotify header(s) not found.]))
], [
    AM_CONDITIONAL(USE_INOTIFY, false)
])

AC_ARG_ENABLE([netlink],
    [AS_HELP_STRING([--enable-netlink], [Enable Netlink socket support [default=yes]])],
    [],
    [enable_netlink=yes])

AS_IF([test "x$enable_netlink" = "xyes"], [
case "${host_os}" in
    freebsd*)
        AC_DEFINE([_ND_USE_NETLINK], [1],
            [Define to enable Netlink emulation support.])
        AM_CONDITIONAL(USE_NETLINK, true)
        ;;
    *)
        AC_DEFINE([_ND_USE_NETLINK], [1],
            [Define to enable Netlink socket support.])
        AM_CONDITIONAL(USE_NETLINK, true)
        AC_CHECK_HEADERS([linux/netlink.h], [], AC_MSG_ERROR([netlink header(s) not found.]))
        ;;
esac
ND_DEFINES+=" -D_ND_USE_NETLINK=1"
], [
    AM_CONDITIONAL(USE_NETLINK, false)
])

AC_ARG_ENABLE([plugins],
    [AS_HELP_STRING([--enable-plugins], [Enable Netify Plugin support [default=yes]])],
    [],
    [enable_plugins=yes])

AS_IF([test "x$enable_plugins" = "xyes"], [
    AC_DEFINE([_ND_USE_PLUGINS], [1],
        [Define to enable Netify Plugin support.])
    ND_DEFINES+=" -D_ND_USE_PLUGINS=1"
    AC_CHECK_HEADERS([dlfcn.h], [], AC_MSG_ERROR([dlfcn.h header(s) not found.]))
    case "${host_os}" in
        linux*)
            AC_CHECK_LIB([dl],
                [dlopen], [], [AC_MSG_ERROR([libdl/dlopen() not found.])])
            ;;
    esac
    AM_CONDITIONAL(USE_PLUGINS, true)
], [
    AM_CONDITIONAL(USE_PLUGINS, false)
])

AC_ARG_ENABLE([libtcmalloc],
    [AS_HELP_STRING([--enable-libtcmalloc], [Enable Thread Caching malloc support [default=yes]])],
    [],
    [enable_libtcmalloc=yes])

AM_CONDITIONAL(USE_LIBTCMALLOC, false)
AM_CONDITIONAL(USE_LIBTCMALLOC_BUNDLED, false)

AS_IF([test "x$enable_libtcmalloc" = "xyes"], [

    AC_DEFINE([_ND_USE_LIBTCMALLOC], [1],
        [Define to enable Thread Caching malloc support.])
    ND_DEFINES+=" -D_ND_USE_LIBTCMALLOC=1"

    PKG_CHECK_MODULES([LIBTCMALLOC], [libtcmalloc_minimal], [
        AM_CONDITIONAL(USE_LIBTCMALLOC, true)

        AC_LANG_PUSH([C++])
        AC_CHECK_HEADERS([gperftools/malloc_extension.h])
        AC_LANG_POP([C++])
    ], [
        AM_CONDITIONAL(USE_LIBTCMALLOC, true)
        AM_CONDITIONAL(USE_LIBTCMALLOC_BUNDLED, true)

        LIBTCMALLOC_LIBS="${ac_abs_confdir}/libs/gperftools/.libs/libtcmalloc_minimal.a"
        LIBTCMALLOC_CFLAGS="-I ${ac_abs_confdir}/libs/gperftools/src"
    ])

    AM_COND_IF([USE_LIBTCMALLOC_BUNDLED], [
        AC_CONFIG_SUBDIRS([libs/gperftools])
        AC_MSG_NOTICE([using tcmalloc (gperftools) from bundled libs...])
        AC_DEFINE([HAVE_GPERFTOOLS_MALLOC_EXTENSION_H], [1],
            [Define to 1 if you have the <gperftools/malloc_extension.h> header file.])
    ])
])

AC_ARG_ENABLE([jemalloc],
    [AS_HELP_STRING([--enable-jemalloc], [Enable jemalloc support [default=no]])],
    [],
    [enable_jemalloc=no])

AM_CONDITIONAL(USE_LIBJEMALLOC, false)
AM_CONDITIONAL(USE_LIBJEMALLOC_BUNDLED, false)

AS_IF([test "x$enable_jemalloc" = "xyes"], [

    AC_DEFINE([_ND_USE_LIBJEMALLOC], [1],
        [Define to enable jemalloc support.])
    ND_DEFINES+=" -D_ND_USE_LIBJEMALLOC=1"

    PKG_CHECK_MODULES([LIBJEMALLOC], [jemalloc], [
        AM_CONDITIONAL(USE_LIBJEMALLOC, true)

        AC_LANG_PUSH([C++])
        AC_CHECK_HEADERS([jemalloc/jemalloc.h])
        AC_LANG_POP([C++])
    ], [
        AM_CONDITIONAL(USE_LIBJEMALLOC, true)
        AM_CONDITIONAL(USE_LIBJEMALLOC_BUNDLED, true)

        LIBJEMALLOC_LIBS="${ac_abs_confdir}/libs/jemalloc/lib/libjemalloc.a"
        LIBJEMALLOC_CFLAGS="-I ${ac_abs_confdir}/libs/jemalloc/include"
    ])

    AM_COND_IF([USE_LIBJEMALLOC_BUNDLED], [
        AC_CONFIG_SUBDIRS([libs/jemalloc])
        AC_MSG_NOTICE([using jemalloc from bundled libs...])
        AC_DEFINE([HAVE_JEMALLOC_JEMALLOC_H], [1],
            [Define to 1 if you have the <jemalloc/jemalloc.h> header file.])
    ])
])

AC_ARG_ENABLE([lean-and-mean],
    [AS_HELP_STRING([--enable-lean-and-mean], [Enable build for embedded systems [default=no]])],
    [],
    [enable_lean_and_mean=no])

AS_IF([test "x$enable_lean_and_mean" = "xyes"], [
    AC_DEFINE([_ND_LEAN_AND_MEAN], [1],
        [Define to build smallest possible binary.])
    ND_DEFINES+=" -D_ND_LEAN_AND_MEAN=1"
    AM_CONDITIONAL(ENABLE_LEAN_AND_MEAN, true)
], [
    AM_CONDITIONAL(ENABLE_LEAN_AND_MEAN, false)
])

AC_ARG_ENABLE([watchdogs],
    [AS_HELP_STRING([--enable-watchdogs], [Enable run-time watchdogs [default=no]])],
    [],
    [enable_watchdogs=no])

AS_IF([test "x$enable_watchdogs" = "xyes"], [
    AC_DEFINE([_ND_USE_WATCHDOGS], [1],
        [Define to enable run-time watchdogs support.])
    ND_DEFINES+=" -D_ND_USE_WATCHDOGS=1"
    AM_CONDITIONAL(USE_WATCHDOGS, true)
], [
    AM_CONDITIONAL(USE_WATCHDOGS, false)
])

AC_ARG_ENABLE([ndpi-debug],
    [AS_HELP_STRING([--enable-ndpi-debug], [Enable nDPI debug messages [default=no]])],
    [],
    [enable_ndpi_debug=no])

AS_IF([test "x$enable_ndpi_debug" = "xyes"], [
    AC_DEFINE([NDPI_ENABLE_DEBUG_MESSAGES], [1],
        [Define to enable nDPI debug messages.])
    ND_DEFINES+=" -DNDPI_ENABLE_DEBUG_MESSAGES=1"
])

# Checks for required header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h net/ethernet.h stdint.h stdlib.h string.h sys/file.h sys/ioctl.h sys/socket.h sys/types.h sys/time.h sys/un.h syslog.h unistd.h], [], AC_MSG_ERROR([required header(s) not found.]))
AC_CHECK_HEADERS([netinet/in.h netinet/ip.h netinet/tcp.h netinet/udp.h], [], AC_MSG_ERROR([required netinet header(s) not found.]),
[[#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
]])

# Check for optional header files.
AC_CHECK_HEADERS([endian.h pthread_np.h sys/cpuset.h sys/endian.h linux/ppp_defs.h net/ppp_defs.h stdalign.h])
AC_CHECK_HEADERS([pcap/sll.h pcap/vlan.h])

# Check for optional parameters

# Checks for typedefs, structures, sizes, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_CHECK_SIZEOF([long])

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_STRNLEN

AC_CHECK_FUNCS([ftruncate memchr memset pathconf select socket strcasecmp strdup strerror])

AC_CHECK_FUNC([pthread_setname_np], [
    AC_DEFINE([HAVE_PTHREAD_SETNAME_NP], [1], [Define if pthread_setname_np is available.])
])
AC_CHECK_FUNC([pthread_attr_setaffinity_np], [
    AC_DEFINE([HAVE_PTHREAD_ATTR_SETAFFINITY_NP], [1], [Define if pthread_attr_setaffinity_np is available.])
])
AC_CHECK_FUNC([malloc_trim], [
    AC_DEFINE([HAVE_MALLOC_TRIM], [1], [Define if malloc_trim is available.])
])

# Get git revision
if test -e ".git"; then :
    GIT_TAG=`git log -1 --format=%h`
    GIT_DATE=`git log -1 --format=%cd`
    GIT_DATE_ISO8601=`git log -1 --format=%ci`

    GIT_LAST_COMMIT_HASH=`git log -1 --format=%H`
    GIT_LAST_COMMIT_DATE=`date -d "${GIT_DATE_ISO8601}" '+%F'`

    AC_SUBST([GIT_LAST_COMMIT_HASH], [$GIT_LAST_COMMIT_HASH])
    AC_SUBST([GIT_LAST_COMMIT_DATE], [$GIT_LAST_COMMIT_DATE])

    # On CentOS 6 `git rev-list HEAD --count` does not work
    GIT_NUM=`git log --pretty=oneline | wc -l | tr -d '[[:space:]]'`
    GIT_BRANCH=`git rev-parse --abbrev-ref HEAD`
    GIT_RELEASE="${PACKAGE_VERSION}-${GIT_BRANCH}-${GIT_NUM}-${GIT_TAG}"
else
    GIT_RELEASE="${PACKAGE_VERSION}"
    GIT_DATE=`date`
fi

AC_DEFINE_UNQUOTED(GIT_RELEASE, "${GIT_RELEASE}", [GIT Release])
AC_DEFINE_UNQUOTED(GIT_DATE, "${GIT_DATE}", [Last GIT change])
AC_SUBST([GIT_SOURCE_URL], [https://gitlab.com/netify.ai/public/netify-agent.git])

# Defines substitution for pkg-config
ND_DEFINES+=" -D'ND_CONF_FILE_NAME=\"$sysconfdir/$PACKAGE_TARNAME.conf\"'"
ND_DEFINES+=" -D'ND_DATADIR=\"$datadir/$PACKAGE_TARNAME\"'"
ND_DEFINES+=" -D'ND_PERSISTENT_STATEDIR=\"$persistentstatedir\"'"
ND_DEFINES+=" -D'ND_PID_FILE_NAME=\"$volatilestatedir/$PACKAGE_TARNAME.pid\"'"
ND_DEFINES+=" -D'ND_VOLATILE_STATEDIR=\"$volatilestatedir\"'"

AC_SUBST([ND_DEFINES], [$ND_DEFINES])

# Output files
AC_CONFIG_FILES([deploy/openwrt/Makefile deploy/openwrt/files/netifyd.init deploy/openwrt/files/netifyd.config])
AC_CONFIG_FILES([libnetifyd.pc])
AC_CONFIG_FILES([Makefile src/Makefile include/Makefile doc/Makefile tests/Makefile deploy/Makefile])
AC_CONFIG_FILES([deploy/buildroot/netifyd.mk])
AC_CONFIG_FILES([deploy/debian/Makefile])
AC_CONFIG_FILES([deploy/edgeos/Makefile])
AC_CONFIG_FILES([deploy/freebsd/Makefile-10x deploy/freebsd/Makefile-11x deploy/freebsd/Makefile-11x-debug deploy/freebsd/Makefile-12x])
AC_CONFIG_FILES([deploy/pfsense/Makefile])
AC_CONFIG_FILES([deploy/systemd/Makefile])
AC_CONFIG_FILES([deploy/ubios/Makefile])
AC_CONFIG_FILES([doc/netifyd.8 doc/netifyd.conf.5])
AC_CONFIG_FILES([netifyd.spec])
AC_CONFIG_FILES([util/generate-json-include.sh], [chmod +x util/generate-json-include.sh])
AC_CONFIG_FILES([util/generate-protocol-csv.sh], [chmod +x util/generate-protocol-csv.sh])

AC_OUTPUT
