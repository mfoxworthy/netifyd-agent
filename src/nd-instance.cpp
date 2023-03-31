// Netify Agent
// Copyright (C) 2015-2023 eGloo Incorporated <http://www.egloo.ca>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <iomanip>
#include <iostream>
#include <set>
#include <map>
#include <queue>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <list>
#include <vector>
#include <locale>
#include <atomic>
#include <regex>
#include <mutex>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/resource.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <locale.h>
#include <syslog.h>
#include <fcntl.h>

#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <netdb.h>
#include <netinet/in.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>

#define __FAVOR_BSD 1
#include <netinet/tcp.h>
#undef __FAVOR_BSD

#include <curl/curl.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <resolv.h>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#ifdef _ND_USE_CONNTRACK
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#endif

#if defined(_ND_USE_LIBTCMALLOC) && defined(HAVE_GPERFTOOLS_MALLOC_EXTENSION_H)
#include <gperftools/malloc_extension.h>
#elif defined(_ND_USE_LIBJEMALLOC) && defined(HAVE_JEMALLOC_JEMALLOC_H)
#include <jemalloc/jemalloc.h>
#elif defined(HAVE_MALLOC_TRIM)
#include <malloc.h>
#endif

#include <radix/radix_tree.hpp>

using namespace std;

#include "netifyd.h"

#include "nd-config.h"
#include "nd-ndpi.h"
#include "nd-risks.h"
#include "nd-serializer.h"
#include "nd-packet.h"
#include "nd-json.h"
#include "nd-util.h"
#include "nd-addr.h"
#ifdef _ND_USE_NETLINK
#include "nd-netlink.h"
#endif
#include "nd-apps.h"
#include "nd-protos.h"
#include "nd-category.h"
#include "nd-flow.h"
#include "nd-flow-map.h"
#include "nd-flow-parser.h"
#include "nd-thread.h"
#ifdef _ND_USE_CONNTRACK
#include "nd-conntrack.h"
#endif
#include "nd-dhc.h"
#include "nd-fhc.h"
#include "nd-detection.h"
#include "nd-capture.h"
#ifdef _ND_USE_LIBPCAP
#include "nd-capture-pcap.h"
#endif
#ifdef _ND_USE_TPACKETV3
#include "nd-capture-tpv3.h"
#endif
#include "nd-socket.h"
#include "nd-sink.h"
#include "nd-base64.h"
#ifdef _ND_USE_PLUGINS
#include "nd-plugin.h"
#endif
#include "nd-signal.h"
#include "nd-napi.h"
#include "nd-instance.h"

void *ndInstanceThread::Entry(void)
{
    if (! ShouldTerminate()) return instance->Entry();
    return nullptr;
}

ndInstance::ndInstance(
    const sigset_t &sigset, const string &tag, bool threaded)
    : exit_code(EXIT_SUCCESS), sigset(sigset),
    tag(tag.empty() ? PACKAGE_TARNAME : tag),
    self(PACKAGE_TARNAME),
    threaded(threaded), thread(nullptr),
    conf_filename(ND_CONF_FILE_NAME),
    agent_stats{0}
{
    terminate = false;
    terminate_force = false;

    if (threaded)
        thread = new ndInstanceThread(tag, this);
// TODO:
//        if (thread == nullptr)
//            throw...

    flows = 0;

    agent_stats.cpus = sysconf(_SC_NPROCESSORS_ONLN);
}

ndInstance::~ndInstance()
{
    if (threaded && thread != nullptr) {
        thread->Terminate();
        delete thread;
    }
}

void ndInstance::InitializeSignals(sigset_t &sigset, bool minimal)
{
    if (! minimal) {
        sigfillset(&sigset);
        //sigdelset(&sigset, SIGPROF);
        //sigdelset(&sigset, SIGINT);
        sigdelset(&sigset, SIGQUIT);
        sigprocmask(SIG_BLOCK, &sigset, NULL);
    }

    sigemptyset(&sigset);
    sigaddset(&sigset, ND_SIG_SINK_REPLY);
    sigaddset(&sigset, ND_SIG_UPDATE);
    sigaddset(&sigset, ND_SIG_CONNECT);
    sigaddset(&sigset, ND_SIG_NAPI_UPDATE);
    sigaddset(&sigset, ND_SIG_NAPI_UPDATED);
    sigaddset(&sigset, SIGIO);

    if (! minimal) {
        sigaddset(&sigset, SIGHUP);
        sigaddset(&sigset, SIGINT);
#ifdef SIGPWR
        sigaddset(&sigset, SIGPWR);
#endif
        sigaddset(&sigset, SIGTERM);
        sigaddset(&sigset, SIGUSR1);
        sigaddset(&sigset, SIGUSR2);
    }
}

bool ndInstance::LoadConfig(int argc, char * const argv[],
    const string &filename)
{
    nd_basename(argv[0], self);

    static struct option options[] =
    {
        { "config", 1, 0, 'c' },
        { "debug", 0, 0, 'd' },
        { "debug-ether-names", 0, 0, 'e' },
        { "debug-ndpi", 0, 0, 'n' },
        { "debug-uploads", 0, 0, 'D' },
        { "device-address", 1, 0, 'A' },
        { "device-filter", 1, 0, 'F' },
        { "device-peer", 1, 0, 'N' },
        { "disable-conntrack", 0, 0, 't' },
        { "disable-netlink", 0, 0, 'l' },
        { "export-json", 1, 0, 'j' },
        { "external", 1, 0, 'E' },
        { "hash-file", 1, 0, 'S' },
        { "help", 0, 0, 'h' },
        { "internal", 1, 0, 'I' },
        { "interval", 1, 0, 'i' },
        { "ndpi-config", 1, 0, 'f' },
        { "provision", 0, 0, 'p' },
        { "remain-in-foreground", 0, 0, 'R' },
        { "replay-delay", 0, 0, 'r' },
        { "status", 0, 0, 's' },
        { "test-output", 1, 0, 'T' },
        { "uuid", 1, 0, 'u' },
        { "uuidgen", 0, 0, 'U' },
        { "verbose", 0, 0, 'v' },
        { "version", 0, 0, 'V' },
#define _ND_LO_ENABLE_SINK          1
#define _ND_LO_DISABLE_SINK         2
        { "enable-sink", 0, 0, _ND_LO_ENABLE_SINK },
        { "disable-sink", 0, 0, _ND_LO_DISABLE_SINK },
#define _ND_LO_FORCE_RESET          3
        { "force-reset", 0, 0, _ND_LO_FORCE_RESET },
#define _ND_LO_CA_CAPTURE_BASE      4
#define _ND_LO_CA_CONNTRACK         5
#define _ND_LO_CA_DETECTION_BASE    6
#define _ND_LO_CA_DETECTION_CORES   7
#define _ND_LO_CA_SINK              8
#define _ND_LO_CA_SOCKET            9
        { "thread-capture-base", 1, 0, _ND_LO_CA_CAPTURE_BASE },
        { "thread-conntrack", 1, 0, _ND_LO_CA_CONNTRACK },
        { "thread-detection-base", 1, 0, _ND_LO_CA_DETECTION_BASE },
        { "thread-detection-cores", 1, 0, _ND_LO_CA_DETECTION_CORES },
        { "thread-sink", 1, 0, _ND_LO_CA_SINK },
        { "thread-socket", 1, 0, _ND_LO_CA_SOCKET },
#define _ND_LO_WAIT_FOR_CLIENT      10
        { "wait-for-client", 0, 0, _ND_LO_WAIT_FOR_CLIENT },
#define _ND_LO_DUMP_PROTOS          11
#define _ND_LO_DUMP_APPS            12
#define _ND_LO_DUMP_CAT             13
#define _ND_LO_DUMP_CATS            14
#define _ND_LO_DUMP_RISKS           15
        { "dump-all", 0, 0, 'P' },
        { "dump-protos", 0, 0, _ND_LO_DUMP_PROTOS },
        { "dump-protocols", 0, 0, _ND_LO_DUMP_PROTOS },
        { "dump-apps", 0, 0, _ND_LO_DUMP_APPS },
        { "dump-applications", 0, 0, _ND_LO_DUMP_APPS },
        { "dump-category", 1, 0, _ND_LO_DUMP_CAT },
        { "dump-categories", 0, 0, _ND_LO_DUMP_CATS },
        { "dump-risks", 0, 0, _ND_LO_DUMP_RISKS },
#define _ND_LO_DUMP_SORT_BY_TAG     16
        { "dump-sort-by-tag", 0, 0, _ND_LO_DUMP_SORT_BY_TAG },
#define _ND_LO_EXPORT_APPS          17
        { "export-apps", 0, 0, _ND_LO_EXPORT_APPS },
#define _ND_LO_LOOKUP_IP            18
        { "lookup-ip", 1, 0, _ND_LO_LOOKUP_IP },

        { NULL, 0, 0, 0 }
    };

    static const char *flags = {
        "?A:c:DdE:eF:f:hI:i:j:lN:nPpRrS:stT:Uu:Vv"
    };

    int rc;
    while (true) {
        if ((rc = getopt_long(argc, argv, flags,
            options, NULL)) == -1) break;

        switch (rc) {
        case 0:
            break;
        case '?':
            fprintf(stderr, "Try `--help' for more information.\n");
            return 1;
        case 'c':
            conf_filename = optarg;
            break;
        case 'd':
            config.flags |= ndGF_DEBUG;
            break;
        default:
            break;
        }
    }

    if (! filename.empty()) conf_filename = filename;

    if (config.Load(conf_filename) < 0)
        return false;

    config.Close();

    optind = 1;

    while (true) {
        if ((rc = getopt_long(argc, argv, flags,
            options, NULL)) == -1) break;

        switch (rc) {
        case 0:
            break;
        case _ND_LO_ENABLE_SINK:
            exit(
                config.SetOption(
                    conf_filename, "config_enable_sink"
                ) ? 0 : 1
            );
        case _ND_LO_DISABLE_SINK:
            exit(
                config.SetOption(
                    conf_filename, "config_disable_sink"
                ) ? 0 : 1
            );
        case _ND_LO_FORCE_RESET:
            exit(
                config.ForceReset() ? 0 : 1
            );
        case _ND_LO_CA_CAPTURE_BASE:
            config.ca_capture_base = (int16_t)atoi(optarg);
            if (config.ca_capture_base > agent_stats.cpus) {
                fprintf(stderr,
                    "Capture thread base greater than online cores.\n");
                return false;
            }
            break;
        case _ND_LO_CA_CONNTRACK:
            config.ca_conntrack = (int16_t)atoi(optarg);
            if (config.ca_conntrack > agent_stats.cpus) {
                fprintf(stderr,
                    "Conntrack thread ID greater than online cores.\n");
                return false;
            }
            break;
        case _ND_LO_CA_DETECTION_BASE:
            config.ca_detection_base = (int16_t)atoi(optarg);
            if (config.ca_detection_base > agent_stats.cpus) {
                fprintf(stderr,
                    "Detection thread base greater than online cores.\n");
                return false;
            }
            break;
        case _ND_LO_CA_DETECTION_CORES:
            config.ca_detection_cores = (int16_t)atoi(optarg);
            if (config.ca_detection_cores > agent_stats.cpus) {
                fprintf(stderr,
                    "Detection cores greater than online cores.\n");
                return false;
            }
            break;
        case _ND_LO_CA_SINK:
            config.ca_sink = (int16_t)atoi(optarg);
            if (config.ca_sink > agent_stats.cpus) {
                fprintf(stderr,
                    "Sink thread ID greater than online cores.\n");
                return false;
            }
            break;
        case _ND_LO_CA_SOCKET:
            config.ca_socket = (int16_t)atoi(optarg);
            if (config.ca_socket > agent_stats.cpus) {
                fprintf(stderr,
                    "Socket thread ID greater than online cores.\n");
                return false;
            }
            break;
        case _ND_LO_WAIT_FOR_CLIENT:
            config.flags |= ndGF_WAIT_FOR_CLIENT;
            break;
        }
#if 0
        case _ND_LO_EXPORT_APPS:
#ifndef _ND_LEAN_AND_MEAN
            exit(nd_export_applications());
#else
            fprintf(stderr, "Sorry, this feature was disabled (embedded).\n");
            exit(1);
#endif
#endif
    }

    return true;
}

int ndInstance::Create(void)
{
    if (threaded) {
        if (thread == nullptr) {
            exit_code = EXIT_FAILURE;
            return exit_code;
        }

        try {
            thread->Create();
        }
        catch (ndThreadException &e) {
            exit_code = EXIT_FAILURE;
        }

        return exit_code;
    }

    void *rc __attribute__((unused)) = Entry();

    return exit_code;
}

void *ndInstance::ndInstance::Entry(void)
{
    int c = 0;
    struct timespec tspec_sigwait = { 1, 0 };

    do {
        int sig;
        siginfo_t si;

        nd_dprintf("%s: tick: %d\n", tag.c_str(), ++c);

        if ((sig = sigtimedwait(&sigset, &si, &tspec_sigwait)) < 0) {
            if (errno == EAGAIN || errno == EINTR) continue;
            exit_code = -1;
            terminate = true;
            nd_printf("sigwaitinfo: %s\n", strerror(errno));
            continue;
        }

        if (sig == SIGINT || sig == SIGTERM) {
            terminate = true;
        }
    }
    while (! terminate.load());

    return nullptr;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
