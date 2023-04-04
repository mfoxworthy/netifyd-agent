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

ndInstance *ndInstance::instance = nullptr;

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

    if (threaded) {
        thread = new ndInstanceThread(tag, this);
        if (thread == nullptr) {
            throw ndSystemException(__PRETTY_FUNCTION__,
                "new ndInstanceThread", ENOMEM
            );
        }
    }

    flows = 0;

    agent_stats.cpus = sysconf(_SC_NPROCESSORS_ONLN);
}

ndInstance::~ndInstance()
{
    if (threaded && thread != nullptr) {
        thread->Terminate();
        delete thread;
    }

    if (this == instance) instance = nullptr;
}

ndInstance& ndInstance::Create(const sigset_t &sigset,
    const string &tag, bool threaded) {
    if (instance != nullptr) {
        fprintf(stderr, "Instance already created.\n");
        throw ndSystemException(__PRETTY_FUNCTION__,
            "instance exists", EINVAL
        );
    }

    instance = new ndInstance(sigset, tag, threaded);

    if (instance == nullptr) {
        throw ndSystemException(__PRETTY_FUNCTION__,
            "new ndInstance", ENOMEM
        );
    }

    return *instance;
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

uint32_t ndInstance::InitializeConfig(
    int argc, char * const argv[], const string &filename)
{
    uint8_t dump_flags = ndDUMP_NONE;

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
            return ndCR_INVALID_OPTION;
        case 'c':
            conf_filename = optarg;
            break;
        case 'd':
            ndGC_SetFlag(ndGF_DEBUG, true);
            break;
        default:
            break;
        }
    }

    if (! filename.empty()) {
        conf_filename = filename;

        if (ndGC.Load(conf_filename) < 0)
            return ndCR_LOAD_FAILURE;
    }

    ndGC.Close();

    Reload();

    optind = 1;
    while (true) {
        if ((rc = getopt_long(argc, argv, flags,
            options, NULL)) == -1) break;

        switch (rc) {
        case 0:
            break;
        case _ND_LO_ENABLE_SINK:
            rc = ndGC.SetOption(
                conf_filename, "config_enable_sink"
            );
            return ndCR_Pack(
                ndCR_SETOPT_SINK_ENABLE, (rc) ? 0 : 1
            );
        case _ND_LO_DISABLE_SINK:
            rc = ndGC.SetOption(
                conf_filename, "config_disable_sink"
            );
            return ndCR_Pack(
                ndCR_SETOPT_SINK_DISABLE, (rc) ? 0 : 1
            );
        case _ND_LO_FORCE_RESET:
            rc = ndGC.ForceReset();
            return ndCR_Pack(
                ndCR_FORCE_RESULT, (rc) ? 0 : 1
            );
        case _ND_LO_CA_CAPTURE_BASE:
            ndGC.ca_capture_base = (int16_t)atoi(optarg);
            if (ndGC.ca_capture_base > agent_stats.cpus) {
                fprintf(stderr,
                    "Capture thread base greater than online cores.\n");
                return ndCR_INVALID_VALUE;
            }
            break;
        case _ND_LO_CA_CONNTRACK:
            ndGC.ca_conntrack = (int16_t)atoi(optarg);
            if (ndGC.ca_conntrack > agent_stats.cpus) {
                fprintf(stderr,
                    "Conntrack thread ID greater than online cores.\n");
                return ndCR_INVALID_VALUE;
            }
            break;
        case _ND_LO_CA_DETECTION_BASE:
            ndGC.ca_detection_base = (int16_t)atoi(optarg);
            if (ndGC.ca_detection_base > agent_stats.cpus) {
                fprintf(stderr,
                    "Detection thread base greater than online cores.\n");
                return ndCR_INVALID_VALUE;
            }
            break;
        case _ND_LO_CA_DETECTION_CORES:
            ndGC.ca_detection_cores = (int16_t)atoi(optarg);
            if (ndGC.ca_detection_cores > agent_stats.cpus) {
                fprintf(stderr,
                    "Detection cores greater than online cores.\n");
                return ndCR_INVALID_VALUE;
            }
            break;
        case _ND_LO_CA_SINK:
            ndGC.ca_sink = (int16_t)atoi(optarg);
            if (ndGC.ca_sink > agent_stats.cpus) {
                fprintf(stderr,
                    "Sink thread ID greater than online cores.\n");
                return ndCR_INVALID_VALUE;
            }
            break;
        case _ND_LO_CA_SOCKET:
            ndGC.ca_socket = (int16_t)atoi(optarg);
            if (ndGC.ca_socket > agent_stats.cpus) {
                fprintf(stderr,
                    "Socket thread ID greater than online cores.\n");
                return ndCR_INVALID_VALUE;
            }
            break;
        case _ND_LO_WAIT_FOR_CLIENT:
            ndGC_SetFlag(ndGF_WAIT_FOR_CLIENT, true);
            break;
        case _ND_LO_EXPORT_APPS:
#ifndef _ND_LEAN_AND_MEAN
            rc = apps.Save("/dev/stdout");
            return ndCR_Pack(
                ndCR_EXPORT_APPS, (rc) ? 0 : 1
            );
#else
            fprintf(stderr, "Sorry, this feature was disabled (embedded).\n");
            return ndCR_DISABLED_OPTION;
#endif
        case _ND_LO_DUMP_SORT_BY_TAG:
            dump_flags |= ndDUMP_SORT_BY_TAG;
            break;

        case _ND_LO_DUMP_PROTOS:
            rc = DumpList(ndDUMP_TYPE_PROTOS | dump_flags);
            return ndCR_Pack(
                ndCR_DUMP_LIST, (rc) ? 0 : 1
            );
        case _ND_LO_DUMP_APPS:
            rc = DumpList(ndDUMP_TYPE_APPS | dump_flags);
            return ndCR_Pack(
                ndCR_DUMP_LIST, (rc) ? 0 : 1
            );
        case _ND_LO_DUMP_CAT:
            if (strncasecmp("application", optarg, 11) == 0)
                rc = DumpList(ndDUMP_TYPE_CAT_APP | dump_flags);
            else if (strncasecmp("protocol", optarg, 8) == 0)
                rc = DumpList(ndDUMP_TYPE_CAT_PROTO | dump_flags);
            else {
                fprintf(stderr,
                    "Invalid catetory type \"%s\", valid types: "
                    "applications, protocols\n", optarg
                );
                rc = 0;
            }
            return ndCR_Pack(
                ndCR_DUMP_LIST, (rc) ? 0 : 1
            );
        case _ND_LO_DUMP_CATS:
            rc = DumpList(ndDUMP_TYPE_CATS | dump_flags);
            return ndCR_Pack(
                ndCR_DUMP_LIST, (rc) ? 0 : 1
            );
        case _ND_LO_DUMP_RISKS:
            rc = DumpList(ndDUMP_TYPE_RISKS | dump_flags);
            return ndCR_Pack(
                ndCR_DUMP_LIST, (rc) ? 0 : 1
            );
        case '?':
            fprintf(stderr, "Try `--help' for more information.\n");
            return ndCR_INVALID_OPTION;
        }
    }

    return ndCR_OK;
}

bool ndInstance::DumpList(uint8_t type)
{
    if (! (type & ndDUMP_TYPE_PROTOS)
        && ! (type & ndDUMP_TYPE_APPS)
        && ! (type & ndDUMP_TYPE_CATS)
        && ! (type & ndDUMP_TYPE_RISKS)) {
        fprintf(stderr,
            "No filter type specified (application, protocol).\n"
        );
        return false;
    }

    if (type & ndDUMP_TYPE_CATS && ! (type & ndDUMP_TYPE_PROTOS)
        && ! (type & ndDUMP_TYPE_APPS)) {

        if (type & ndDUMP_TYPE_CAT_APP
            && ! (type & ndDUMP_TYPE_CAT_PROTO))
            categories.Dump(ndCAT_TYPE_APP);
        else if (! (type & ndDUMP_TYPE_CAT_APP)
            && type & ndDUMP_TYPE_CAT_PROTO)
            categories.Dump(ndCAT_TYPE_PROTO);
        else
            categories.Dump();
    }

    map<unsigned, string> entries_by_id;
    map<string, unsigned> entries_by_tag;

    if (type & ndDUMP_TYPE_PROTOS) {
        for (auto &proto : nd_protos) {

            if (proto.first == ND_PROTO_TODO) continue;

            if (! (type & ndDUMP_SORT_BY_TAG))
                entries_by_id[proto.first] = proto.second;
            else
                entries_by_tag[proto.second] = proto.first;
        }
    }

    if (type & ndDUMP_TYPE_APPS) {
        nd_apps_t applist;
        apps.Get(applist);
        for (auto &app : applist) {

            if (! (type & ndDUMP_SORT_BY_TAG))
                entries_by_id[app.second] = app.first;
            else
                entries_by_tag[app.first] = app.second;
        }
    }

    if (type & ndDUMP_TYPE_RISKS) {
        for (auto &risk : nd_risks) {

            if (risk.first == ND_RISK_TODO) continue;

            if (! (type & ndDUMP_SORT_BY_TAG))
                entries_by_id[risk.first] = risk.second;
            else
                entries_by_tag[risk.second] = risk.first;
        }
    }

    for (auto &entry : entries_by_id)
        printf("%6u: %s\n", entry.first, entry.second.c_str());
    for (auto &entry : entries_by_tag)
        printf("%6u: %s\n", entry.second, entry.first.c_str());

    return true;
}

int ndInstance::Run(void)
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

bool ndInstance::Reload(void)
{
    bool result = true;

    nd_dprintf("Reloading configuration...\n");
    if (! (result = apps.Load(ndGC.path_app_config)))
        result = apps.LoadLegacy(ndGC.path_legacy_config);

    result = categories.Load();
    if (ndGC_LOAD_DOMAINS) result = domains.Load();

#ifdef _ND_USE_PLUGINS
    //nd_plugin_event(ndPlugin::EVENT_RELOAD);
#endif

    nd_dprintf("Configuration reloaded %s.\n",
        (result) ? "successfully" : "with errors");

    return result;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
