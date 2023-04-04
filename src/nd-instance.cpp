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
    string last_iface;
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
        case _ND_LO_LOOKUP_IP:
#ifndef _ND_LEAN_AND_MEAN
            rc = LookupAddress(optarg);
            return ndCR_Pack(
                ndCR_LOOKUP_ADDR, (rc) ? 0 : 1
            );
#else
            fprintf(stderr, "Sorry, this feature was disabled (embedded).\n");
            exit(1);
#endif
        case '?':
            fprintf(stderr, "Try `--help' for more information.\n");
            return ndCR_INVALID_OPTION;
        case 'A':
            if (last_iface.size() == 0) {
                fprintf(stderr,
                    "You must specify an interface first (-I/E).\n"
                );
                return ndCR_INVALID_OPTION;
            }
            ndGC.AddInterfaceAddress(last_iface, optarg);
            break;
        case 'd':
            break;
        case 'D':
            ndGC.flags |= ndGF_DEBUG_UPLOAD;
            break;
        case 'c':
            break;
        case 'E':
            ndGC.AddInterface(optarg, ndIR_WAN, ndCT_PCAP);
            last_iface = optarg;
            break;
        case 'F':
            if (last_iface.size() == 0) {
                fprintf(stderr,
                    "You must specify an interface first (-I/E).\n"
                );
                return ndCR_INVALID_OPTION;
            }
            ndGC.AddInterfaceFilter(last_iface, optarg);
            break;
        case 'f':
            ndGC.path_legacy_config = optarg;
            break;
        case 'h':
            CommandLineHelp();
            return ndCR_USAGE_OR_VERSION;
        case 'I':
            ndGC.AddInterface(optarg, ndIR_LAN, ndCT_PCAP);
            last_iface = optarg;
            break;
        case 'i':
            ndGC.update_interval = atoi(optarg);
            break;
        case 'j':
            ndGC.path_export_json = optarg;
            break;
        case 'l':
            ndGC_SetFlag(ndGF_USE_NETLINK, false);
            break;
        case 'n':
            ndGC_SetFlag(ndGF_DEBUG_NDPI, true);
            break;
        case 'N':
            if (last_iface.size() == 0) {
                fprintf(stderr,
                    "You must specify an interface first (-I/E).\n"
                );
                return ndCR_INVALID_OPTION;
            }
            ndGC.AddInterfacePeer(last_iface, optarg);
            break;
        case 'P':
            rc = DumpList(ndDUMP_TYPE_ALL | dump_flags);
            return ndCR_Pack(
                ndCR_DUMP_LIST, (rc) ? 0 : 1
            );
        case 'p':
            if ((rc = (CheckAgentUUID() && ndGC.uuid != nullptr)))
                fprintf(stdout, "Agent UUID: %s\n", ndGC.uuid);
            return ndCR_Pack(
                ndCR_PROVISION_UUID, (rc) ? 0 : 1
            );
        case 'R':
            ndGC_SetFlag(ndGF_REMAIN_IN_FOREGROUND, true);
            break;
        case 'r':
            ndGC_SetFlag(ndGF_REPLAY_DELAY, true);
            break;
        case 'S':
#ifndef _ND_LEAN_AND_MEAN
            {
                uint8_t digest[SHA1_DIGEST_LENGTH];

                if ((rc = nd_sha1_file(optarg, digest)) == 0) {
                    string sha1;
                    nd_sha1_to_string(digest, sha1);
                    fprintf(stdout, "%s  %s\n",
                        sha1.c_str(), optarg
                    );
                }
                return ndCR_Pack(ndCR_HASH_FILE, rc);
            }
#else
            fprintf(stderr,
                "Sorry, this feature was disabled (embedded).\n"
            );
            return ndCR_OPTION_DISABLED;
#endif
        case 's':
            rc = AgentStatus();
            return ndCR_Pack(
                ndCR_AGENT_STATUS, (rc) ? 0 : 1
            );
            break;
        case 't':
            ndGC_SetFlag(ndGF_USE_CONNTRACK, false);
            break;
        case 'T':
            if ((ndGC.h_flow = fopen(optarg, "w")) == NULL) {
                fprintf(stderr,
                    "Error while opening test output log: %s: %s\n",
                    optarg, strerror(errno)
                );
                return ndCR_INVALID_VALUE;
            }
            break;
        case 'U':
            {
                string uuid;
                nd_generate_uuid(uuid);
                fprintf(stdout, "%s\n", uuid.c_str());
            }
            return ndCR_GENERATE_UUID;
        case 'u':
            ndGC.uuid = strdup(optarg);
            break;
        case 'V':
            CommandLineHelp(true);
            return ndCR_USAGE_OR_VERSION;
        case 'v':
            ndGC_SetFlag(ndGF_VERBOSE, true);
            break;
        default:
            CommandLineHelp();
            return ndCR_INVALID_OPTION;
        }
    }

    for (auto &r : ndGC.interfaces) {
        for (auto &i : r.second) {
            auto result = interfaces.insert(
                make_pair(
                    i.first,
                    ndInterface(
                        i.first,
                        i.second.first,
                        r.first
                    )
                )
            );

            if (result.second) {
                switch (i.second.first) {
                case ndCT_PCAP:
                    result.first->second.SetConfig(
                        static_cast<nd_config_pcap *>(
                            i.second.second
                        )
                    );
                    break;
#if defined(_ND_USE_TPACKETV3)
                case ndCT_TPV3:
                    result.first->second.SetConfig(
                        static_cast<nd_config_tpv3 *>(
                            i.second.second
                        )
                    );
                    break;
#endif
#if defined(_ND_USE_NFQUEUE)
                case ndCT_NFQ:
                    result.first->second.SetConfig(
                        static_cast<nd_config_nfq *>(
                            i.second.second
                        )
                    );
                    break;
#endif
                default:
                    break;
                }
            }

            auto peer = ndGC.interface_peers.find(i.first);
            if (peer != ndGC.interface_peers.end())
                result.first->second.ifname_peer = peer->second;
        }
    }

    if (interfaces.size() == 0) {
        fprintf(stderr, "No packet capture sources configured.\n");
        return ndCR_INVALID_INTERFACES;
    }

    version = nd_get_version_and_features();

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

bool ndInstance::LookupAddress(const string &ip)
{
    ndAddr addr(ip);

    if (! addr.IsValid() || ! addr.IsIP()) {
        fprintf(stderr, "Invalid IP address: %s\n", ip.c_str());
        return false;
    }

    nd_app_id_t id = apps.Find(addr);

    fprintf(stdout, "%6u: %s\n", id, apps.Lookup(id));

    return true;
}

void ndInstance::CommandLineHelp(bool version_only)
{
    ndGC_SetFlag(ndGF_QUIET, true);

    fprintf(stderr,
        "%s\n%s\n", nd_get_version_and_features().c_str(), PACKAGE_URL);
    if (version_only) {
        fprintf(stderr,
            "\nThis application uses nDPI v%s, API v%u\n"
            "https://www.ntop.org/products/deep-packet-inspection/ndpi/\n"
            "https://github.com/ntop/nDPI\n", ndpi_revision(), NDPI_API_VERSION);

        fprintf(stderr, "\n  This program comes with ABSOLUTELY NO WARRANTY.\n"
            "  Netifyd is dual-licensed under commercial and open source licenses. The\n"
            "  commercial license gives you the full rights to create and distribute software\n"
            "  on your own terms without any open source license obligations.\n\n"
            "  Netifyd is also available under GPL and LGPL open source licenses.  The open\n"
            "  source licensing is ideal for student/academic purposes, hobby projects,\n"
            "  internal research project, or other projects where all open source license\n"
            "  obligations can be met.\n");
#ifdef PACKAGE_BUGREPORT
        fprintf(stderr, "\nReport bugs to: %s\n", PACKAGE_BUGREPORT);
#endif
#ifdef _ND_USE_PLUGINS
        if (ndGC.plugin_detections.size())
            fprintf(stderr, "\nDetection plugins:\n");

        for (auto i : ndGC.plugin_detections) {

            string plugin_version("?.?.?");

            try {
                ndPluginLoader *loader = new ndPluginLoader(
                    i.second, i.first
                );
                loader->GetPlugin()->GetVersion(plugin_version);
            }
            catch (...) { }

            fprintf(stderr, "  %s: %s: v%s\n",
                i.first.c_str(), i.second.c_str(),
                plugin_version.c_str()
            );
        }

        if (ndGC.plugin_sinks.size())
            fprintf(stderr, "\nStatistics plugins:\n");

        for (auto i : ndGC.plugin_sinks) {

            string plugin_version("?.?.?");

            try {
                ndPluginLoader *loader = new ndPluginLoader(
                    i.second, i.first
                );
                loader->GetPlugin()->GetVersion(plugin_version);
            }
            catch (...) { }

            fprintf(stderr, "  %s: %s: v%s\n",
                i.first.c_str(), i.second.c_str(),
                plugin_version.c_str()
            );
        }

        if (ndGC.plugin_stats.size())
            fprintf(stderr, "\nStatistics plugins:\n");

        for (auto i : ndGC.plugin_stats) {

            string plugin_version("?.?.?");

            try {
                ndPluginLoader *loader = new ndPluginLoader(
                    i.second, i.first
                );
                loader->GetPlugin()->GetVersion(plugin_version);
            }
            catch (...) { }

            fprintf(stderr, "  %s: %s: v%s\n",
                i.first.c_str(), i.second.c_str(),
                plugin_version.c_str()
            );
        }
#endif
    }
    else {
        fprintf(stderr,
            "\nStatus options:\n"
            "  -s, --status\n    Display Agent status.\n"

            "\nGlobal options:\n"
            "  -d, --debug\n    Enable debug output and remain in foreground.\n"
            "  -e, --debug-ether-names\n    In debug mode, resolve and display addresses from: /etc/ethers\n"
            "  -n, --debug-ndpi\n    In debug mode, display nDPI debug message when enabled (compile-time).\n"
            "  -D, --debug-upload\n    In debug mode, display debug output from sink server uploads.\n"
            "  -v, --verbose\n    In debug mode, display real-time flow detections.\n"
            "  -R, --remain-in-foreground\n    Remain in foreground, don't daemonize (OpenWrt).\n"
            "  --wait-for-client\n    In debug mode, don't start capture threads until a client connects.\n"

            "\nConfiguration options:\n"
            "  -u, --uuid\n    Display configured Agent UUID.\n"
            "  -U, --uuidgen\n    Generate (but don't save) a new Agent UUID.\n"
            "  -p, --provision\n    Provision Agent (generate and save Agent UUID).\n"
            "  --enable-sink, --disable-sink\n    Enable/disable sink uploads.\n"
            "  -c, --config <filename>\n    Specify an alternate Agent configuration.\n"
            "    Default: %s\n"
            "  -f, --ndpi-config <filename>\n    Specify an alternate legacy (nDPI) application configuration file.\n"
            "    Default: %s\n"
            "  --force-reset\n    Reset Agent sink configuration options.\n"
            "    Deletes: %s, %s, %s\n"
            "\nDump options:\n"
            "  --dump-sort-by-tag\n    Sort entries by tag.\n"
            "    Default: sort entries by ID.\n"
            "  -P, --dump-all\n    Dump all applications and protocols.\n"
            "  --dump-apps\n    Dump applications only.\n"
            "  --dump-protos\n    Dump protocols only.\n"
            "  --dump-categories\n    Dump application and protocol categories.\n"
            "  --dump-category <type>\n    Dump categories by type: application or protocol\n"
            "  --dump-risks\n    Dump flow security risks.\n"
            "\nCapture options:\n"
            "  -I, --internal <interface>\n    Specify an internal (LAN) interface to capture from.\n"
            "  -E, --external <interface>\n    Specify an external (WAN) interface to capture from.\n"
            "  -A, --device-address <address>\n    Interface/device option: consider address is assigned to interface.\n"
            "  -F, --device-filter <BPF expression>\n    Interface/device option: attach a BPF filter expression to interface.\n"
            "  -N, --device-peer <interface>\n    Interface/device option: associate interface with a peer (ex: PPPoE interface, pppX).\n"
            "  -t, --disable-conntrack\n    Disable connection tracking thread.\n"
            "  -l, --disable-netlink\n    Don't process Netlink messages for capture interfaces.\n"
            "  -r, --replay-delay\n    Simulate packet-to-packet arrival times in offline playback mode.\n"

            "\nThreading options:\n"
            "  --thread-capture-base <offset>\n    Specify a thread affinity base or offset for capture threads.\n"
            "  --thread-conntrack <cpu>\n    Specify a CPU affinity ID for the conntrack thread.\n"
            "  --thread-sink <cpu>\n    Specify a CPU affinity ID for the sink upload thread.\n"
            "  --thread-socket <cpu>\n    Specify a CPU affinity ID for the socket server thread.\n"
            "  --thread-detection-base <offset>\n    Specify a thread affinity base or offset for detection (DPI) threads.\n"
            "  --thread-detection-cores <count>\n    Specify the number of detection (DPI) threads to start.\n"

            "\nSee netifyd(8) and netifyd.conf(5) for further options.\n",

            ND_CONF_FILE_NAME,
            ND_CONF_LEGACY_PATH,
            ndGC.path_uuid.c_str(),
            ndGC.path_uuid_site.c_str(),
            ND_URL_SINK_PATH
        );
    }
}

bool ndInstance::CheckAgentUUID(void)
{
    if (ndGC.uuid == nullptr ||
        ! strncmp(ndGC.uuid, ND_AGENT_UUID_NULL, ND_AGENT_UUID_LEN)) {

        string uuid;
        if (! nd_load_uuid(uuid, ndGC.path_uuid, ND_AGENT_UUID_LEN) ||
            ! uuid.size() ||
            ! strncmp(uuid.c_str(), ND_AGENT_UUID_NULL, ND_AGENT_UUID_LEN)) {

            nd_generate_uuid(uuid);

            fprintf(stdout,
                "Generated a new Agent UUID: %s\n", uuid.c_str()
            );
            if (! nd_save_uuid(uuid, ndGC.path_uuid, ND_AGENT_UUID_LEN))
                return false;
        }

        if (ndGC.uuid != nullptr) free(ndGC.uuid);
        ndGC.uuid = strdup(uuid.c_str());
    }

    return true;
}

bool ndInstance::AgentStatus(void)
{
    const char *icon = ND_I_INFO;
    const char *color = ND_C_RESET;

    fprintf(stderr, "%s\n", nd_get_version_and_features().c_str());

    if (geteuid() != 0) {
        fprintf(stderr,
            "%s%s%s Error while retrieving agent status: %s%s%s\n",
            ND_C_RED, ND_I_FAIL, ND_C_RESET,
            ND_C_RED, strerror(EPERM), ND_C_RESET
        );
        return false;
    }

    pid_t nd_pid = nd_load_pid(ndGC.path_pid_file);
    nd_pid = nd_is_running(nd_pid, self);

    if (nd_file_exists(ND_URL_SINK_PATH) > 0) {
        string url_sink;
        if (nd_load_sink_url(url_sink)) {
            free(ndGC.url_sink);
            ndGC.url_sink = strdup(url_sink.c_str());
        }
    }

    fprintf(stderr, "%s%s%s agent %s: PID %d\n",
        (nd_pid < 0) ? ND_C_YELLOW :
            (nd_pid == 0) ? ND_C_RED : ND_C_GREEN,
        (nd_pid < 0) ? ND_I_WARN :
            (nd_pid == 0) ? ND_I_FAIL : ND_I_OK,
        ND_C_RESET,
        (nd_pid < 0) ? "status could not be determined" :
            (nd_pid == 0) ? "is not running" : "is running",
        nd_pid
    );

    fprintf(stderr, "%s persistent state path: %s\n",
        ND_I_INFO, ndGC.path_state_persistent.c_str());
    fprintf(stderr, "%s volatile state path: %s\n",
        ND_I_INFO, ndGC.path_state_volatile.c_str());

    json jstatus;

    try {
        string status;
        if (nd_file_load(ndGC.path_agent_status, status) < 0
            || status.size() == 0) {
            fprintf(stderr,
                "%s%s%s agent run-time status could not be determined.\n",
                ND_C_YELLOW, ND_I_WARN, ND_C_RESET
            );

            return false;
        }

        jstatus = json::parse(status);

        if (jstatus["type"].get<string>() != "agent_status")
            throw ndJsonParseException("Required type: agent_status");

        char timestamp[64];
        time_t ts = jstatus["timestamp"].get<time_t>();
        struct tm *tm_local = localtime(&ts);

        if (nd_pid <= 0) {
            fprintf(stderr,
                "%s%s The following run-time information is likely out-dated.%s\n",
                ND_C_YELLOW, ND_I_WARN, ND_C_RESET
            );
        }

        if (strftime(timestamp, sizeof(timestamp), "%c", tm_local) > 0) {
            fprintf(stderr,
                "%s%s%s agent timestamp: %s\n",
                ND_C_GREEN, ND_I_INFO, ND_C_RESET, timestamp
            );
        }

        string uptime;
        nd_uptime(jstatus["uptime"].get<time_t>(), uptime);
        fprintf(stderr,
            "%s agent uptime: %s\n", ND_I_INFO, uptime.c_str()
        );

        double flows = jstatus["flow_count"].get<double>();
        double flow_utilization = (ndGC.max_flows > 0) ?
            flows * 100.0 / (double)ndGC.max_flows : 0;
        string max_flows = (ndGC.max_flows == 0) ?
            "unlimited" : to_string(ndGC.max_flows);

        if (flows > 0) {
            if (ndGC.max_flows) {
                if (flow_utilization < 75) {
                    icon = ND_I_OK;
                    color = ND_C_GREEN;
                }
                else if (flow_utilization < 90) {
                    icon = ND_I_WARN;
                    color = ND_C_YELLOW;
                }
                else {
                    icon = ND_I_FAIL;
                    color = ND_C_RED;
                }
            }
            else {
                icon = ND_I_OK;
                color = ND_C_GREEN;
            }
        }
        else {
            icon = ND_I_WARN;
            color = ND_C_YELLOW;
        }

        fprintf(stderr,
            "%s%s%s active flows: %s%u%s / %s (%s%.01lf%%%s)\n",
            color, icon, ND_C_RESET,
            color, (unsigned)flows, ND_C_RESET,
            max_flows.c_str(),
            color, flow_utilization, ND_C_RESET
        );

        fprintf(stderr, "%s minimum flow size: %lu\n",
            ND_I_INFO,
            sizeof(struct ndFlow) + sizeof(struct ndpi_flow_struct)
        );

        fprintf(stderr, "%s CPU cores: %u\n",
            ND_I_INFO, jstatus["cpu_cores"].get<unsigned>());

        double cpu_user_delta =
            jstatus["cpu_user"].get<double>() -
            jstatus["cpu_user_prev"].get<double>();
        double cpu_system_delta =
            jstatus["cpu_system"].get<double>() -
            jstatus["cpu_system_prev"].get<double>();
        double cpu_max_time =
            jstatus["update_interval"].get<double>() *
            jstatus["cpu_cores"].get<double>();

        double cpu_user_percent = cpu_user_delta * 100.0 / cpu_max_time;
        double cpu_system_percent = cpu_system_delta * 100.0 / cpu_max_time;
        double cpu_total = cpu_user_percent + cpu_system_percent;

        if (cpu_total < 33.34) {
            icon = ND_I_OK;
            color = ND_C_GREEN;
        }
        else if (cpu_total < 66.67) {
            icon = ND_I_WARN;
            color = ND_C_YELLOW;
        }
        else {
            icon = ND_I_FAIL;
            color = ND_C_RED;
        }

        fprintf(stderr,
            "%s%s%s CPU utilization (user + system): %s%.1f%%%s\n",
            color, icon, ND_C_RESET, color, cpu_total, ND_C_RESET);
        fprintf(stderr,
            "%s%s%s CPU time (user / system): %.1fs / %.1fs\n",
            color, icon, ND_C_RESET, cpu_user_delta, cpu_system_delta);

#if (defined(_ND_USE_LIBTCMALLOC) && defined(HAVE_GPERFTOOLS_MALLOC_EXTENSION_H)) || \
    (defined(_ND_USE_LIBJEMALLOC) && defined(HAVE_JEMALLOC_JEMALLOC_H))
        fprintf(stderr, "%s%s%s current memory usage: %u kB\n",
            ND_C_GREEN, ND_I_INFO, ND_C_RESET,
            jstatus["tcm_kb"].get<unsigned>()
        );
#endif // _ND_USE_LIBTCMALLOC || _ND_USE_LIBJEMALLOC
        fprintf(stderr, "%s%s%s maximum memory usage: %u kB\n",
            ND_C_GREEN, ND_I_INFO, ND_C_RESET,
            jstatus["maxrss_kb"].get<unsigned>()
        );

        for (auto& i : jstatus["interfaces"].items()) {
            const json& j = i.value();
            const string &iface = i.key();
            double dropped_percent = 0;

            icon = ND_I_FAIL;
            color = ND_C_RED;
            string state = "unknown";

            const char *colors[2] = {
                ND_C_RED, ND_C_RESET
            };

            try {
                auto jstate = j.find("state");

                if (jstate != j.end()) {
                    switch (jstate->get<unsigned>()) {
                    case ndCaptureThread::STATE_INIT:
                        icon = ND_I_WARN;
                        colors[0] = color = ND_C_YELLOW;
                        state = "initializing";
                        break;
                    case ndCaptureThread::STATE_ONLINE:
                        icon = ND_I_OK;
                        colors[0] = color = ND_C_GREEN;
                        state = "online";
                        break;
                    case ndCaptureThread::STATE_OFFLINE:
                        state = "offline";
                        break;
                    default:
                        state = "invalid";
                        break;
                    }
                }

                unsigned pkts = 0, dropped = 0;

                pkts = jstatus["stats"][iface]["raw"].get<unsigned>();
                dropped = jstatus["stats"][iface]["capture_dropped"].get<unsigned>();
                dropped += jstatus["stats"][iface]["queue_dropped"].get<unsigned>();

                if (pkts == 0) {
                    icon = ND_I_WARN;
                    colors[1] = color = ND_C_YELLOW;
                }
                else {
                    dropped_percent =
                        (double)dropped * 100 /
                        (double)pkts;

                    if (dropped_percent > 0.0) {
                        icon = ND_I_WARN;
                        colors[1] = color = ND_C_YELLOW;
                    }
                    else if (dropped_percent > 5.0) {
                        icon = ND_I_FAIL;
                        colors[1] = color = ND_C_RED;
                    }
                }
            }
            catch (...) { }

            fprintf(stderr,
                "%s%s%s %s [%s/%s]: %s%s%s: packets dropped: %s%.01lf%%%s\n",
                color, icon, ND_C_RESET, iface.c_str(),
                j["role"].get<string>().c_str(),
                j["capture_type"].get<string>().c_str(),
                colors[0], state.c_str(), ND_C_RESET,
                colors[1], dropped_percent, ND_C_RESET
            );
        }

        bool dhc_status = jstatus["dhc_status"].get<bool>();
        fprintf(stderr, "%s%s%s DNS hint cache: %s%s%s\n",
            (dhc_status) ? ND_C_GREEN : ND_C_YELLOW,
            (dhc_status) ? ND_I_OK : ND_I_WARN,
            ND_C_RESET,
            (dhc_status) ? ND_C_GREEN : ND_C_YELLOW,
            (dhc_status) ? "enabled" : "disabled",
            ND_C_RESET
        );

        if (dhc_status) {
            fprintf(stderr, "%s%s%s DNS hint cache entries: %u\n",
                ND_C_GREEN, ND_I_INFO, ND_C_RESET,
                jstatus["dhc_size"].get<unsigned>()
            );
        }

        fprintf(stderr, "%s%s%s sink URL: %s\n",
            ND_C_GREEN, ND_I_INFO, ND_C_RESET, ndGC.url_sink);
        fprintf(stderr, "%s%s%s sink services are %s.\n",
            (ndGC_USE_SINK) ? ND_C_GREEN : ND_C_RED,
            (ndGC_USE_SINK) ? ND_I_OK : ND_I_FAIL,
            ND_C_RESET,
            (ndGC_USE_SINK) ? "enabled" : "disabled"
        );

        if (! ndGC_USE_SINK) {
            fprintf(stderr,
                "  To enable sink services, run the following command:\n"
            );
            fprintf(stderr, "  # netifyd --enable-sink\n");
        }

        bool sink_uploads = jstatus["sink_uploads"].get<bool>();
        fprintf(stderr, "%s%s%s sink uploads are %s.\n",
            (sink_uploads) ? ND_C_GREEN : ND_C_RED,
            (sink_uploads) ? ND_I_OK : ND_I_FAIL,
            ND_C_RESET,
            (sink_uploads) ? "enabled" : "disabled"
        );

        if (! sink_uploads) {
            fprintf(stderr,
                "  To enable sink uploads, ensure your Agent has been provisioned.\n"
            );
        }

        string uuid;

        uuid = (ndGC.uuid != NULL) ? ndGC.uuid : "00-00-00-00";
        if (nd_file_exists(ndGC.path_uuid) > 0)
            nd_load_uuid(uuid, ndGC.path_uuid, ND_AGENT_UUID_LEN);

        if (uuid.size() != ND_AGENT_UUID_LEN || uuid == "00-00-00-00") {
            fprintf(stderr, "%s%s%s sink agent UUID is not set.\n",
                ND_C_RED, ND_I_FAIL, ND_C_RESET);
            fprintf(stderr,
                "  To generate a new one, run the following command:\n"
            );
            fprintf(stderr, "  # netifyd --provision\n");
        }
        else {
            fprintf(stderr, "%s%s%s sink agent UUID: %s\n",
                ND_C_GREEN, ND_I_OK, ND_C_RESET, uuid.c_str());
        }

        uuid = (ndGC.uuid_serial != NULL) ? ndGC.uuid_serial : "-";
        if (nd_file_exists(ndGC.path_uuid_serial) > 0)
            nd_load_uuid(uuid, ndGC.path_uuid_serial, ND_AGENT_SERIAL_LEN);

        if (uuid.size() && uuid != "-") {
            fprintf(stderr, "%s%s%s sink serial UUID: %s\n",
                ND_C_GREEN, ND_I_INFO, ND_C_RESET, uuid.c_str());
        }

        uuid = (ndGC.uuid_site != NULL) ? ndGC.uuid_site : "-";
        if (nd_file_exists(ndGC.path_uuid_site) > 0)
            nd_load_uuid(uuid, ndGC.path_uuid_site, ND_SITE_UUID_LEN);

        if (! uuid.size() || uuid == "-") {
            fprintf(stderr, "%s%s%s sink site UUID is not set.\n",
                ND_C_YELLOW, ND_I_WARN, ND_C_RESET);
            fprintf(stderr, "  A new site UUID will be automatically set "
                "after this agent has been provisioned by the sink server.\n");
        }
        else {
            fprintf(stderr, "%s%s%s sink site UUID: %s\n",
                ND_C_GREEN, ND_I_OK, ND_C_RESET, uuid.c_str());
        }

        bool sink_status = jstatus["sink_status"].get<bool>();
        if (sink_status) {
            string status, help;
            icon = ND_I_OK;
            color = ND_C_GREEN;
            unsigned resp_code = jstatus["sink_resp_code"].get<unsigned>();
            switch (resp_code) {
            case ndJSON_RESP_NULL:
                status = "not available";
                icon = ND_I_WARN;
                color = ND_C_YELLOW;
                help = "Sink status not yet available, try again.";
                break;
            case ndJSON_RESP_OK:
                status = "ok";
                break;
            case ndJSON_RESP_AUTH_FAIL:
                status = "authorization failed";
                icon = ND_I_FAIL;
                color = ND_C_YELLOW;
                help = "If no site UUID is set, please provision this agent.";
                break;
            case ndJSON_RESP_MALFORMED_DATA:
                status = "malformed data";
                icon = ND_I_FAIL;
                color = ND_C_RED;
                help = "This should never happen, please contact support.";
                break;
            case ndJSON_RESP_SERVER_ERROR:
                status = "server error";
                icon = ND_I_FAIL;
                color = ND_C_RED;
                help = "Contact support if this error persists.";
                break;
            case ndJSON_RESP_POST_ERROR:
                status = "upload error";
                icon = ND_I_WARN;
                color = ND_C_YELLOW;
                help = "This error should resolve automatically.";
                break;
            case ndJSON_RESP_PARSE_ERROR:
                status = "parse error";
                icon = ND_I_FAIL;
                color = ND_C_RED;
                help = "This should never happen, please contact support.";
                break;
            case ndJSON_RESP_INVALID_RESPONSE:
                status = "invalid response";
                icon = ND_I_FAIL;
                color = ND_C_RED;
                help = "This should never happen, please contact support.";
                break;
            case ndJSON_RESP_INVALID_CONTENT_TYPE:
                status = "invalid response content type";
                icon = ND_I_FAIL;
                color = ND_C_RED;
                help = "This should never happen, please contact support.";
                break;
            default:
                status = "unknown error";
                icon = ND_I_FAIL;
                color = ND_C_RED;
                help = "This should never happen, please contact support.";
                break;
            }

            fprintf(stderr, "%s%s%s sink server status: %s%s (%d)%s\n",
                color, icon, ND_C_RESET, color,
                status.c_str(), resp_code, ND_C_RESET
            );

            if (help.size() > 0)
                fprintf(stderr, "  %s\n", help.c_str());

            double sink_util =
                jstatus["sink_queue_size_kb"].get<double>() * 100 /
                jstatus["sink_queue_max_size_kb"].get<double>();

            if (sink_util < 33.34) {
                icon = ND_I_OK;
                color = ND_C_GREEN;
            }
            else if (sink_util < 66.67) {
                icon = ND_I_WARN;
                color = ND_C_YELLOW;
            }
            else {
                icon = ND_I_FAIL;
                color = ND_C_RED;
            }

            fprintf(stderr,
                "%s%s%s sink queue utilization: %s%.1lf%%%s\n",
                color, icon, ND_C_RESET, color, sink_util, ND_C_RESET);
        }
    }
    catch (runtime_error &e) {
        fprintf(stderr, "%s%s%s agent run-time status exception: %s%s%s\n",
            ND_C_RED, ND_I_FAIL, ND_C_RESET, ND_C_RED, e.what(), ND_C_RESET);
    }

    return true;
}

int ndInstance::Run(void)
{
    if (version.empty()) {
        nd_printf(
            "%s: Instance configuration not initialized.\n",
            tag.c_str()
        );
        exit_code = EXIT_FAILURE;
        return exit_code;
    }

    nd_printf("%s\n", version.c_str());

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
