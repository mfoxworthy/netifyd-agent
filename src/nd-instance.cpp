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
#elif defined(HAVE_MALLOC_TRIM)
#include <malloc.h>
#endif

#include <radix/radix_tree.hpp>

using namespace std;

#include "netifyd.h"

#include "nd-config.h"
#include "nd-signal.h"
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
#include "nd-dhc.h"
#include "nd-fhc.h"
#include "nd-thread.h"
#ifdef _ND_USE_PLUGINS
#include "nd-plugin.h"
#endif
#include "nd-instance.h"
#ifdef _ND_USE_CONNTRACK
#include "nd-conntrack.h"
#endif
#include "nd-detection.h"
#include "nd-capture.h"
#ifdef _ND_USE_LIBPCAP
#include "nd-capture-pcap.h"
#endif
#ifdef _ND_USE_TPACKETV3
#include "nd-capture-tpv3.h"
#endif
#ifdef _ND_USE_NFQUEUE
#include "nd-capture-nfq.h"
#endif
#include "nd-socket.h"
#include "nd-sink.h"
#include "nd-base64.h"
#include "nd-napi.h"

ndInstance *ndInstance::instance = nullptr;

ndInstanceStatus::ndInstanceStatus() :
    cpus(0),
    ts_epoch{ 0, 0 },
    ts_now{ 0, 0 },
    flows(0),
    flows_prev(0),
    cpu_user(0),
    cpu_user_prev(0),
    cpu_system(0),
    cpu_system_prev(0),
    maxrss_kb(0),
    maxrss_kb_prev(0),
#if (defined(_ND_USE_LIBTCMALLOC) && defined(HAVE_GPERFTOOLS_MALLOC_EXTENSION_H))
    tcm_alloc_kb(0),
    tcm_alloc_kb_prev(0),
#endif
    dhc_status(false),
    dhc_size(0),
    sink_uploads(false),
    sink_status(false),
    sink_queue_size(0),
    sink_resp_code(ndJSON_RESP_NULL)
{
    cpus = sysconf(_SC_NPROCESSORS_ONLN);
}

ndInstance::ndInstance(const string &tag)
    : ndThread(tag, -1, true),
    exit_code(EXIT_FAILURE),
    dns_hint_cache(nullptr),
    flow_hash_cache(nullptr),
    flow_buckets(nullptr),
#ifdef _ND_USE_NETLINK
    netlink(nullptr),
#endif
    thread_sink(nullptr),
    thread_socket(nullptr),
    thread_napi(nullptr),
#ifdef _ND_USE_CONNTRACK
    thread_conntrack(nullptr),
#endif
    sig_update(-1), sig_update_napi(-1),
    timer_update(nullptr), timer_update_napi(nullptr),
    tag(tag.empty() ? PACKAGE_TARNAME : tag),
    self(PACKAGE_TARNAME), self_pid(-1),
    conf_filename(ND_CONF_FILE_NAME)
{
    terminate_force = false;
    flows = 0;
}

ndInstance::~ndInstance()
{
    Terminate();

    Join();

    if (timer_update != nullptr)
        timer_delete(timer_update);
    if (ndGC_USE_NAPI && timer_update_napi != nullptr)
        timer_delete(timer_update_napi);

    for (unsigned p = 0; p < 2; p++) {
        if (thread_napi) {
            if (p == 0)
                thread_napi->Terminate();
            else {
                delete thread_napi;
                thread_napi= nullptr;
            }
        }

        if (thread_socket) {
            if (p == 0)
                thread_socket->Terminate();
            else {
                delete thread_socket;
                thread_socket = nullptr;
            }
        }

        if (thread_sink) {
            if (p == 0)
                thread_sink->Terminate();
            else {
                delete thread_sink;
                thread_sink = nullptr;
            }
        }

#ifdef _ND_USE_CONNTRACK
        if (ndGC_USE_CONNTRACK && thread_conntrack) {
            if (p == 0)
                thread_conntrack->Terminate();
            else {
                delete thread_conntrack;
                thread_conntrack = nullptr;
            }
        }
#endif

        for (auto i : thread_detection) {
            if (p == 0)
                i.second->Terminate();
            else
                delete i.second;
        }

        if (p > 0 && thread_detection.size())
            thread_detection.clear();
    }

    if (dns_hint_cache != nullptr) {
        delete dns_hint_cache;
        dns_hint_cache = nullptr;
    }

    if (flow_hash_cache != nullptr) {
        delete flow_hash_cache;
        flow_hash_cache = nullptr;
    }

    if (flow_buckets != nullptr) {
        delete flow_buckets;
        flow_buckets = nullptr;
    }

#ifdef _ND_USE_NETLINK
    if (netlink != nullptr) {
        delete netlink;
        netlink = nullptr;
    }
#endif

    if (this == instance) {
        instance = nullptr;

        curl_global_cleanup();
    }

    if (self_pid > 0 &&
        self_pid == nd_is_running(self_pid, self)) {
        if (unlink(ndGC.path_pid_file.c_str()) != 0) {
            nd_dprintf("%s: unlink: %s: %s\n", tag.c_str(),
                ndGC.path_pid_file.c_str(), strerror(errno)
            );
        }
    }
}

ndInstance& ndInstance::Create(const string &tag) {

    if (instance != nullptr) {
        throw ndSystemException(__PRETTY_FUNCTION__,
            "instance exists", EEXIST
        );
    }

    instance = new ndInstance(tag);

    if (instance == nullptr) {
        throw ndSystemException(__PRETTY_FUNCTION__,
            "new ndInstance", ENOMEM
        );
    }

    return *instance;
}

void ndInstance::Destroy(void)
{
    if (instance == nullptr) {
        throw ndSystemException(__PRETTY_FUNCTION__,
            "instance not found", ENOENT
        );
    }

    delete instance;
}

uint32_t ndInstance::InitializeConfig(int argc, char * const argv[])
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

    if (conf_filename != "/dev/null") {
        if (ndGC.Load(conf_filename) == false)
            return ndCR_LOAD_FAILURE;

        ndGC.Close();
    }

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
            if (ndGC.ca_capture_base > status.cpus) {
                fprintf(stderr,
                    "Capture thread base greater than online cores.\n"
                );
                return ndCR_INVALID_VALUE;
            }
            break;
        case _ND_LO_CA_CONNTRACK:
            ndGC.ca_conntrack = (int16_t)atoi(optarg);
            if (ndGC.ca_conntrack > status.cpus) {
                fprintf(stderr,
                    "Conntrack thread ID greater than online cores.\n"
                );
                return ndCR_INVALID_VALUE;
            }
            break;
        case _ND_LO_CA_DETECTION_BASE:
            ndGC.ca_detection_base = (int16_t)atoi(optarg);
            if (ndGC.ca_detection_base > status.cpus) {
                fprintf(stderr,
                    "Detection thread base greater than online cores.\n"
                );
                return ndCR_INVALID_VALUE;
            }
            break;
        case _ND_LO_CA_DETECTION_CORES:
            ndGC.ca_detection_cores = (int16_t)atoi(optarg);
            if (ndGC.ca_detection_cores > status.cpus) {
                fprintf(stderr,
                    "Detection cores greater than online cores.\n"
                );
                return ndCR_INVALID_VALUE;
            }
            break;
        case _ND_LO_CA_SINK:
            ndGC.ca_sink = (int16_t)atoi(optarg);
            if (ndGC.ca_sink > status.cpus) {
                fprintf(stderr,
                    "Sink thread ID greater than online cores.\n"
                );
                return ndCR_INVALID_VALUE;
            }
            break;
        case _ND_LO_CA_SOCKET:
            ndGC.ca_socket = (int16_t)atoi(optarg);
            if (ndGC.ca_socket > status.cpus) {
                fprintf(stderr,
                    "Socket thread ID greater than online cores.\n"
                );
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
            fprintf(stderr,
                "Sorry, this feature was disabled (embedded).\n"
            );
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
            rc = LookupAddress(optarg);
            return ndCR_Pack(
                ndCR_LOOKUP_ADDR, (rc) ? 0 : 1
            );
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
                return ndCR_Pack(ndCR_HASH_TEST, rc);
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

    // Prepare packet capture interfaces
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
        fprintf(stderr,
            "%s: no packet capture sources configured.\n",
            tag.c_str()
        );
        return ndCR_INVALID_INTERFACES;
    }

    for (auto &i : ndGC.interface_addrs) {
        for (auto &a : i.second)
            addr_types.AddAddress(ndAddr::atLOCAL, a, i.first);
    }

    // Test mode enabled?  Disable/set certain config parameters
    if (ndGC.h_flow != stderr) {
        ndGC_SetFlag(ndGF_USE_FHC, true);
        ndGC_SetFlag(ndGF_USE_SINK, false);
        ndGC_SetFlag(ndGF_EXPORT_JSON, false);
        ndGC_SetFlag(ndGF_REMAIN_IN_FOREGROUND, true);

        ndGC.update_interval = 1;
#ifdef _ND_USE_PLUGINS
        ndGC.plugin_detections.clear();
        ndGC.plugin_sinks.clear();
        ndGC.plugin_stats.clear();
#endif
        ndGC.dhc_save = ndDHC_DISABLED;
        ndGC.fhc_save = ndFHC_DISABLED;
    }

    // Global libCURL initialization
    CURLcode cc;
    if ((cc = curl_global_init(CURL_GLOBAL_ALL)) != 0) {
        fprintf(stderr,
            "%s: Unable to initialize libCURL: %d\n",
            tag.c_str(), cc
        );
        return ndCR_LIBCURL_FAILURE;
    }

    // Hash config file
    nd_sha1_file(
        ndGC.path_app_config, ndGC.digest_app_config
    );
    nd_sha1_file(
        ndGC.path_legacy_config, ndGC.digest_legacy_config
    );

    ndGC.LoadSinkURL();

    // Configuration is valid when version is set
    version = nd_get_version_and_features();

    return ndCR_OK;
}

bool ndInstance::InitializeTimers(
    int sig_update, int sig_update_napi)
{
    this->sig_update = sig_update;
    this->sig_update_napi = sig_update_napi;

    struct sigevent sigev;
    memset(&sigev, 0, sizeof(struct sigevent));
    sigev.sigev_notify = SIGEV_SIGNAL;
    sigev.sigev_signo = sig_update;

    if (timer_create(CLOCK_MONOTONIC, &sigev, &timer_update) < 0) {
        nd_printf("%s: timer_create: %s\n",
            tag.c_str(), strerror(errno)
        );
        return false;
    }

    if (ndGC_USE_NAPI) {
        memset(&sigev, 0, sizeof(struct sigevent));
        sigev.sigev_notify = SIGEV_SIGNAL;
        sigev.sigev_signo = sig_update_napi;

        if (timer_create(
            CLOCK_MONOTONIC, &sigev, &timer_update_napi) < 0) {
            nd_printf("%s: timer_create: %s\n",
                tag.c_str(), strerror(errno)
            );
            exit_code = EXIT_FAILURE;

            timer_delete(timer_update);
            timer_update = nullptr;

            return false;
        }
    }

    return true;
}

bool ndInstance::Daemonize(void)
{
    if (! ndGC_DEBUG && ! ndGC_REMAIN_IN_FOREGROUND) {
        if (daemon(1, 0) != 0) {
            nd_printf("%s: daemon: %s\n",
                tag.c_str(), strerror(errno)
            );
            return false;
        }
    }

    if (! nd_dir_exists(ndGC.path_state_volatile)) {
        if (mkdir(ndGC.path_state_volatile.c_str(), 0755) != 0) {
            nd_printf("%s: error creating volatile state path: %s: %s\n",
                tag.c_str(),
                ndGC.path_state_volatile.c_str(), strerror(errno)
            );
            return false;
        }
    }

    pid_t old_pid = nd_load_pid(ndGC.path_pid_file);

    if (old_pid > 0 &&
        old_pid == nd_is_running(old_pid, self)) {
        nd_printf("%s: an instance is already running: PID %d\n",
            tag.c_str(), old_pid
        );
        return false;
    }

    self_pid = getpid();
    if (nd_save_pid(ndGC.path_pid_file, self_pid) != 0)
        return false;

    return true;
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
    if (! ndGC_DEBUG)
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
        try {
            plugins.Load();

            if (ndGC.plugin_detections.size()) {
                fprintf(stderr, "\nDetection plugins:\n");
                plugins.DumpVersions(ndPlugin::TYPE_DETECTION);
            }

            if (ndGC.plugin_stats.size()) {
                fprintf(stderr, "\nStatistics plugins:\n");
                plugins.DumpVersions(ndPlugin::TYPE_STATS);
            }

            if (ndGC.plugin_sinks.size()) {
                fprintf(stderr, "\nSink plugins:\n");
                plugins.DumpVersions(ndPlugin::TYPE_SINK);
            }
        }
        catch (exception &e) {
            fprintf(stderr,
                "\nError while loading plugins: %s\n", e.what()
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
            "  --lookup-ip <addr>\n    Perform application query by IP address.\n"
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

#if (defined(_ND_USE_LIBTCMALLOC) && defined(HAVE_GPERFTOOLS_MALLOC_EXTENSION_H))
        fprintf(stderr, "%s%s%s current memory usage: %u kB\n",
            ND_C_GREEN, ND_I_INFO, ND_C_RESET,
            jstatus["tcm_kb"].get<unsigned>()
        );
#endif // _ND_USE_LIBTCMALLOC
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
                color, icon, ND_C_RESET,
                color, sink_util, ND_C_RESET
            );
        }
    }
    catch (runtime_error &e) {
        fprintf(stderr,
            "%s%s%s agent run-time status exception: %s%s%s\n",
            ND_C_RED, ND_I_FAIL, ND_C_RESET, ND_C_RED,
            e.what(), ND_C_RESET
        );
    }

    return true;
}

void ndInstance::ProcessUpdate(void)
{
    nd_dprintf("%s: %s\n", tag.c_str(), __PRETTY_FUNCTION__);

    UpdateStatus();

    if (ndGC_USE_DHC && dns_hint_cache != nullptr)
        dns_hint_cache->Purge();
#if !defined(_ND_USE_LIBTCMALLOC) && defined(HAVE_MALLOC_TRIM)
    // Attempt to release heap back to OS when supported
    malloc_trim(0);
#endif
}

void ndInstance::ProcessFlows(void)
{
    nd_dprintf("%s: %s\n", tag.c_str(), __PRETTY_FUNCTION__);

    uint32_t now = time(NULL);
    size_t purged = 0, expiring = 0, expired = 0, active = 0, total = 0, blocked = 0;
#ifdef _ND_PROCESS_FLOW_DEBUG
    size_t tcp = 0, tcp_fin = 0, tcp_fin_ack_1 = 0, tcp_fin_ack_gt2 = 0, tickets = 0;
#endif
    bool add_flows = (ndGC_USE_SINK || ndGC_EXPORT_JSON);
    bool socket_queue = (thread_socket && thread_socket->GetClientCount());

    //flow_buckets->DumpBucketStats();

    size_t buckets = flow_buckets->GetBuckets();

    for (size_t b = 0; b < buckets; b++) {
        nd_flow_map *fm = flow_buckets->Acquire(b);
        nd_flow_map::const_iterator i = fm->begin();

        total += fm->size();
        status.flows += fm->size();

        while (i != fm->end()) {
#ifdef _ND_PROCESS_FLOW_DEBUG
            if (i->second->ip_protocol == IPPROTO_TCP) tcp++;
            if (i->second->ip_protocol == IPPROTO_TCP &&
                i->second->flags.tcp_fin.load()) tcp_fin++;
            if (i->second->ip_protocol == IPPROTO_TCP &&
                i->second->flags.tcp_fin.load() && i->second->flags.tcp_fin_ack.load() == 1) tcp_fin_ack_1++;
            if (i->second->ip_protocol == IPPROTO_TCP &&
                i->second->flags.tcp_fin.load() && i->second->flags.tcp_fin_ack.load() >= 2) tcp_fin_ack_gt2++;
            if (i->second->tickets.load() > 0) tickets++;
#endif
            if (i->second->flags.expired.load() == false) {

                uint32_t ttl = ((i->second->ip_protocol != IPPROTO_TCP) ?
                    ndGC.ttl_idle_flow : (
                        (i->second->flags.tcp_fin_ack.load() >= 2) ?
                            ndGC.ttl_idle_flow : ndGC.ttl_idle_tcp_flow
                    )
                );

                if ((i->second->ts_last_seen / 1000) + ttl < now) {

                    if (i->second->flags.detection_complete.load() == true)
                        i->second->flags.expired = true;
                    else if (i->second->flags.expiring.load() == false) {

                        expiring++;

                        ExpireFlow(i->second);

                        auto it = thread_detection.find(i->second->dpi_thread_id);
                        if (it != thread_detection.end())
                            it->second->QueuePacket(i->second);
                        else
                            i->second->flags.expired = true;
                    }
                }
            }

            if (i->second->flags.expired.load() == true) {

                expired++;

                if (i->second->tickets.load() == 0) {

                    if (add_flows &&
                        (ndGC_UPLOAD_NAT_FLOWS || i->second->flags.ip_nat.load() == false)) {

                        json jf;
                        i->second->encode<json>(jf);

                        string iface_name;
                        nd_iface_name(i->second->iface.ifname, iface_name);

                        // TODO: jflows[iface_name].push_back(jf);
                    }

                    if (socket_queue) {

                        if (ndGC_FLOW_DUMP_UNKNOWN &&
                            i->second->detected_protocol == ND_PROTO_UNKNOWN) {

                            json j, jf;

                            j["type"] = "flow";
                            j["interface"] = i->second->iface.ifname;
                            j["internal"] = (i->second->iface.role == ndIR_LAN);
                            j["established"] = false;

                            i->second->encode<json>(
                                jf, ndFlow::ENCODE_METADATA
                            );
                            j["flow"] = jf;

                            string json_string;
                            nd_json_to_string(j, json_string, false);
                            json_string.append("\n");

                            thread_socket->QueueWrite(json_string);
                        }

                        if (ndGC_FLOW_DUMP_UNKNOWN ||
                            i->second->detected_protocol != ND_PROTO_UNKNOWN) {

                            json j, jf;

                            j["type"] = "flow_purge";
                            j["reason"] = (
                                i->second->ip_protocol == IPPROTO_TCP &&
                                i->second->flags.tcp_fin.load()
                            ) ? "closed" : (ShouldTerminate()) ? "terminated" : "expired";
                            j["interface"] = i->second->iface.ifname;
                            j["internal"] = (i->second->iface.role == ndIR_LAN);
                            j["established"] = false;

                            i->second->encode<json>(
                                jf, ndFlow::ENCODE_STATS | ndFlow::ENCODE_TUNNELS
                            );
                            j["flow"] = jf;

                            string json_string;
                            nd_json_to_string(j, json_string, false);
                            json_string.append("\n");

                            thread_socket->QueueWrite(json_string);
                        }
                    }

                    delete i->second;
                    i = fm->erase(i);

                    purged++;
                    flows--;

                    continue;
                }
                else {
                    if (blocked == 0) {
                        nd_dprintf("%s: flow purge blocked by %lu tickets.\n",
                            i->second->iface.ifname.c_str(), i->second->tickets.load());
                    }

                    blocked++;
                }
            }
            else {
                if (i->second->flags.detection_init.load()) {

                    if (add_flows && i->second->ts_first_update &&
                        (ndGC_UPLOAD_NAT_FLOWS || i->second->flags.ip_nat.load() == false)) {

                        json jf;
                        i->second->encode<json>(jf);

                        string iface_name;
                        nd_iface_name(i->second->iface.ifname, iface_name);

                        // TODO: jflows[iface_name].push_back(jf);

                        if (socket_queue) {
                            json j;

                            j["type"] = "flow_stats";
                            j["interface"] = i->second->iface.ifname;
                            j["internal"] = (i->second->iface.role == ndIR_LAN);
                            j["established"] = false;

                            jf.clear();
                            i->second->encode<json>(
                                jf, ndFlow::ENCODE_STATS | ndFlow::ENCODE_TUNNELS
                            );
                            j["flow"] = jf;

                            string json_string;
                            nd_json_to_string(j, json_string, false);
                            json_string.append("\n");

                            thread_socket->QueueWrite(json_string);
                        }
                    }

                    i->second->reset();

                    active++;
                }
            }

            i++;
        }

        flow_buckets->Release(b);
    }

    nd_dprintf(
        "Purged %lu of %lu flow(s), active: %lu, expiring: %lu, expired: %lu, "
        "idle: %lu, blocked: %lu\n",
        purged, total, active, expiring, expired, total - active, blocked
    );
#ifdef _ND_PROCESS_FLOW_DEBUG
    nd_dprintf("TCP: %lu, TCP+FIN: %lu, TCP+FIN+ACK1: %lu, TCP+FIN+ACK>=2: %lu, tickets: %lu\n",
        tcp, tcp_fin, tcp_fin_ack_1, tcp_fin_ack_gt2, tickets
    );
#endif
}

int ndInstance::Run(void)
{
    if (version.empty()) {
        nd_printf(
            "%s: Instance configuration not initialized.\n",
            tag.c_str()
        );
        goto ndInstance_RunReturn;
    }

    nd_printf("%s: %s\n", tag.c_str(), version.c_str());
    nd_dprintf("%s: online CPU cores: %ld\n",
        tag.c_str(), status.cpus
    );

    CheckAgentUUID();

    ndpi_global_init();

    ndInterface::UpdateAddrs(interfaces);

    if (ndGC_USE_DHC) {
        dns_hint_cache = new ndDNSHintCache();
        if (dns_hint_cache == nullptr) {
            throw ndSystemException(__PRETTY_FUNCTION__,
                "new ndDNSHintCache", ENOMEM
            );
        }
    }

    if (ndGC_USE_FHC) {
        flow_hash_cache = new ndFlowHashCache(ndGC.max_fhc);
        if (flow_hash_cache == nullptr) {
            throw ndSystemException(__PRETTY_FUNCTION__,
                "new ndFlowHashCache", ENOMEM
            );
        }
    }

    flow_buckets = new ndFlowMap(ndGC.fm_buckets);
    if (flow_buckets == nullptr) {
        throw ndSystemException(__PRETTY_FUNCTION__,
            "new ndFlowMap", ENOMEM
        );
    }

#ifdef _ND_USE_NETLINK
    if (ndGC_USE_NETLINK) {
        netlink = new ndNetlink();
        if (netlink == nullptr) {
            throw ndSystemException(__PRETTY_FUNCTION__,
                "new ndNetlink", ENOMEM
            );
        }
    }
#endif

    try {
#ifdef _ND_USE_CONNTRACK
        if (ndGC_USE_CONNTRACK) {
            thread_conntrack = new ndConntrackThread(ndGC.ca_conntrack);
            thread_conntrack->Create();
        }
#endif
#ifdef _ND_USE_PLUGINS
        plugins.Load();
#endif
        if (ndGC_USE_SINK) {
            thread_sink = new ndSinkThread(ndGC.ca_sink);
            thread_sink->Create();
        }

        if (ndGC.socket_host.size() || ndGC.socket_path.size()) {
            thread_socket = new ndSocketThread(ndGC.ca_socket);
            thread_socket->Create();
        }

        int16_t cpu = (
                ndGC.ca_detection_base > -1 &&
                ndGC.ca_detection_base < (int16_t)status.cpus
        ) ? ndGC.ca_detection_base : 0;
        int16_t cpus = (
                ndGC.ca_detection_cores > (int16_t)status.cpus
                || ndGC.ca_detection_cores <= 0
        ) ? (int16_t)status.cpus : ndGC.ca_detection_cores;

        for (int16_t i = 0; i < cpus; i++) {

            thread_detection[i] = new ndDetectionThread(
                cpu,
                string("dpi") + to_string(cpu),
#ifdef _ND_USE_NETLINK
                netlink,
#endif
                thread_socket,
#ifdef _ND_USE_CONNTRACK
                (! ndGC_USE_CONNTRACK) ? nullptr : thread_conntrack,
#endif
#ifdef _ND_USE_PLUGINS
                nullptr, // TODO: &plugin_detections,
#endif
                dns_hint_cache,
                flow_hash_cache,
                (uint8_t)cpu
            );

            thread_detection[i]->Create();

            if (++cpu == cpus) cpu = 0;
        }
    }
    catch (ndSinkThreadException &e) {
        nd_printf("%s: Fatal sink thread exception: %s\n",
            tag.c_str(), e.what()
        );
        goto ndInstance_RunReturn;
    }
    catch (ndSocketException &e) {
        nd_printf("%s: Fatal socket exception: %s\n",
            tag.c_str(), e.what()
        );
        goto ndInstance_RunReturn;
    }
    catch (ndSocketThreadException &e) {
        nd_printf("%s: Fatal socket thread exception: %s\n",
            tag.c_str(), e.what()
        );
        goto ndInstance_RunReturn;
    }
    catch (ndSocketSystemException &e) {
        nd_printf("%s: Fatal system exception: %s\n",
            tag.c_str(), e.what()
        );
        goto ndInstance_RunReturn;
    }
#ifdef _ND_USE_CONNTRACK
    catch (ndConntrackThreadException &e) {
        nd_printf("%s: Fatal conntrack thread exception: %s\n",
            tag.c_str(), e.what()
        );
        goto ndInstance_RunReturn;
    }
#endif
#ifdef _ND_USE_PLUGINS
    catch (ndPluginException &e) {
        nd_printf("%s: Fatal plugin exception: %s\n",
            tag.c_str(), e.what()
        );
        goto ndInstance_RunReturn;
    }
#endif
    catch (ndThreadException &e) {
        nd_printf("%s: Fatal thread exception: %s\n",
            tag.c_str(), e.what()
        );
        goto ndInstance_RunReturn;
    }
    catch (exception &e) {
        nd_printf("%s: Fatal exception: %s\n",
            tag.c_str(), e.what()
        );
        goto ndInstance_RunReturn;
    }

    if (clock_gettime(
        CLOCK_MONOTONIC_RAW, &status.ts_epoch) != 0) {
        nd_printf(
            "%s: error getting epoch time: %s\n",
            tag.c_str(), strerror(errno)
        );
        goto ndInstance_RunReturn;
    }

    try {
        ndThread::Create();
        exit_code = EXIT_SUCCESS;
    }
    catch (exception &e) {
        exit_code = EXIT_FAILURE;
        nd_dprintf("%s: exception: %s\n", tag.c_str(), e.what());
    }

ndInstance_RunReturn:
    return exit_code;
}

void *ndInstance::ndInstance::Entry(void)
{
    nd_capture_threads thread_capture;

    // Process an initial update on start-up
    ProcessUpdate();

    if (ndGC_USE_NETLINK) {
        try {
#ifdef _ND_USE_NETLINK
        netlink->Refresh();
#endif
        }
        catch (exception &e) {
            nd_printf("%s: exception while refreshing Netlink: %s\n",
                tag.c_str(), e.what()
            );
            exit_code = EXIT_FAILURE;
            goto ndInstance_EntryReturn;
        }
    }

    try {
        // Create and start capture threads
        if (! CreateCaptureThreads(thread_capture))
            return nullptr;
    }
    catch (exception &e) {
        nd_printf(
            "%s: exception while starting capture threads: %s\n",
            tag.c_str(), e.what()
        );
        exit_code = EXIT_FAILURE;
        goto ndInstance_EntryReturn;
    }

    if (timer_update != nullptr) {
        struct itimerspec itspec;
        itspec.it_value.tv_sec = ndGC.update_interval;
        itspec.it_value.tv_nsec = 0;
        itspec.it_interval.tv_sec = ndGC.update_interval;
        itspec.it_interval.tv_nsec = 0;

        timer_settime(timer_update, 0, &itspec, nullptr);
    }

    if (ndGC_USE_NAPI && timer_update_napi != nullptr) {
        time_t ttl = 3; // Delay first signal...
        if (categories.GetLastUpdate() > 0) {
            time_t age = time(NULL) - categories.GetLastUpdate();
            if (age < ndGC.ttl_napi_update)
                ttl = ndGC.ttl_napi_update - age;
            else if (age == ndGC.ttl_napi_update)
                ttl = ndGC.ttl_napi_update;
        }

        struct itimerspec itspec;
        itspec.it_value.tv_sec = ttl;
        itspec.it_value.tv_nsec = 0;
        itspec.it_interval.tv_sec = ndGC.ttl_napi_update;
        itspec.it_interval.tv_nsec = 0;

        timer_settime(timer_update_napi, 0, &itspec, nullptr);
    }

    do {
        int ipc = ndIPC_NONE;

        switch ((ipc = WaitForIPC(1))) {
        case ndIPC_NONE:
            break;
        case ndIPC_NETLINK_IO:
            nd_dprintf(
                "%s: received IPC: [%d] %s\n",
                tag.c_str(), ipc, "Netlink data available"
            );
#ifdef _ND_USE_NETLINK
            if (ndGC_USE_NETLINK && netlink != nullptr)
                netlink->ProcessEvent();
#endif
            break;
        case ndIPC_RELOAD:
            nd_dprintf(
                "%s: received IPC: [%d] %s\n",
                tag.c_str(), ipc, "Reload run-time configuration"
            );
            Reload();
            break;
        case ndIPC_TERMINATE:
            Terminate();
            exit_code = EXIT_SUCCESS;
            break;
        case ndIPC_UPDATE:
            nd_dprintf("%s: received IPC: [%d] %s\n",
                tag.c_str(), ipc, "Update");
            ProcessUpdate();
            ProcessFlows();
            break;
        case ndIPC_UPDATE_NAPI:
            nd_dprintf(
                "%s: received IPC: [%d] %s\n",
                tag.c_str(), ipc, "Netify API update"
            );
            if (ndGC_USE_NAPI && thread_napi == NULL) {
                thread_napi = new ndNetifyApiThread();
                thread_napi->Create();
            }
            break;
        case ndIPC_UPDATE_NAPI_DONE:
            nd_dprintf(
                "%s: received IPC: [%d] %s\n",
                tag.c_str(), ipc, "Netify API update complete"
            );
            Reload();
            if (thread_napi != nullptr) {
                delete thread_napi;
                thread_napi = nullptr;
#ifdef _ND_USE_PLUGINS
            plugins.BroadcastEvent(
                ndPlugin::TYPE_BASE,
                ndPlugin::EVENT_CATEGORIES_UPDATE
            );
#endif
            }
            break;
        default:
            nd_dprintf(
                "%s: received IPC: [%d] %s\n",
                tag.c_str(), ipc, "Ignored"
            );
        }

        size_t threads = thread_capture.size();

        for (auto &it : thread_capture) {
            for (auto &it_instance : it.second) {
                if (it_instance->HasTerminated()) threads--;
            }
        }

        if (threads == 0) {
            nd_printf("Exiting, no active capture threads.\n");
            Terminate();
            exit_code = EXIT_SUCCESS;
        }

        plugins.Reap();

        nd_dprintf("%s: tick\n", tag.c_str());
    }
    while (! ShouldTerminate());

ndInstance_EntryReturn:
    Terminate();

    DestroyCaptureThreads(thread_capture);

    if (exit_code == 0)
        nd_dprintf("%s: normal exit.\n", tag.c_str());
    else {
        nd_dprintf("%s: exit on error: %d\n",
            tag.c_str(), exit_code
        );
    }

    return nullptr;
}

bool ndInstance::Reload(void)
{
    bool result = true;

    nd_dprintf("%s: reloading configuration...\n", tag.c_str());

    if (! (result = apps.Load(ndGC.path_app_config)))
        result = apps.LoadLegacy(ndGC.path_legacy_config);

    result = categories.Load();
    if (ndGC_LOAD_DOMAINS) result = domains.Load();

#ifdef _ND_USE_PLUGINS
    //nd_plugin_event(ndPlugin::EVENT_RELOAD);
#endif

    nd_dprintf("%s: configuration reloaded %s.\n", tag.c_str(),
        (result) ? "successfully" : "with errors");

    return result;
}

bool ndInstance::CreateCaptureThreads(nd_capture_threads &threads)
{
    if (threads.size() != 0) {
        nd_printf("%s: capture threads already created.\n",
            tag.c_str()
        );
        return false;
    }

    uint8_t private_addr = 0;
    vector<ndCaptureThread *> thread_group;

    int16_t cpu = (
            ndGC.ca_capture_base > -1 &&
            ndGC.ca_capture_base < (int16_t)status.cpus
    ) ? ndGC.ca_capture_base : 0;

    for (auto &it : interfaces) {

        switch (it.second.capture_type) {
        case ndCT_PCAP:
        {
            ndCapturePcap *thread = new ndCapturePcap(
                (interfaces.size() > 1) ? cpu++ : -1,
                it.second,
                thread_socket,
                thread_detection,
                dns_hint_cache,
                (it.second.role == ndIR_LAN) ? 0 : ++private_addr
            );

            thread_group.push_back(thread);
            break;
        }
#if defined(_ND_USE_TPACKETV3)
        case ndCT_TPV3:
        {
            unsigned instances = it.second.config.tpv3->fanout_instances;
            if (it.second.config.tpv3->fanout_mode == ndFOM_DISABLED ||
                it.second.config.tpv3->fanout_instances < 2)
                instances = 1;

            for (unsigned i = 0; i < instances; i++) {

                ndCaptureTPv3 *thread = new ndCaptureTPv3(
                    (instances > 1) ? cpu++ : -1,
                    it.second,
                    thread_socket,
                    thread_detection,
                    dns_hint_cache,
                    (it.second.role == ndIR_LAN) ? 0 : ++private_addr
                );

                thread_group.push_back(thread);

                if (cpu == (int16_t)status.cpus) cpu = 0;
            }

            break;
        }
#endif
#if defined(_ND_USE_NFQUEUE)
        case ndCT_NFQ:
        {
            unsigned instances = it.second.config.nfq->instances;
            if (it.second.config.nfq->instances == 0)
                instances = 1;

            for (unsigned i = 0; i < instances; i++) {

                ndCaptureNFQueue *thread = new ndCaptureNFQueue(
                    (instances > 1) ? cpu++ : -1,
                    it.second,
                    thread_socket,
                    thread_detection,
                    i, // instance_id
                    dns_hint_cache,
                    (it.second.role == ndIR_LAN) ? 0 : ++private_addr
                );

                thread_group.push_back(thread);

                if (cpu == (int16_t)status.cpus) cpu = 0;
            }

            break;
        }
#endif
        default:
            nd_printf("%s: WARNING: Unsupported capture type: %s: %hu",
                tag.c_str(),
                it.second.ifname.c_str(), it.second.capture_type
            );
        }

        if (! thread_group.size()) continue;

        threads[it.second.ifname] = thread_group;

        thread_group.clear();

        if (cpu == (int16_t)status.cpus) cpu = 0;
    }

    if (thread_socket != nullptr && ndGC_WAIT_FOR_CLIENT) {
        nd_dprintf("%s: waiting for a client to connect...\n",
            tag.c_str()
        );
        do {
            if (WaitForIPC(1) == ndIPC_TERMINATE) {
                Terminate();
                exit_code = EXIT_SUCCESS;
                return false;
            }

            sleep(1);
        }
        while (
            ! ShouldTerminate() && ! thread_socket->GetClientCount()
        );
    }

    for (auto &it : threads) {
        for (auto &it_instance : it.second)
            it_instance->Create();
    }

    return true;
}

void ndInstance::DestroyCaptureThreads(nd_capture_threads &threads)
{
    for (auto &it : threads) {
        for (auto &it_instance : it.second) {
            it_instance->Terminate();
            delete it_instance;
        }
    }

    threads.clear();

    size_t buckets = flow_buckets->GetBuckets();

    for (size_t b = 0; b < buckets; b++) {
        nd_flow_map *fm = flow_buckets->Acquire(b);

        for (auto it = fm->begin(); it != fm->end(); it++) {
            if (it->second->flags.expiring.load() == false) {
                it->second->flags.expiring = true;
                ExpireFlow(it->second);
                thread_detection[it->second->dpi_thread_id]->
                    QueuePacket(it->second);
            }
        }

        flow_buckets->Release(b);
    }
}

int ndInstance::WaitForIPC(int timeout)
{
    int rc;
    int ipc = 0;
    fd_set fds_read;

    do {
        FD_ZERO(&fds_read);
        FD_SET(fd_ipc[IPC_PE_READ], &fds_read);

        struct timeval tv = { 1, 0 };

        rc = select(
            fd_ipc[IPC_PE_READ] + 1, &fds_read, NULL, NULL, &tv
        );

        if (rc == -1) {
            throw ndSystemException(__PRETTY_FUNCTION__,
                "select", errno
            );
        }

        if (rc > 0) {
            if (! FD_ISSET(fd_ipc[IPC_PE_READ], &fds_read)) {
                throw ndSystemException(__PRETTY_FUNCTION__,
                    "select returned invalid descriptor", EINVAL
                );
            }

            ipc = (int)RecvIPC();
            break;
        }
    }
    while (! ShouldTerminate() && timeout < 0 && --timeout != 0);

    return ipc;
}

void ndInstance::UpdateStatus(void)
{
#if defined(_ND_USE_LIBTCMALLOC) && defined(HAVE_GPERFTOOLS_MALLOC_EXTENSION_H)
    size_t tcm_alloc_bytes = 0;

    // Force tcmalloc to free unused memory
    MallocExtension::instance()->ReleaseFreeMemory();
    MallocExtension::instance()->
        GetNumericProperty("generic.current_allocated_bytes", &tcm_alloc_bytes);
    status.tcm_alloc_kb_prev = status.tcm_alloc_kb;
    status.tcm_alloc_kb = tcm_alloc_bytes / 1024;
#endif
    struct rusage rusage_data;
    getrusage(RUSAGE_SELF, &rusage_data);

    status.cpu_user_prev = status.cpu_user;
    status.cpu_user = (double)rusage_data.ru_utime.tv_sec +
        ((double)rusage_data.ru_utime.tv_usec / 1000000.0);
    status.cpu_system_prev = status.cpu_system;
    status.cpu_system = (double)rusage_data.ru_stime.tv_sec +
        ((double)rusage_data.ru_stime.tv_usec / 1000000.0);

    status.maxrss_kb_prev = status.maxrss_kb;
    status.maxrss_kb = rusage_data.ru_maxrss;

    status.flows_prev = status.flows;
    status.flows = 0;

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &status.ts_now) != 0)
        memcpy(&status.ts_now, &status.ts_epoch, sizeof(struct timespec));

    if (ndGC_USE_DHC) {
        status.dhc_status = true;
        status.dhc_size = dns_hint_cache->GetSize();
    }
    else
        status.dhc_status = false;

    if (thread_sink == NULL)
        status.sink_status = false;
    else {
        status.sink_status = true;
        status.sink_queue_size = thread_sink->QueuePendingSize();
    }
}

void ndInstance::DisplayDebugScoreboard(void)
{
}

void ndInstance::ExpireFlow(ndFlow *flow)
{
    flow->flags.expiring = true;
#ifdef _ND_USE_PLUGINS
    plugins.BroadcastDetectionEvent(
        ndPluginDetection::EVENT_EXPIRING, flow
    );
#endif
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
