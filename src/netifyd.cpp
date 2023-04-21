// Netify Agent 🥷
// Copyright (C) 2015-2022 eGloo Incorporated <http://www.egloo.ca>
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
#include "nd-base64.h"
#include "nd-napi.h"

//static string nd_self;
//static nd_capture_threads capture_threads;
//static nd_detection_threads detection_threads;
//static ndPacketStats pkt_totals;
#ifdef _ND_USE_PLUGINS
//static nd_plugins plugin_detections;
//static nd_plugins plugin_stats;
#endif

//extern ndInterfaces nd_interfaces;
//extern ndFlowMap *nd_flow_buckets;
//extern ndApplications *nd_apps;
//extern ndCategories *nd_categories;
//extern ndDomains *nd_domains;
//extern ndAddrType *nd_addrtype;
//extern atomic_uint nd_flow_count;
//extern nd_agent_stats nd_json_agent_stats;
#ifdef _ND_USE_NETLINK
//extern ndNetlink *netlink;
//extern nd_netlink_device nd_netlink_devices;
#endif

#if 0
static void nd_print_stats(void)
{
#ifndef _ND_LEAN_AND_MEAN
    string uptime;
    nd_uptime(nd_json_agent_stats.ts_now.tv_sec - nd_json_agent_stats.ts_epoch.tv_sec, uptime);

    nd_dprintf("\n");
    nd_dprintf("Cumulative Packet Totals [Uptime: %s]:\n",
        uptime.c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.raw, false);
    nd_dprintf("%12s: %s ", "Wire", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.eth, false);
    nd_dprintf("%12s: %s ", "ETH", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.vlan, false);
    nd_dprintf("%12s: %s\n", "VLAN", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.ip, false);
    nd_dprintf("%12s: %s ", "IP", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.ip4, false);
    nd_dprintf("%12s: %s ", "IPv4", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.ip6, false);
    nd_dprintf("%12s: %s\n", "IPv6", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.icmp + pkt_totals.pkt.igmp, false);
    nd_dprintf("%12s: %s ", "ICMP/IGMP", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.udp, false);
    nd_dprintf("%12s: %s ", "UDP", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.tcp, false);
    nd_dprintf("%12s: %s\n", "TCP", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.mpls, false);
    nd_dprintf("%12s: %s ", "MPLS", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.pppoe, false);
    nd_dprintf("%12s: %s\n", "PPPoE", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.frags, false);
    nd_dprintf("%12s: %s ", "Frags", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.discard, false);
    nd_dprintf("%12s: %s ", "Discarded", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.maxlen);
    nd_dprintf("%12s: %s\n", "Largest", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.capture_filtered, false);
    nd_dprintf("%12s: %s ", "Filtered", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.capture_dropped, false);
    nd_dprintf("%12s: %s", "Dropped", (*nd_stats_os).str().c_str());

    double pkt_loss = (
        ((double)pkt_totals.pkt.discard + (double)pkt_totals.pkt.capture_dropped) * 100)
        / (double)pkt_totals.pkt.raw;

    nd_print_percent(*nd_stats_os, pkt_loss);
    nd_dprintf("%13s: %s\n", "Loss", (*nd_stats_os).str().c_str());

    nd_dprintf("\nCumulative Byte Totals:\n");

    nd_print_number(*nd_stats_os, pkt_totals.pkt.wire_bytes);
    nd_dprintf("%12s: %s\n", "Wire", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.ip_bytes);
    nd_dprintf("%12s: %s ", "IP", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.ip4_bytes);
    nd_dprintf("%12s: %s ", "IPv4", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.ip6_bytes);
    nd_dprintf("%12s: %s\n", "IPv6", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.discard_bytes);
    nd_dprintf("%39s: %s ", "Discarded", (*nd_stats_os).str().c_str());

    (*nd_stats_os).str("");
    (*nd_stats_os) << setw(8) << nd_json_agent_stats.flows;

    nd_dprintf("%12s: %s (%s%d)", "Flows", (*nd_stats_os).str().c_str(),
        (nd_json_agent_stats.flows > nd_json_agent_stats.flows_prev) ? "+" : "",
        int(nd_json_agent_stats.flows - nd_json_agent_stats.flows_prev));

    nd_dprintf("\n\n");
#endif // _ND_LEAN_AND_MEAN
}
#endif

#if 0
static void nd_dump_stats(void)
{
#if defined(_ND_USE_LIBTCMALLOC) && defined(HAVE_GPERFTOOLS_MALLOC_EXTENSION_H)
    size_t tcm_alloc_bytes = 0;

    // Force tcmalloc to free unused memory
    MallocExtension::instance()->ReleaseFreeMemory();
    MallocExtension::instance()->
        GetNumericProperty("generic.current_allocated_bytes", &tcm_alloc_bytes);
    nd_json_agent_stats.tcm_alloc_kb_prev = nd_json_agent_stats.tcm_alloc_kb;
    nd_json_agent_stats.tcm_alloc_kb = tcm_alloc_bytes / 1024;
#endif
    struct rusage rusage_data;
    getrusage(RUSAGE_SELF, &rusage_data);

    nd_json_agent_stats.cpu_user_prev = nd_json_agent_stats.cpu_user;
    nd_json_agent_stats.cpu_user = (double)rusage_data.ru_utime.tv_sec +
        ((double)rusage_data.ru_utime.tv_usec / 1000000.0);
    nd_json_agent_stats.cpu_system_prev = nd_json_agent_stats.cpu_system;
    nd_json_agent_stats.cpu_system = (double)rusage_data.ru_stime.tv_sec +
        ((double)rusage_data.ru_stime.tv_usec / 1000000.0);

    nd_json_agent_stats.maxrss_kb_prev = nd_json_agent_stats.maxrss_kb;
    nd_json_agent_stats.maxrss_kb = rusage_data.ru_maxrss;

    nd_json_agent_stats.flows_prev = nd_json_agent_stats.flows;
    nd_json_agent_stats.flows = 0;

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &nd_json_agent_stats.ts_now) != 0)
        memcpy(&nd_json_agent_stats.ts_now, &nd_json_agent_stats.ts_epoch, sizeof(struct timespec));

    if (ndGC_USE_DHC) {
        nd_json_agent_stats.dhc_status = true;
        nd_json_agent_stats.dhc_size = dns_hint_cache->GetSize();
    }
    else
        nd_json_agent_stats.dhc_status = false;

#ifdef _ND_USE_PLUGINS
    for (nd_plugins::iterator pi = plugin_stats.begin();
        pi != plugin_stats.end(); pi++) {
        ndPluginStats *p = reinterpret_cast<ndPluginStats *>(
            pi->second->GetPlugin()
        );
        p->ProcessStats(ndPluginStats::INIT);
    }
#endif

    json jstatus;
    string json_string;
    nd_json_agent_status(jstatus);
#if 0
#ifdef _ND_USE_PLUGINS
    for (nd_plugins::iterator pi = plugin_stats.begin();
        pi != plugin_stats.end(); pi++) {
        ndPluginStats *p = reinterpret_cast<ndPluginStats *>(
            pi->second->GetPlugin()
        );
        // p->ProcessStats(...);
    }
#endif
#endif

    json ji, jd;

    ndInterface::UpdateAddrs(nd_interfaces);

    nd_json_add_interfaces(ji);
    jstatus["interfaces"] = ji;
#ifdef _ND_USE_PLUGINS
    for (nd_plugins::iterator pi = plugin_stats.begin();
        pi != plugin_stats.end(); pi++) {
        ndPluginStats *p = reinterpret_cast<ndPluginStats *>(
            pi->second->GetPlugin()
        );
        p->ProcessStats(nd_interfaces);
    }
#endif
    for (auto &it : nd_interfaces)
        it.second.NextEndpointSnapshot();

    nd_json_add_devices(jd);
    jstatus["devices"] = jd;
#ifdef _ND_USE_PLUGINS
    for (nd_plugins::iterator pi = plugin_stats.begin();
        pi != plugin_stats.end(); pi++) {
        ndPluginStats *p = reinterpret_cast<ndPluginStats *>(
            pi->second->GetPlugin()
        );
        p->ProcessStats(nd_interfaces);
    }
#endif
    unordered_map<string, json> jflows;

    for (auto &it : capture_threads) {

        json js, jf;

        string iface_name;
        nd_iface_name(it.first, iface_name);

        jflows[iface_name] = vector<json>();

        ndPacketStats stats;

        for (auto &it_instance : it.second) {

            it_instance->Lock();

            it_instance->GetCaptureStats(stats);

            it_instance->Unlock();
        }

        pkt_totals += stats;
        nd_json_add_stats(js, stats);

#ifdef _ND_USE_PLUGINS
        for (nd_plugins::iterator pi = plugin_stats.begin();
            pi != plugin_stats.end(); pi++) {
            ndPluginStats *p = reinterpret_cast<ndPluginStats *>(
                pi->second->GetPlugin()
            );
            p->ProcessStats(iface_name, stats);
        }
#endif
        jstatus["stats"][iface_name] = js;
        jstatus["interfaces"][iface_name]["state"] = it.second[0]->capture_state.load();
    }
#ifdef _ND_USE_PLUGINS
    for (nd_plugins::iterator pi = plugin_stats.begin();
        pi != plugin_stats.end(); pi++) {
        ndPluginStats *p = reinterpret_cast<ndPluginStats *>(
            pi->second->GetPlugin()
        );
        p->ProcessStats(pkt_totals);
        p->ProcessStats(nd_flow_buckets);
        p->ProcessStats(ndPluginStats::COMPLETE);
    }
#endif
    nd_process_flows(jflows,
        (ndGC_USE_SINKS || ndGC_EXPORT_JSON)
    );

    jstatus["flow_count"] = nd_json_agent_stats.flows;
    jstatus["flow_count_prev"] = nd_json_agent_stats.flows_prev;

    json j = jstatus;

    try {
        jstatus["type"] = "agent_status";
        jstatus["agent_version"] = PACKAGE_VERSION;

        nd_json_to_string(jstatus, json_string);
        json_string.append("\n");

        if (thread_socket)
            thread_socket->QueueWrite(json_string);

        nd_json_save_to_file(json_string, ndGC.path_agent_status);
    }
    catch (runtime_error &e) {
        nd_printf("Error saving Agent status to file: %s\n",
            e.what());
    }

    if (ndGC_USE_SINKS || ndGC_EXPORT_JSON) {
        j["flows"] = jflows;
        nd_json_to_string(j, json_string, ndGC_DEBUG);
    }

    if (ndGC_USE_SINKS && ! nd_terminate) {
        try {
            if (ndGC_UPLOAD_ENABLED)
                thread_sink->QueuePush(json_string);
            else {
                j["version"] = (double)ND_JSON_VERSION;
                j["timestamp"] = time(NULL);
                j["uptime"] = nd_json_agent_stats.ts_now.tv_sec - nd_json_agent_stats.ts_epoch.tv_sec;
                j["ping"] = true;

                nd_json_to_string(j, json_string);
                thread_sink->QueuePush(json_string);
            }
        }
        catch (runtime_error &e) {
            nd_printf("Error pushing JSON payload to upload queue: %s\n", e.what());
        }
    }

    try {
        if (ndGC_EXPORT_JSON)
            nd_json_save_to_file(json_string, ndGC.path_export_json);
    }
    catch (runtime_error &e) {
        nd_printf("Error writing JSON export playload to file: %s: %s\n",
            ndGC.path_export_json.c_str(), e.what());
    }

    if (ndGC_DEBUG)
        nd_print_stats();
}
#endif

int main(int argc, char *argv[])
{
    int rc = 0;
    uint32_t result;

    setlocale(LC_ALL, "");

    openlog(
        PACKAGE_TARNAME,
        LOG_NDELAY | LOG_PID | LOG_PERROR,
        LOG_DAEMON
    );

    nd_seed_rng();

    sigset_t sigset;
    sigfillset(&sigset);

    //sigdelset(&sigset, SIGPROF);
    //sigdelset(&sigset, SIGINT);
    sigdelset(&sigset, SIGQUIT);

    sigprocmask(SIG_BLOCK, &sigset, NULL);

    sigemptyset(&sigset);
    sigaddset(&sigset, ND_SIG_UPDATE);
    sigaddset(&sigset, ND_SIG_UPDATE_NAPI);
    sigaddset(&sigset, SIGHUP);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGIO);
#ifdef SIGPWR
    sigaddset(&sigset, SIGPWR);
#endif
    sigaddset(&sigset, SIGTERM);
    sigaddset(&sigset, SIGUSR1);
    sigaddset(&sigset, SIGUSR2);

    ndInstance& instance = ndInstance::Create();

    result = instance.InitializeConfig(argc, argv);

    if (ndCR_Result(result) != ndInstance::ndCR_OK)
        return ndCR_Code(result);

    if (instance.InitializeTimers() == false)
        return 1;

    instance.Daemonize();

    rc = instance.Run();

    if (rc == 0) {
        struct timespec tspec_sigwait = { 1, 0 };

        while (! instance.HasTerminated()) {
            int sig;
            siginfo_t si;

            if ((sig = sigtimedwait(&sigset, &si, &tspec_sigwait)) < 0) {
                if (errno == EAGAIN || errno == EINTR) continue;

                nd_printf("sigwaitinfo: %s\n", strerror(errno));

                rc = -1;
                instance.Terminate();
                continue;
            }

            if (sig == SIGIO) {
                if (! instance.IsNetlinkDescriptor(si.si_fd))
                    continue;
            }

            instance.SendSignal(sig);
        }
    }

    ndInstance::Destroy();

    return rc;
}
#if 0
int main(int argc, char *argv[])
{
    int rc = 0;
    sigset_t sigset;
    struct sigevent sigev;
    timer_t timer_update, timer_napi;
    struct timespec tspec_sigwait;
    struct itimerspec itspec_update;
    string last_device;
    nd_device_addr device_addresses;
    uint8_t dump_flags = ndDUMP_NONE;

    nd_basename(argv[0], nd_self);

    setlocale(LC_ALL, "");

    ostringstream os;
    nd_stats_os = &os;
#ifdef HAVE_CXX11
    struct nd_numpunct : numpunct<char> {
        string do_grouping() const { return "\03"; }
    };

    locale lc(cout.getloc(), new nd_numpunct);
    os.imbue(lc);
#endif

    openlog(PACKAGE_TARNAME, LOG_NDELAY | LOG_PID | LOG_PERROR, LOG_DAEMON);

    nd_seed_rng();

    nd_flow_count = 0;

    memset(&nd_json_agent_stats, 0, sizeof(nd_agent_stats));
    nd_json_agent_stats.cpus = sysconf(_SC_NPROCESSORS_ONLN);

    static struct option options[] =
    {
        { "config", 1, 0, 'c' },
        { "debug", 0, 0, 'd' },
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

        { "enable-sink", 0, 0, _ND_LO_ENABLE_SINK },
        { "disable-sink", 0, 0, _ND_LO_DISABLE_SINK },

        { "force-reset", 0, 0, _ND_LO_FORCE_RESET },

        { "thread-capture-base", 1, 0, _ND_LO_CA_CAPTURE_BASE },
        { "thread-conntrack", 1, 0, _ND_LO_CA_CONNTRACK },
        { "thread-detection-base", 1, 0, _ND_LO_CA_DETECTION_BASE },
        { "thread-detection-cores", 1, 0, _ND_LO_CA_DETECTION_CORES },
        { "thread-sink", 1, 0, _ND_LO_CA_SINK },
        { "thread-socket", 1, 0, _ND_LO_CA_SOCKET },

        { "wait-for-client", 0, 0, _ND_LO_WAIT_FOR_CLIENT },

        { "dump-all", 0, 0, 'P' },
        { "dump-protos", 0, 0, _ND_LO_DUMP_PROTOS },
        { "dump-protocols", 0, 0, _ND_LO_DUMP_PROTOS },
        { "dump-apps", 0, 0, _ND_LO_DUMP_APPS },
        { "dump-applications", 0, 0, _ND_LO_DUMP_APPS },
        { "dump-category", 1, 0, _ND_LO_DUMP_CAT },
        { "dump-categories", 0, 0, _ND_LO_DUMP_CATS },
        { "dump-risks", 0, 0, _ND_LO_DUMP_RISKS },

        { "dump-sort-by-tag", 0, 0, _ND_LO_DUMP_SORT_BY_TAG },

        { "export-apps", 0, 0, _ND_LO_EXPORT_APPS },

        { "lookup-ip", 1, 0, _ND_LO_LOOKUP_IP },

        { NULL, 0, 0, 0 }
    };

    static const char *flags = { "?A:c:DdE:F:f:hI:i:j:lN:nPpRrS:stT:Uu:Vv" };

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
            nd_conf_filename = strdup(optarg);
            break;
        case 'd':
            ndGC.flags |= ndGF_DEBUG;
            break;
        default:
            break;
        }
    }

    if (nd_conf_filename == NULL)
        nd_conf_filename = strdup(ND_CONF_FILE_NAME);

    if (ndGC.Load(nd_conf_filename) == false)
        return 1;

    ndGC.Close();

    optind = 1;

    while (true) {
        if ((rc = getopt_long(argc, argv, flags,
            options, NULL)) == -1) break;

        switch (rc) {
        case 0:
            break;
        case _ND_LO_ENABLE_SINK:
        case _ND_LO_DISABLE_SINK:
            exit(nd_config_set_option(rc));
        case _ND_LO_FORCE_RESET:
            nd_force_reset();
            exit(0);
        case _ND_LO_CA_CAPTURE_BASE:
            ndGC.ca_capture_base = (int16_t)atoi(optarg);
            if (ndGC.ca_capture_base > nd_json_agent_stats.cpus) {
                fprintf(stderr, "Capture thread base greater than online cores.\n");
                exit(1);
            }
            break;
        case _ND_LO_CA_CONNTRACK:
            ndGC.ca_conntrack = (int16_t)atoi(optarg);
            if (ndGC.ca_conntrack > nd_json_agent_stats.cpus) {
                fprintf(stderr, "Conntrack thread ID greater than online cores.\n");
                exit(1);
            }
            break;
        case _ND_LO_CA_DETECTION_BASE:
            ndGC.ca_detection_base = (int16_t)atoi(optarg);
            if (ndGC.ca_detection_base > nd_json_agent_stats.cpus) {
                fprintf(stderr, "Detection thread base greater than online cores.\n");
                exit(1);
            }
            break;
        case _ND_LO_CA_DETECTION_CORES:
            ndGC.ca_detection_cores = (int16_t)atoi(optarg);
            if (ndGC.ca_detection_cores > nd_json_agent_stats.cpus) {
                fprintf(stderr, "Detection cores greater than online cores.\n");
                exit(1);
            }
            break;
        case _ND_LO_CA_SINK:
            ndGC.ca_sink = (int16_t)atoi(optarg);
            if (ndGC.ca_sink > nd_json_agent_stats.cpus) {
                fprintf(stderr, "Sink thread ID greater than online cores.\n");
                exit(1);
            }
            break;
        case _ND_LO_CA_SOCKET:
            ndGC.ca_socket = (int16_t)atoi(optarg);
            if (ndGC.ca_socket > nd_json_agent_stats.cpus) {
                fprintf(stderr, "Socket thread ID greater than online cores.\n");
                exit(1);
            }
            break;
        case _ND_LO_WAIT_FOR_CLIENT:
            ndGC.flags |= ndGF_WAIT_FOR_CLIENT;
            break;

        case _ND_LO_EXPORT_APPS:
#ifndef _ND_LEAN_AND_MEAN
            exit(nd_export_applications());
#else
            fprintf(stderr, "Sorry, this feature was disabled (embedded).\n");
            exit(1);
#endif
        case _ND_LO_DUMP_SORT_BY_TAG:
            dump_flags |= ndDUMP_SORT_BY_TAG;
            break;

        case _ND_LO_DUMP_PROTOS:
            nd_dump_protocols(ndDUMP_TYPE_PROTOS | dump_flags);
            exit(0);
        case _ND_LO_DUMP_APPS:
            nd_dump_protocols(ndDUMP_TYPE_APPS | dump_flags);
            exit(0);
        case _ND_LO_DUMP_CAT:
            if (strncasecmp("application", optarg, 11) == 0)
                nd_dump_protocols(ndDUMP_TYPE_CAT_APP | dump_flags);
            else if (strncasecmp("protocol", optarg, 8) == 0)
                nd_dump_protocols(ndDUMP_TYPE_CAT_PROTO | dump_flags);
            exit(0);
        case _ND_LO_DUMP_CATS:
            nd_dump_protocols(ndDUMP_TYPE_CATS | dump_flags);
            exit(0);
        case _ND_LO_DUMP_RISKS:
            nd_dump_protocols(ndDUMP_TYPE_RISKS | dump_flags);
            exit(0);
        case _ND_LO_LOOKUP_IP:
#ifndef _ND_LEAN_AND_MEAN
            exit(nd_lookup_ip(optarg));
#else
            fprintf(stderr, "Sorry, this feature was disabled (embedded).\n");
            exit(1);
#endif
        case '?':
            fprintf(stderr, "Try `--help' for more information.\n");
            return 1;
        case 'A':
            if (last_device.size() == 0) {
                fprintf(stderr, "You must specify an interface first (-I/E).\n");
                exit(1);
            }
            ndGC.AddInterfaceAddress(last_device, optarg);
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
            last_device = optarg;
            break;
        case 'F':
            if (last_device.size() == 0) {
                fprintf(stderr, "You must specify an interface first (-I/E).\n");
                exit(1);
            }
            ndGC.AddInterfaceFilter(last_device, optarg);
            break;
        case 'f':
            ndGC.path_legacy_config = optarg;
            break;
        case 'h':
            nd_usage();
        case 'I':
            ndGC.AddInterface(optarg, ndIR_LAN, ndCT_PCAP);
            last_device = optarg;
            break;
        case 'i':
            ndGC.update_interval = atoi(optarg);
            break;
        case 'j':
            ndGC.path_export_json = optarg;
            break;
        case 'l':
            ndGC.flags &= ~ndGF_USE_NETLINK;
            break;
        case 'n':
            ndGC.flags |= ndGF_DEBUG_NDPI;
            break;
        case 'N':
            if (last_device.size() == 0) {
                fprintf(stderr, "You must specify an interface first (-I/E).\n");
                exit(1);
            }
            ndGC.AddInterfacePeer(last_device, optarg);
            break;
        case 'P':
            nd_dump_protocols(ndDUMP_TYPE_ALL | dump_flags);
            exit(0);
        case 'p':
            if (nd_check_agent_uuid() || ndGC.uuid == NULL) return 1;
            printf("Agent UUID: %s\n", ndGC.uuid);
            return 0;
        case 'R':
            ndGC.flags |= ndGF_REMAIN_IN_FOREGROUND;
            break;
        case 'r':
            ndGC.flags |= ndGF_REPLAY_DELAY;
            break;
        case 'S':
#ifndef _ND_LEAN_AND_MEAN
            {
                uint8_t digest[SHA1_DIGEST_LENGTH];

                if (nd_sha1_file(optarg, digest) < 0) return 1;
                else {
                    string sha1;
                    nd_sha1_to_string(digest, sha1);
                    printf("%s\n", sha1.c_str());
                    return 0;
                }
            }
#else
            fprintf(stderr, "Sorry, this feature was disabled (embedded).\n");
            exit(1);
#endif
        case 's':
            nd_status();
            exit(0);
        case 't':
            ndGC.flags &= ~ndGF_USE_CONNTRACK;
            break;
        case 'T':
            if ((ndGC.h_flow = fopen(optarg, "w")) == NULL) {
                fprintf(stderr, "Error while opening test output log: %s: %s\n",
                    optarg, strerror(errno));
                exit(1);
            }
            break;
        case 'U':
            {
                string uuid;
                nd_generate_uuid(uuid);
                printf("%s\n", uuid.c_str());
            }
            exit(0);
        case 'u':
            ndGC.uuid = strdup(optarg);
            break;
        case 'V':
            nd_usage(0, true);
            break;
        case 'v':
            ndGC.flags |= ndGF_VERBOSE;
            break;
        default:
            nd_usage(1);
        }
    }

    nd_printf("%s\n", nd_get_version_and_features().c_str());

    for (auto &r : ndGC.interfaces) {
        for (auto &i : r.second) {
            auto result = nd_interfaces.insert(
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

    if (nd_interfaces.size() == 0) {
        fprintf(stderr, "No capture interfaces defined.\n");
        return 1;
    }

    for (auto &i : ndGC.interface_addrs) {
        for (auto &a : i.second)
            device_addresses.push_back(make_pair(i.first, a));
    }

    {
        string url_sink;
        if (nd_load_sink_url(url_sink)) {
            free(ndGC.url_sink);
            ndGC.url_sink = strdup(url_sink.c_str());
        }
    }

    if (ndGC.h_flow != stderr) {
        // Test mode enabled, disable/set certain config parameters
        ndGC_SetFlag(ndGF_USE_FHC, true);
        ndGC_SetFlag(ndGF_USE_SINKS, false);
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

    CURLcode cc;
    if ((cc = curl_global_init(CURL_GLOBAL_ALL)) != 0) {
        fprintf(stderr, "Unable to initialize libCURL: %d\n", cc);
        return 1;
    }

    if (! ndGC_DEBUG && ! ndGC_REMAIN_IN_FOREGROUND) {
        if (daemon(1, 0) != 0) {
            nd_printf("daemon: %s\n", strerror(errno));
            return 1;
        }
    }

    if (ndGC_USE_DHC)
        dns_hint_cache = new ndDNSHintCache();

    if (ndGC_USE_FHC)
        flow_hash_cache = new ndFlowHashCache(ndGC.max_fhc);

    nd_check_agent_uuid();

    if (! nd_dir_exists(ndGC.path_state_volatile)) {
        if (mkdir(ndGC.path_state_volatile.c_str(), 0755) != 0) {
            nd_printf("Unable to create volatile state directory: %s: %s\n",
                ndGC.path_state_volatile.c_str(), strerror(errno));
            return 1;
        }
    }

    pid_t old_pid = nd_load_pid(ndGC.path_pid_file);

    if (old_pid > 0 &&
        old_pid == nd_is_running(old_pid, nd_self)) {
        nd_printf("An agent is already running: PID %d\n", old_pid);
        return 1;
    }

    if (nd_save_pid(ndGC.path_pid_file, getpid()) != 0) return 1;

    if (clock_gettime(
        CLOCK_MONOTONIC_RAW, &nd_json_agent_stats.ts_epoch) != 0) {
        nd_printf(
            "Error getting epoch time: %s\n", strerror(errno));
        return 1;
    }

    if (dns_hint_cache) dns_hint_cache->Load();
    if (flow_hash_cache) flow_hash_cache->Load();

    nd_sha1_file(
        ndGC.path_app_config, ndGC.digest_app_config
    );
    nd_sha1_file(
        ndGC.path_legacy_config, ndGC.digest_legacy_config
    );

    sigfillset(&sigset);
    //sigdelset(&sigset, SIGPROF);
    //sigdelset(&sigset, SIGINT);
    sigdelset(&sigset, SIGQUIT);
    sigprocmask(SIG_BLOCK, &sigset, NULL);

    sigemptyset(&sigset);
    sigaddset(&sigset, ND_SIG_UPDATE);
    sigaddset(&sigset, ND_SIG_UPDATE_NAPI);
    sigaddset(&sigset, ND_SIG_SINK_REPLY);
    sigaddset(&sigset, ND_SIG_NAPI_UPDATED);
    sigaddset(&sigset, SIGHUP);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGIO);
#ifdef SIGPWR
    sigaddset(&sigset, SIGPWR);
#endif
    sigaddset(&sigset, SIGTERM);
    sigaddset(&sigset, SIGUSR1);
    sigaddset(&sigset, SIGUSR2);

    try {
#ifdef _ND_USE_CONNTRACK
        if (ndGC_USE_CONNTRACK) {
            thread_conntrack = new ndConntrackThread(ndGC.ca_conntrack);
            thread_conntrack->Create();
        }
#endif
        if (ndGC.socket_host.size() || ndGC.socket_path.size())
            thread_socket = new ndSocketThread(ndGC.ca_socket);

        if (ndGC_USE_SINKS) {
            thread_sink = new ndSinkThread(ndGC.ca_sink);
            thread_sink->Create();
        }
    }
    catch (ndSinkThreadException &e) {
        nd_printf("Error starting upload thread: %s\n", e.what());
        return 1;
    }
    catch (ndSocketException &e) {
        nd_printf("Error starting socket thread: %s\n", e.what());
        return 1;
    }
    catch (ndSocketSystemException &e) {
        nd_printf("Error starting socket thread: %s\n", e.what());
        return 1;
    }
    catch (ndSocketThreadException &e) {
        nd_printf("Error starting socket thread: %s\n", e.what());
        return 1;
    }
#ifdef _ND_USE_CONNTRACK
    catch (ndConntrackThreadException &e) {
        nd_printf("Error starting conntrack thread: %s\n", e.what());
        return 1;
    }
#endif
    catch (ndThreadException &e) {
        nd_printf("Error starting thread: %s\n", e.what());
        return 1;
    }
    catch (exception &e) {
        nd_printf("Error starting thread: %s\n", e.what());
        return 1;
    }

    nd_addrtype = new ndAddrType();

    for (auto it : device_addresses) {
        nd_addrtype->AddAddress(
            ndAddr::atLOCAL, it.second, it.first.c_str()
        );
    }

    nd_init();
    ndpi_global_init();

    nd_dprintf("Online CPU cores: %ld\n", nd_json_agent_stats.cpus);

    try {
        if (thread_socket != NULL)
            thread_socket->Create();
    }
    catch (ndThreadException &e) {
        nd_printf("Error starting socket thread: %s\n", e.what());
        return 1;
    }

    if (nd_start_detection_threads() < 0)
        return 1;

    // Always send an update on start-up.
    // XXX: BEFORE capture threads have started.
    nd_dump_stats();

    if (thread_socket == NULL || ! ndGC_WAIT_FOR_CLIENT) {
        if (nd_start_capture_threads() < 0)
            return 1;
    }
    else if (thread_socket != NULL && ndGC_WAIT_FOR_CLIENT) {
        do {
            nd_dprintf("Waiting for a client to connect...\n");
            sleep(1);
        } while (thread_socket->GetClientCount() == 0);

        if (nd_start_capture_threads() < 0)
            return 1;
    }

#ifdef _ND_USE_PLUGINS
    if (nd_plugin_start_detections() < 0)
        return 1;
    if (nd_plugin_start_sinks() < 0)
        return 1;
    if (nd_plugin_start_stats() < 0)
        return 1;
#endif

#ifdef _ND_USE_NETLINK
    if (ndGC_USE_NETLINK) netlink->Refresh();
#endif
    memset(&sigev, 0, sizeof(struct sigevent));
    sigev.sigev_notify = SIGEV_SIGNAL;
    sigev.sigev_signo = ND_SIG_UPDATE;

    if (timer_create(CLOCK_MONOTONIC, &sigev, &timer_update) < 0) {
        nd_printf("timer_create: %s\n", strerror(errno));
        return 1;
    }

    itspec_update.it_value.tv_sec = ndGC.update_interval;
    itspec_update.it_value.tv_nsec = 0;
    itspec_update.it_interval.tv_sec = ndGC.update_interval;
    itspec_update.it_interval.tv_nsec = 0;

    timer_settime(timer_update, 0, &itspec_update, NULL);

    if (ndGC_USE_NAPI) {
        memset(&sigev, 0, sizeof(struct sigevent));
        sigev.sigev_notify = SIGEV_SIGNAL;
        sigev.sigev_signo = ND_SIG_UPDATE_NAPI;

        if (timer_create(CLOCK_MONOTONIC, &sigev, &timer_napi) < 0) {
            nd_printf("timer_create: %s\n", strerror(errno));
            return 1;
        }

        time_t ttl = 3;
        if (nd_categories->GetLastUpdate() > 0) {
            time_t age = time(NULL) - nd_categories->GetLastUpdate();
            if (age < ndGC.ttl_napi_update)
                ttl = ndGC.ttl_napi_update - age;
            else if (age == ndGC.ttl_napi_update)
                ttl = ndGC.ttl_napi_update;
        }

        itspec_update.it_value.tv_sec = ttl;
        itspec_update.it_value.tv_nsec = 0;
        itspec_update.it_interval.tv_sec = ndGC.ttl_napi_update;
        itspec_update.it_interval.tv_nsec = 0;

        timer_settime(timer_napi, 0, &itspec_update, NULL);
    }

    tspec_sigwait.tv_sec = 1;
    tspec_sigwait.tv_nsec = 0;

    while (! nd_terminate || (! nd_terminate_force && nd_json_agent_stats.flows > 0)) {
        int sig;
        siginfo_t si;

        if ((sig = sigtimedwait(&sigset, &si, &tspec_sigwait)) < 0) {
            if (errno == EAGAIN || errno == EINTR) continue;
            rc = -1;
            nd_terminate = true;
            nd_stop_capture_threads(true);
            nd_printf("sigwaitinfo: %s\n", strerror(errno));
            continue;
        }

        if (sig == ND_SIG_UPDATE) {
            nd_dprintf("Caught signal: [%d] %s: Update\n", sig, strsignal(sig));
        }
        else if (sig == ND_SIG_SINK_REPLY) {
            nd_dprintf("Caught signal: [%d] %s: Process sink reply\n", sig, strsignal(sig));
        }
        else if (sig == ND_SIG_UPDATE_NAPI) {
            nd_dprintf("Caught signal: [%d] %s: Netify API update\n", sig, strsignal(sig));
        }
        else {
            nd_dprintf("Caught signal: [%d] %s\n", sig, strsignal(sig));
        }
#ifndef SIGPWR
        if (sig == SIGINT || sig == SIGTERM) {
#else
        if (sig == SIGINT || sig == SIGTERM || sig == SIGPWR) {
#endif
            if (! nd_terminate) {
                nd_printf("Shutdown requested, waiting for threads to exit...\n");

                itspec_update.it_value = { 1, 0 };
                itspec_update.it_interval = { 1, 0 };

                timer_settime(timer_update, 0, &itspec_update, NULL);
            }
            else {
                nd_printf("Shutdown forced, exiting now...\n");
                nd_terminate_force = true;
                continue;
            }

            rc = 0;
            nd_terminate = true;
            nd_stop_capture_threads(true);
            continue;
        }

        if (sig == ND_SIG_UPDATE) {
            nd_dump_stats();
#ifdef _ND_USE_PLUGINS
            nd_plugin_event(ndPlugin::EVENT_STATUS_UPDATE);
#endif
            if (dns_hint_cache)
                dns_hint_cache->Purge();
#if !defined(_ND_USE_LIBTCMALLOC) && defined(HAVE_MALLOC_TRIM)
            // Attempt to release heap back to OS when supported
            malloc_trim(0);
#endif
            if (nd_reap_capture_threads() == 0) {
                nd_stop_capture_threads(true);
                if (thread_sink == NULL ||
                    thread_sink->QueuePendingSize() == 0) {
                    nd_printf("Exiting, no remaining capture threads.\n");
                    nd_terminate = true;
                    continue;
                }
            }
            continue;
        }

        if (sig == SIGIO) {
#ifdef _ND_USE_NETLINK
            if (ndGC_USE_NETLINK &&
                netlink->GetDescriptor() == si.si_fd) {
                netlink->ProcessEvent();
            }
#endif
            continue;
        }

        if (sig == ND_SIG_SINK_REPLY) {
            if (ndGC_USE_SINKS && nd_sink_process_responses() < 0) {
                nd_dprintf("nd_sink_process_responses failed!\n");
                break;
            }
            continue;
        }
#if 0
        // TODO: Send all flows from this thread.  Capture threads
        // no longer have their own flow maps.
        if (sig == ND_SIG_CONNECT) {
            for (auto &it : capture_threads) {
                for (auto &it_instance : it.second)
                    it_instance->SendIPC(ND_SIG_CONNECT);
            }
            continue;
        }
#endif
        if (sig == ND_SIG_UPDATE_NAPI) {
            if (thread_napi == NULL) {
                thread_napi = new ndNetifyApiThread();
                thread_napi->Create();
            }
            continue;
        }

        if (sig == ND_SIG_NAPI_UPDATED) {
            if (nd_domains != NULL && ndGC_LOAD_DOMAINS)
                nd_domains->Load();

            if (nd_categories != NULL)
                nd_categories->Load();

            if (thread_napi != NULL) {
                delete thread_napi;
                thread_napi = NULL;
#ifdef _ND_USE_PLUGINS
                nd_plugin_event(ndPlugin::EVENT_RELOAD);
#endif
            }
            continue;
        }

        if (sig == SIGHUP) {
            nd_printf("Reloading configuration...\n");
            if (! nd_apps->Load(ndGC.path_app_config))
                nd_apps->LoadLegacy(ndGC.path_legacy_config);

            if (nd_domains != NULL && ndGC_LOAD_DOMAINS)
                nd_domains->Load();

            if (nd_categories != NULL)
                nd_categories->Load();
#ifdef _ND_USE_PLUGINS
            nd_plugin_event(ndPlugin::EVENT_RELOAD);
#endif
            nd_printf("Configuration reloaded.\n");
            continue;
        }

        if (sig == SIGUSR1) {
            nd_start_capture_threads();
            nd_capture_stopped_by_signal = false;
            continue;
        }

        if (sig == SIGUSR2) {
            nd_stop_capture_threads();
            nd_capture_stopped_by_signal = true;
            continue;
        }

        nd_printf("Unhandled signal: %s\n", strsignal(sig));
    }

    timer_delete(timer_update);
    if (ndGC_USE_NAPI)
        timer_delete(timer_napi);

    nd_stop_detection_threads();

    if (thread_socket) {
        thread_socket->Terminate();
        delete thread_socket;
    }

    nd_destroy();

#ifdef _ND_USE_PLUGINS
    nd_plugin_stop_detections();
    nd_plugin_stop_sinks();
    nd_plugin_stop_stats();
#endif

    if (thread_sink) {
        thread_sink->Terminate();
        delete thread_sink;
    }

#ifdef _ND_USE_CONNTRACK
    if (ndGC_USE_CONNTRACK && thread_conntrack) {
        thread_conntrack->Terminate();
        delete thread_conntrack;
    }
#endif

    if (dns_hint_cache) {
        dns_hint_cache->Save();
        delete dns_hint_cache;
    }

    if (flow_hash_cache) {
        flow_hash_cache->Save();
        delete flow_hash_cache;
    }

    delete nd_addrtype;

    nd_dprintf("Normal exit.\n");

    curl_global_cleanup();

    closelog();

    unlink(ndGC.path_pid_file.c_str());

    return 0;
}
#endif
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
