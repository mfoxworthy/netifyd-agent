// Netify Agent 🥷
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
class ndInstanceStatus;
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

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
