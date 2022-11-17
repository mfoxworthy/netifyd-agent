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

#include "INIReader.h"

using namespace std;

#include "netifyd.h"

#include "nd-config.h"
#include "nd-ndpi.h"
#ifdef _ND_USE_INOTIFY
#include "nd-inotify.h"
#endif
#ifdef _ND_USE_NETLINK
#include "nd-netlink.h"
#endif
#include "nd-json.h"
#include "nd-apps.h"
#include "nd-protos.h"
#include "nd-risks.h"
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
#include "nd-socket.h"
#include "nd-sink.h"
#include "nd-base64.h"
#ifdef _ND_USE_PLUGINS
#include "nd-plugin.h"
#endif
#include "nd-util.h"
#include "nd-signal.h"
#include "nd-napi.h"

static bool nd_terminate = false;
static bool nd_terminate_force = false;
static nd_stats stats;
static nd_capture_threads capture_threads;
static nd_detection_threads detection_threads;
static nd_packet_stats pkt_totals;
static ostringstream *nd_stats_os = NULL;
static ndSinkThread *thread_sink = NULL;
static ndSocketThread *thread_socket = NULL;
static ndNetifyApiThread *thread_napi = NULL;
#ifdef _ND_USE_PLUGINS
static nd_plugins plugin_services;
static nd_plugins plugin_tasks;
static nd_plugins plugin_detections;
static nd_plugins plugin_stats;
#endif
static char *nd_conf_filename = NULL;
#ifdef _ND_USE_CONNTRACK
static ndConntrackThread *thread_conntrack = NULL;
#endif
#ifdef _ND_USE_INOTIFY
static ndInotify *inotify = NULL;
#endif
static nd_device_filter device_filters;
static bool nd_capture_stopped_by_signal = false;
static ndDNSHintCache *dns_hint_cache = NULL;
static ndFlowHashCache *flow_hash_cache = NULL;
static time_t nd_ethers_mtime = 0;

extern ndGlobalConfig nd_config;
extern nd_device nd_devices;
extern nd_device_ether nd_device_ethers;
extern ndFlowMap *nd_flow_buckets;
extern ndApplications *nd_apps;
extern ndCategories *nd_categories;
extern ndDomains *nd_domains;
extern atomic_uint nd_flow_count;
extern nd_agent_stats nd_json_agent_stats;
extern nd_interface nd_interfaces;
extern nd_interface_addr_map nd_interface_addrs;
#ifdef _ND_USE_NETLINK
extern ndNetlink *netlink;
extern nd_netlink_device nd_netlink_devices;
#endif

#define _ND_LO_ENABLE_SINK          1
#define _ND_LO_DISABLE_SINK         2
#define _ND_LO_FORCE_RESET          3
#define _ND_LO_CA_CAPTURE_BASE      4
#define _ND_LO_CA_CONNTRACK         5
#define _ND_LO_CA_DETECTION_BASE    6
#define _ND_LO_CA_DETECTION_CORES   7
#define _ND_LO_CA_SINK              8
#define _ND_LO_CA_SOCKET            9
#define _ND_LO_WAIT_FOR_CLIENT      10
#define _ND_LO_DUMP_PROTOS          11
#define _ND_LO_DUMP_APPS            12
#define _ND_LO_DUMP_CAT             13
#define _ND_LO_DUMP_CATS            14
#define _ND_LO_DUMP_RISKS           15
#define _ND_LO_DUMP_SORT_BY_TAG     16
#define _ND_LO_EXPORT_APPS          17
#define _ND_LO_LOOKUP_IP            18

static int nd_config_set_option(int option)
{
    string func, output;

    switch (option) {
    case _ND_LO_ENABLE_SINK:
        func = "config_enable_sink";
        printf("Enabling Netify Cloud Sink.\n");
        break;
    case _ND_LO_DISABLE_SINK:
        func = "config_disable_sink";
        printf("Disabling Netify Cloud Sink.\n");
        break;
    default:
        fprintf(stderr, "Unrecognized configuration option: %d\n", option);
        return 1;
    }

    int rc = nd_functions_exec(func, output);
    if (rc != 0) {
        fprintf(stderr, "Error while modifying configuration file.\n"
            "Manually edit configuration file: %s\n", nd_conf_filename);

        if (ND_DEBUG) fprintf(stderr, "%s", output.c_str());

        return rc;
    }
    else
        printf("Configuration modified: %s\n", nd_conf_filename);

    return 0;
}

static void nd_usage(int rc = 0, bool version = false)
{
    if (nd_conf_filename == NULL)
        nd_conf_filename = strdup(ND_CONF_FILE_NAME);

    nd_config.Load(nd_conf_filename);

    ND_GF_SET_FLAG(ndGF_QUIET, true);

    fprintf(stderr,
        "%s\n%s\n", nd_get_version_and_features().c_str(), PACKAGE_URL);
    if (version) {
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
        if (nd_config.plugin_services.size())
            fprintf(stderr, "\nService plugins:\n");

        for (auto i : nd_config.plugin_services) {

            string plugin_version("?.?.?");

            try {
                ndPluginLoader *loader = new ndPluginLoader(i.second, i.first);
                loader->GetPlugin()->GetVersion(plugin_version);
            }
            catch (...) { }

            fprintf(stderr, "  %s: %s: v%s\n",
                i.first.c_str(), i.second.c_str(), plugin_version.c_str());
        }

        if (nd_config.plugin_tasks.size())
            fprintf(stderr, "\nTask plugins:\n");

        for (auto i : nd_config.plugin_tasks) {

            string plugin_version("?.?.?");

            try {
                ndPluginLoader *loader = new ndPluginLoader(i.second, i.first);
                loader->GetPlugin()->GetVersion(plugin_version);
            }
            catch (...) { }

            fprintf(stderr, "  %s: %s: v%s\n",
                i.first.c_str(), i.second.c_str(), plugin_version.c_str());
        }

        if (nd_config.plugin_detections.size())
            fprintf(stderr, "\nDetection plugins:\n");

        for (auto i : nd_config.plugin_detections) {

            string plugin_version("?.?.?");

            try {
                ndPluginLoader *loader = new ndPluginLoader(i.second, i.first);
                loader->GetPlugin()->GetVersion(plugin_version);
            }
            catch (...) { }

            fprintf(stderr, "  %s: %s: v%s\n",
                i.first.c_str(), i.second.c_str(), plugin_version.c_str());
        }

        if (nd_config.plugin_stats.size())
            fprintf(stderr, "\nStatistics plugins:\n");

        for (auto i : nd_config.plugin_stats) {

            string plugin_version("?.?.?");

            try {
                ndPluginLoader *loader = new ndPluginLoader(i.second, i.first);
                loader->GetPlugin()->GetVersion(plugin_version);
            }
            catch (...) { }

            fprintf(stderr, "  %s: %s: v%s\n",
                i.first.c_str(), i.second.c_str(), plugin_version.c_str());
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

#ifndef _ND_LEAN_AND_MEAN
            "\nDump options:\n"
            "  --dump-sort-by-tag\n    Sort entries by tag.\n"
            "    Default: sort entries by ID.\n"
            "  -P, --dump-all\n    Dump all applications and protocols.\n"
            "  --dump-apps\n    Dump applications only.\n"
            "  --dump-protos\n    Dump protocols only.\n"
            "  --dump-categories\n    Dump application and protocol categories.\n"
            "  --dump-category <type>\n    Dump categories by type: application or protocol\n"
            "  --dump-risks\n    Dump flow security risks.\n"
#endif
            "\nCapture options:\n"
            "  -I, --internal <interface>\n    Specify an internal (LAN) interface to capture from.\n"
            "  -E, --external <interface>\n    Specify an external (WAN) interface to capture from.\n"
            "  -A, --device-address <address>\n    Interface/device option: consider address is assigned to interface.\n"
            "  -F, --device-filter <BPF expression>\n    Interface/device option: attach a BPF filter expression to interface.\n"
            "  -N, --device-netfilter <interface>\n    Interface/device option: associate Netlink messages from an alternate interface (ex: physdev of PPP interface).\n"
            "  -t, --disable-conntrack\n    Disable connection tracking thread.\n"
            "  -l, --disable-netlink\n    Don't process Netlink messages for capture interfaces.\n"

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
            nd_config.path_uuid, nd_config.path_uuid_site, ND_URL_SINK_PATH
        );
    }

    exit(rc);
}

static void nd_force_reset(void)
{
    if (nd_conf_filename == NULL)
        nd_conf_filename = strdup(ND_CONF_FILE_NAME);

    if (nd_config.Load(nd_conf_filename) < 0)
        return;

    vector<string> files = {
        nd_config.path_uuid, nd_config.path_uuid_site, ND_URL_SINK_PATH
    };

    int seconds = 3;
    fprintf(stdout,
        "%sWARNING%s: Resetting Agent state files in %s%d%s seconds...\n",
        ND_C_RED, ND_C_RESET, ND_C_RED, seconds, ND_C_RESET);
    for ( ; seconds >= 0; seconds--) {
        fprintf(stdout, "%sWARNING%s: Press CTRL-C to abort: %s%d%s\r",
            ND_C_RED, ND_C_RESET, ND_C_RED, seconds, ND_C_RESET);
        fflush(stdout);
        sleep(1);
    }
    fputc('\n', stdout);
    sleep(2);

    for (vector<string>::const_iterator i = files.begin();
        i != files.end(); i++) {
        fprintf(stdout, "Deleting file: %s\n", (*i).c_str());
        if (unlink((*i).c_str()) != 0 && errno != ENOENT) {
            fprintf(stderr, "Error while removing file: %s: %s\n",
                (*i).c_str(), strerror(errno));
        }
    }

    string output;
    int rc = nd_functions_exec("restart_netifyd", output);

    if (rc != 0) {
        fprintf(stderr, "Error while restarting service.\n"
            "Manual restart is required for the reset to be completed.\n");
    }

    if (output.size())
        fprintf(stdout, "%s", output.c_str());

    if (rc == 0)
        fprintf(stdout, "Reset successful.\n");
}

static void nd_init(void)
{
    nd_apps = new ndApplications();
    if (nd_apps == nullptr)
        throw ndSystemException(__PRETTY_FUNCTION__, "new nd_apps", ENOMEM);

    if (! nd_apps->Load(nd_config.path_app_config))
        nd_apps->LoadLegacy(nd_config.path_legacy_config);

    nd_categories = new ndCategories();
    if (nd_categories == nullptr)
        throw ndSystemException(__PRETTY_FUNCTION__, "new nd_categories", ENOMEM);

    nd_categories->Load();

    nd_domains = new ndDomains();
    if (nd_domains == nullptr)
        throw ndSystemException(__PRETTY_FUNCTION__, "new nd_domains", ENOMEM);

    if (ND_LOAD_DOMAINS) nd_domains->Load();

    nd_flow_buckets = new ndFlowMap();
    if (nd_flow_buckets == nullptr)
        throw ndSystemException(__PRETTY_FUNCTION__, "new nd_flow_buckets", ENOMEM);

    for (nd_interface::iterator i = nd_interfaces.begin();
        i != nd_interfaces.end(); i++) {

        stats[(*i).second] = new nd_packet_stats;
        if (stats[(*i).second] == NULL)
            throw ndSystemException(__PRETTY_FUNCTION__, "new nd_packet_stats", ENOMEM);

        if (! (*i).first) {
            // XXX: Only collect device MAC/addresses on LAN interfaces.
            nd_devices[(*i).second] = make_pair(
                (mutex *)NULL, (nd_device_addrs *)NULL
            );
        }
        else {
            int rc;

            nd_devices[(*i).second] = make_pair(
                new mutex, new nd_device_addrs
            );
            if (nd_devices[(*i).second].first == NULL)
                throw ndSystemException(__PRETTY_FUNCTION__, "new mutex", ENOMEM);
            if (nd_devices[(*i).second].second == NULL)
                throw ndSystemException(__PRETTY_FUNCTION__, "new nd_device_addrs", ENOMEM);
        }
    }

    nd_ifaddrs_update(nd_interface_addrs);
}

static void nd_destroy(void)
{
    for (nd_interface::iterator i = nd_interfaces.begin(); i != nd_interfaces.end(); i++) {

        delete stats[(*i).second];
        if (nd_devices.find((*i).second) != nd_devices.end()) {
            if (nd_devices[(*i).second].first != NULL)
                delete nd_devices[(*i).second].first;
            if (nd_devices[(*i).second].second != NULL)
                delete nd_devices[(*i).second].second;
        }
    }

    stats.clear();
    nd_devices.clear();

    if (nd_flow_buckets) {
        delete nd_flow_buckets;
        nd_flow_buckets = NULL;
    }

    if (nd_apps) {
        delete nd_apps;
        nd_apps = NULL;
    }

    if (nd_domains) {
        delete nd_domains;
        nd_domains = NULL;
    }
}

static int nd_start_capture_threads(void)
{
    if (capture_threads.size() > 0) return 1;

    try {
        int16_t cpu = (
                nd_config.ca_capture_base > -1 &&
                nd_config.ca_capture_base < (int16_t)nd_json_agent_stats.cpus
            ) ? nd_config.ca_capture_base : 0;
        string netlink_dev;
        uint8_t private_addr = 0;
        uint8_t mac[ETH_ALEN];

        for (nd_interface::iterator i = nd_interfaces.begin();
            i != nd_interfaces.end(); i++) {

            if (! nd_ifaddrs_get_mac(nd_interface_addrs, (*i).second, mac))
                memset(mac, 0, ETH_ALEN);

            capture_threads[(*i).second] = new ndCaptureThread(
                (nd_interfaces.size() > 1) ? cpu++ : -1,
                i,
                mac,
                thread_socket,
                detection_threads,
                stats[(*i).second],
                dns_hint_cache,
                (i->first) ? 0 : ++private_addr
            );

            capture_threads[(*i).second]->Create();

            if (cpu == (int16_t)nd_json_agent_stats.cpus) cpu = 0;
        }
    }
    catch (exception &e) {
        nd_printf("Runtime error: %s\n", e.what());
        throw;
    }

    return 0;
}

static void nd_stop_capture_threads(bool expire_flows = false)
{
    if (capture_threads.size() == 0) return;

    for (nd_interface::iterator i = nd_interfaces.begin(); i != nd_interfaces.end(); i++) {
        capture_threads[(*i).second]->Terminate();
        delete capture_threads[(*i).second];
    }

    capture_threads.clear();

    if (! expire_flows) return;

    size_t buckets = nd_flow_buckets->GetBuckets();

    for (size_t b = 0; b < buckets; b++) {
        nd_flow_map *fm = nd_flow_buckets->Acquire(b);

        for (auto it = fm->begin(); it != fm->end(); it++) {
            if (it->second->flags.detection_expiring.load() == false) {

                it->second->flags.detection_expiring = true;
                detection_threads[it->second->dpi_thread_id]->QueuePacket(it->second);
            }
        }

        nd_flow_buckets->Release(b);
    }
}

static size_t nd_reap_capture_threads(void)
{
    size_t threads = capture_threads.size();

    for (nd_capture_threads::iterator i = capture_threads.begin();
        i != capture_threads.end(); i++) {
        if (i->second->HasTerminated()) threads--;
    }

    return threads;
}

static int nd_start_detection_threads(void)
{
    if (detection_threads.size() > 0) return 1;

    try {
        int16_t cpu = (
                nd_config.ca_detection_base > -1 &&
                nd_config.ca_detection_base < (int16_t)nd_json_agent_stats.cpus
            ) ? nd_config.ca_detection_base : 0;
        int16_t cpus = (
                nd_config.ca_detection_cores > (int16_t)nd_json_agent_stats.cpus ||
                nd_config.ca_detection_cores <= 0
            ) ? (int16_t)nd_json_agent_stats.cpus : nd_config.ca_detection_cores;

        nd_dprintf("Creating %hd detection threads at offset: %hd\n", cpus, cpu);

        for (int16_t i = 0; i < cpus; i++) {
            ostringstream os;
            os << "dpi" << cpu;

            detection_threads[i] = new ndDetectionThread(
                cpu,
                os.str(),
#ifdef _ND_USE_NETLINK
                netlink,
#endif
                thread_socket,
#ifdef _ND_USE_CONNTRACK
                (! ND_USE_CONNTRACK) ?  NULL : thread_conntrack,
#endif
#ifdef _ND_USE_PLUGINS
                &plugin_detections,
#endif
                nd_devices,
                dns_hint_cache,
                flow_hash_cache,
                (uint8_t)cpu
            );

            detection_threads[i]->Create();

            if (++cpu == cpus) cpu = 0;
        }
    }
    catch (exception &e) {
        nd_printf("Runtime error: %s\n", e.what());
        throw;
    }

    return 0;
}

static void nd_stop_detection_threads(void)
{
    if (detection_threads.size() == 0) return;

    for (nd_detection_threads::iterator i = detection_threads.begin();
        i != detection_threads.end(); i++) {
        i->second->Terminate();
        delete i->second;
    }

    detection_threads.clear();
}

static int nd_reload_detection_threads(void)
{
    for (nd_detection_threads::iterator i = detection_threads.begin();
        i != detection_threads.end(); i++) {
        i->second->Lock();
        i->second->Reload();
        i->second->Unlock();
    }

    return 0;
}

#ifdef _ND_USE_PLUGINS

static int nd_plugin_start_services(void)
{
    for (map<string, string>::const_iterator i = nd_config.plugin_services.begin();
        i != nd_config.plugin_services.end(); i++) {
        try {
            plugin_services[i->first] = new ndPluginLoader(i->second, i->first);
            plugin_services[i->first]->GetPlugin()->Create();
        }
        catch (ndPluginException &e) {
            nd_printf("Error loading service plugin: %s\n", e.what());
            return 1;
        }
        catch (ndThreadException &e) {
            nd_printf("Error starting service plugin: %s %s: %s\n",
                i->first.c_str(), i->second.c_str(), e.what());
            return 1;
        }
    }

    return 0;
}

static void nd_plugin_stop_services(void)
{
    for (nd_plugins::iterator i = plugin_services.begin();
        i != plugin_services.end(); i++) {

        ndPluginService *service = reinterpret_cast<ndPluginService *>(
            i->second->GetPlugin()
        );
        service->Terminate();
        delete service;

        delete i->second;
    }

    plugin_services.clear();
}

static int nd_plugin_dispatch_service_param(
    const string &name, const string &uuid_dispatch, const ndJsonPluginParams &params)
{
    int rc = 0;
#if 0
    if (name == "netifyd.service.capture.start") {
        nd_printf("Unclassified flow capture started by service parameter request.\n");
        ND_GF_SET_FLAG(ndGF_CAPTURE_UNKNOWN_FLOWS, true);
        return 0;
    }
    else if (name == "netifyd.service.capture.stop") {
        nd_printf("Unclassified flow capture stopped by service parameter request.\n");
        ND_GF_SET_FLAG(ndGF_CAPTURE_UNKNOWN_FLOWS, false);
        return 0;
    }
#endif
    nd_plugins::iterator plugin_iter = plugin_services.find(name);

    if (plugin_iter == plugin_services.end()) {
        nd_printf("Unable to dispatch parameters; service not found: %s\n",
            name.c_str());
        rc = -1;
    }
    else {
        ndPluginService *service = reinterpret_cast<ndPluginService *>(
            plugin_iter->second->GetPlugin()
        );

        service->SetParams(uuid_dispatch, params);
    }

    return rc;
}

static int nd_plugin_start_task(
    const string &name, const string &uuid_dispatch, const ndJsonPluginParams &params)
{
    map<string, string>::const_iterator task_iter = nd_config.plugin_tasks.find(name);

    if (task_iter == nd_config.plugin_tasks.end()) {
        nd_printf("Unable to initialize plugin; task not found: %s\n",
            name.c_str());
        return -1;
    }

    nd_plugins::iterator plugin_iter = plugin_tasks.find(uuid_dispatch);

    if (plugin_iter != plugin_tasks.end()) {
        nd_printf("Unable to initialize plugin; task exists: %s: %s\n",
            name.c_str(), uuid_dispatch.c_str());
        return -1;
    }

    try {
        ndPluginLoader *plugin = new ndPluginLoader(
            task_iter->second, task_iter->first
        );

        ndPluginTask *task = reinterpret_cast<ndPluginTask *>(
            plugin->GetPlugin()
        );

        task->SetParams(uuid_dispatch, params);
        task->Create();

        plugin_tasks[uuid_dispatch] = plugin;
    }
    catch (ndPluginException &e) {
        nd_printf("Error loading task plugin: %s\n", e.what());
        return -1;
    }
    catch (ndThreadException &e) {
        nd_printf("Error starting task plugin: %s %s: %s\n",
            task_iter->first.c_str(), task_iter->second.c_str(), e.what());
        return -1;
    }

    return 0;
}

static void nd_plugin_stop_tasks(void)
{
    for (nd_plugins::iterator i = plugin_tasks.begin();
        i != plugin_tasks.end(); i++) {

        ndPluginTask *task = reinterpret_cast<ndPluginTask *>(
            i->second->GetPlugin()
        );
        task->Terminate();
        delete task;
    }
}

static void nd_plugin_reap_tasks(void)
{
    for (nd_plugins::iterator i = plugin_tasks.begin();
        i != plugin_tasks.end(); i++) {
        if (! i->second->GetPlugin()->HasTerminated()) continue;

        nd_dprintf("Reaping task plugin: %s: %s\n",
            i->second->GetPlugin()->GetTag().c_str(),
            i->first.c_str());

        delete i->second->GetPlugin();
        delete i->second;

        plugin_tasks.erase(i);
    }
}

static int nd_plugin_start_detections(void)
{
    for (map<string, string>::const_iterator i = nd_config.plugin_detections.begin();
        i != nd_config.plugin_detections.end(); i++) {
        try {
            plugin_detections[i->first] = new ndPluginLoader(i->second, i->first);
            plugin_detections[i->first]->GetPlugin()->Create();
        }
        catch (ndPluginException &e) {
            nd_printf("Error loading detection plugin: %s\n", e.what());
            return 1;
        }
        catch (ndThreadException &e) {
            nd_printf("Error starting detection plugin: %s %s: %s\n",
                i->first.c_str(), i->second.c_str(), e.what());
            return 1;
        }
    }

    return 0;
}

static void nd_plugin_stop_detections(void)
{
    for (nd_plugins::iterator i = plugin_detections.begin();
        i != plugin_detections.end(); i++) {

        ndPluginDetection *detection = reinterpret_cast<ndPluginDetection *>(
            i->second->GetPlugin()
        );
        detection->Terminate();
        delete detection;

        delete i->second;
    }

    plugin_detections.clear();
}

static int nd_plugin_start_stats(void)
{
    for (map<string, string>::const_iterator i = nd_config.plugin_stats.begin();
        i != nd_config.plugin_stats.end(); i++) {
        try {
            plugin_stats[i->first] = new ndPluginLoader(i->second, i->first);
            plugin_stats[i->first]->GetPlugin()->Create();
        }
        catch (ndPluginException &e) {
            nd_printf("Error loading detection plugin: %s\n", e.what());
            return 1;
        }
        catch (ndThreadException &e) {
            nd_printf("Error starting detection plugin: %s %s: %s\n",
                i->first.c_str(), i->second.c_str(), e.what());
            return 1;
        }
    }

    return 0;
}

static void nd_plugin_stop_stats(void)
{
    for (nd_plugins::iterator i = plugin_stats.begin();
        i != plugin_stats.end(); i++) {

        ndPluginDetection *detection = reinterpret_cast<ndPluginDetection *>(
            i->second->GetPlugin()
        );
        detection->Terminate();
        delete detection;

        delete i->second;
    }

    plugin_stats.clear();
}

static void nd_plugin_event(
    ndPlugin::ndPluginEvent event, void *param = NULL)
{
    for (nd_plugins::iterator i = plugin_services.begin();
        i != plugin_services.end(); i++)
        i->second->GetPlugin()->ProcessEvent(event, param);
    for (nd_plugins::iterator i = plugin_tasks.begin();
        i != plugin_tasks.end(); i++)
        i->second->GetPlugin()->ProcessEvent(event, param);
    for (nd_plugins::iterator i = plugin_detections.begin();
        i != plugin_detections.end(); i++)
        i->second->GetPlugin()->ProcessEvent(event, param);
    for (nd_plugins::iterator i = plugin_stats.begin();
        i != plugin_stats.end(); i++)
        i->second->GetPlugin()->ProcessEvent(event, param);
}

#endif // _USE_ND_PLUGINS

static int nd_sink_process_responses(void)
{
    int count = 0;
    bool reloaded = false;

    while (true) {
        ndJsonResponse *response = thread_sink->PopResponse();

        if (response == NULL) break;

        count++;

        if (response->resp_code == ndJSON_RESP_OK) {

            for (ndJsonData::const_iterator i = response->data.begin();
                i != response->data.end(); i++) {

                if (! reloaded && i->first == ND_CONF_APP_BASE) {
                    reloaded = nd_apps->Load(nd_config.path_app_config);
                }

                if (! reloaded && i->first == ND_CONF_LEGACY_BASE) {
                    reloaded = nd_apps->LoadLegacy(nd_config.path_legacy_config);
                }
            }

            if (reloaded && thread_socket) {
                string json;
                nd_json_protocols(json);
                thread_socket->QueueWrite(json);
            }
#ifdef _ND_USE_PLUGINS
            for (ndJsonPluginRequest::const_iterator
                i = response->plugin_request_service_param.begin();
                i != response->plugin_request_service_param.end(); i++) {

                ndJsonPluginDispatch::const_iterator iter_params;
                iter_params = response->plugin_params.find(i->first);

                if (iter_params != response->plugin_params.end()) {
                    const ndJsonPluginParams &params(iter_params->second);
                    nd_plugin_dispatch_service_param(i->second, i->first, params);
                }
                else {
                    const ndJsonPluginParams params;
                    nd_plugin_dispatch_service_param(i->second, i->first, params);
                }
            }

            for (ndJsonPluginRequest::const_iterator
                i = response->plugin_request_task_exec.begin();
                i != response->plugin_request_task_exec.end(); i++) {

                ndJsonPluginDispatch::const_iterator iter_params;
                iter_params = response->plugin_params.find(i->first);

                if (iter_params != response->plugin_params.end()) {
                    const ndJsonPluginParams &params(iter_params->second);
                    nd_plugin_start_task(i->second, i->first, params);
                }
                else {
                    const ndJsonPluginParams params;
                    nd_plugin_start_task(i->second, i->first, params);
                }
            }
#endif
        }

        nd_json_agent_stats.sink_resp_code = response->resp_code;

        delete response;
    }

    return count;
}

static void nd_process_flows(
    unordered_map<string, json> &jflows, bool add_flows)
{
    uint32_t now = time(NULL);
    size_t purged = 0, expiring = 0, expired = 0, active = 0, total = 0, blocked = 0;

    bool socket_queue = (thread_socket && thread_socket->GetClientCount());

    //nd_flow_buckets->DumpBucketStats();

    size_t buckets = nd_flow_buckets->GetBuckets();

    for (size_t b = 0; b < buckets; b++) {
        nd_flow_map *fm = nd_flow_buckets->Acquire(b);
        nd_flow_map::const_iterator i = fm->begin();

        total += fm->size();
        nd_json_agent_stats.flows += fm->size();

        while (i != fm->end()) {
            uint32_t last_seen = i->second->ts_last_seen / 1000;
            uint32_t ttl = (
                i->second->ip_protocol != IPPROTO_TCP
            ) ? nd_config.ttl_idle_flow : nd_config.ttl_idle_tcp_flow;

            if (nd_terminate)
                i->second->flags.detection_expired = true;

            if (last_seen + ttl < now ||
                i->second->flags.detection_expired.load() ||
                (i->second->ip_protocol == IPPROTO_TCP &&
                    i->second->flags.tcp_fin.load())) {

                if (i->second->flags.detection_expired.load() == true)
                    expired++;
                else if (i->second->flags.detection_init.load() == false) {

                    if (i->second->flags.detection_expiring.load() == false) {

                        if (i->second->dpi_thread_id >= 0 &&
                            (size_t)i->second->dpi_thread_id < detection_threads.size()) {

                            expiring++;
                            i->second->flags.detection_expiring = true;
                            detection_threads[i->second->dpi_thread_id]->QueuePacket(i->second);
                        }
                    }

                    i++;
                    continue;
                }

                if (add_flows &&
                    (ND_UPLOAD_NAT_FLOWS || i->second->flags.ip_nat.load() == false)) {

                    json jf;
                    i->second->json_encode(jf);

                    string iface_name;
                    nd_iface_name(i->second->iface->second, iface_name);

                    jflows[iface_name].push_back(jf);
                }

                if (socket_queue) {

                    if (ND_FLOW_DUMP_UNKNOWN &&
                        i->second->detected_protocol == ND_PROTO_UNKNOWN) {

                        json j, jf;

                        j["type"] = "flow";
                        j["interface"] = i->second->iface->second;
                        j["internal"] = i->second->iface->first;
                        j["established"] = false;

                        i->second->json_encode(
                            jf, ndFlow::ENCODE_METADATA
                        );
                        j["flow"] = jf;

                        string json_string;
                        nd_json_to_string(j, json_string, false);
                        json_string.append("\n");

                        thread_socket->QueueWrite(json_string);
                    }

                    if (ND_FLOW_DUMP_UNKNOWN ||
                        i->second->detected_protocol != ND_PROTO_UNKNOWN) {

                        json j, jf;

                        j["type"] = "flow_purge";
                        j["reason"] = (
                            i->second->ip_protocol == IPPROTO_TCP &&
                            i->second->flags.tcp_fin.load()
                        ) ? "closed" : (nd_terminate) ? "terminated" : "expired";
                        j["interface"] = i->second->iface->second;
                        j["internal"] = i->second->iface->first;
                        j["established"] = false;

                        i->second->json_encode(
                            jf, ndFlow::ENCODE_STATS | ndFlow::ENCODE_TUNNELS
                        );
                        j["flow"] = jf;

                        string json_string;
                        nd_json_to_string(j, json_string, false);
                        json_string.append("\n");

                        thread_socket->QueueWrite(json_string);
                    }
                }

                if (i->second->queued.load() == 0) {
                    delete i->second;
                    i = fm->erase(i);

                    purged++;
                    nd_flow_count--;
                }
                else {
                    if (blocked == 0) {
                        nd_dprintf("%s: flow purge blocked by %lu queued packets.\n",
                            i->second->iface->second.c_str(), i->second->queued.load());
                    }
                    blocked++;
                    i++;
                }
            }
            else {
                if (i->second->flags.detection_init.load()) {

                    if (add_flows && i->second->ts_first_update &&
                        (ND_UPLOAD_NAT_FLOWS || i->second->flags.ip_nat.load() == false)) {

                        json jf;
                        i->second->json_encode(jf);

                        string iface_name;
                        nd_iface_name(i->second->iface->second, iface_name);

                        jflows[iface_name].push_back(jf);

                        if (socket_queue) {
                            json j;

                            j["type"] = "flow_stats";
                            j["interface"] = i->second->iface->second;
                            j["internal"] = i->second->iface->first;
                            j["established"] = false;

                            jf.clear();
                            i->second->json_encode(
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

                i++;
            }
        }

        nd_flow_buckets->Release(b);
    }

    nd_dprintf(
        "Purged %lu of %lu flow(s), active: %lu, expiring: %lu, expired: %lu, queued: %lu, blocked: %lu\n",
        purged, total, active, expiring, expired, total - active, blocked
    );
}

static void nd_json_add_file(
    json &parent, const string &tag, const string &filename)
{
    string digest;
    uint8_t _digest[SHA1_DIGEST_LENGTH];

    if (nd_sha1_file(filename.c_str(), _digest) < 0) return;

    nd_sha1_to_string(_digest, digest);

    uint8_t buffer[ND_JSON_DATA_CHUNKSIZ];
    int fd = open(filename.c_str(), O_RDONLY);

    if (fd < 0) {
        nd_printf("Error opening file for upload: %s: %s\n",
            filename.c_str(), strerror(errno));
        return;
    }

    struct stat file_stat;
    if (fstat(fd, &file_stat) != 0) {
        nd_printf("Error reading stats for upload file: %s: %s\n",
            filename.c_str(), strerror(errno));
        close(fd);
        return;
    }

    json jd, jc;

    jd["digest"] = digest;
    jd["size"] = file_stat.st_size;

    size_t bytes;

    do {
        if ((bytes = read(fd, buffer, ND_JSON_DATA_CHUNKSIZ)) > 0)
            jc.push_back(base64_encode(buffer, bytes));
    }
    while (bytes > 0);

    close(fd);

    jd["chunks"] = jc;
    parent[tag] = jd;
}

static void nd_json_add_data(
    json &parent, const string &tag, const string &data)
{
    sha1 ctx;
    string digest;
    uint8_t _digest[SHA1_DIGEST_LENGTH];

    sha1_init(&ctx);

    json jd, jc;

    jd["size"] = data.size();

    size_t offset = 0;

    do {
        const string chunk = data.substr(offset, ND_JSON_DATA_CHUNKSIZ);

        if (! chunk.size()) break;

        sha1_write(&ctx, chunk.c_str(), chunk.size());

        jc.push_back(
            base64_encode((const unsigned char *)chunk.c_str(),
            chunk.size())
        );

        if (chunk.size() != ND_JSON_DATA_CHUNKSIZ) break;

        offset += ND_JSON_DATA_CHUNKSIZ;
    }
    while (offset < data.size());

    digest.assign((const char *)sha1_result(&ctx, _digest), SHA1_DIGEST_LENGTH);
    nd_sha1_to_string(_digest, digest);

    jd["digest"] = digest;
    jd["chunks"] = jc;

    parent[tag] = jd;
}

#ifdef _ND_USE_PLUGINS

static void nd_json_add_plugin_replies(
    json &json_plugin_service_replies,
    json &json_plugin_task_replies, json &json_data)
{
    vector<ndPluginSink *> plugins;

    for (nd_plugins::const_iterator i = plugin_services.begin();
        i != plugin_services.end(); i++)
        plugins.push_back(reinterpret_cast<ndPluginSink *>(i->second->GetPlugin()));
    for (nd_plugins::const_iterator i = plugin_tasks.begin();
        i != plugin_tasks.end(); i++)
        plugins.push_back(reinterpret_cast<ndPluginSink *>(i->second->GetPlugin()));

    for (vector<ndPluginSink *>::const_iterator i = plugins.begin();
        i != plugins.end(); i++) {

        json *parent = NULL;

        switch ((*i)->GetType()) {

        case ndPlugin::TYPE_SINK_SERVICE:
            parent = &json_plugin_service_replies;
            break;
        case ndPlugin::TYPE_SINK_TASK:
            parent = &json_plugin_task_replies;
            break;

        default:
            nd_dprintf("%s: Unsupported plugin type: %d\n",
                __PRETTY_FUNCTION__, (*i)->GetType());
        }

        if (parent == NULL) continue;

        ndPluginFiles files, data;
        ndPluginReplies replies;
        (*i)->GetReplies(files, data, replies);

        nd_dprintf("%s: files: %ld, data: %ld, replies: %ld\n",
            __PRETTY_FUNCTION__, files.size(), data.size(), replies.size());

        if (! replies.size()) continue;

        for (ndPluginReplies::const_iterator iter_reply = replies.begin();
            iter_reply != replies.end(); iter_reply++) {

            json ja;

            for (ndJsonPluginReplies::const_iterator iter_params = iter_reply->second.begin();
                iter_params != iter_reply->second.end(); iter_params++) {

                json jr;

                jr[iter_params->first] = base64_encode(
                    (const unsigned char *)iter_params->second.c_str(),
                    iter_params->second.size()
                );

                ja.push_back(jr);
            }

            (*parent)[iter_reply->first.c_str()] = ja;
        }

        for (ndPluginFiles::const_iterator iter_file = files.begin();
            iter_file != files.end(); iter_file++) {
            nd_json_add_file(json_data, iter_file->first, iter_file->second);
        }

        for (ndPluginFiles::const_iterator iter_file = data.begin();
            iter_file != data.end(); iter_file++) {
            nd_json_add_data(json_data, iter_file->first, iter_file->second);
        }
    }
}
#endif // _ND_USE_PLUGINS

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

#ifndef _ND_LEAN_AND_MEAN
static void nd_load_ethers(void)
{
    char buffer[1024 + ND_STR_ETHALEN + 17];

    struct stat ethers_stat;
    if (stat(ND_ETHERS_FILE_NAME, &ethers_stat) < 0) {
        fprintf(stderr, "Could not stat ethers file: %s: %s\n",
            ND_ETHERS_FILE_NAME, strerror(errno));
        return;
    }

    if (nd_ethers_mtime == ethers_stat.st_mtime) return;
    nd_ethers_mtime = ethers_stat.st_mtime;

    FILE *fh = fopen(ND_ETHERS_FILE_NAME, "r");

    if (fh == NULL) return;

    nd_device_ethers.clear();

    size_t line = 0;
    while (! feof(fh)) {
        if (fgets(buffer, sizeof(buffer), fh)) {
            line++;
            char *p = buffer;
            while (isspace(*p) && *p != '\0') p++;

            char *ether = p;
            if (! isxdigit(*p)) continue;
            while (*p != '\0' && (isxdigit(*p) || *p == ':')) p++;
            *p = '\0';
            if (strlen(ether) != ND_STR_ETHALEN) continue;

            while (isspace(*(++p)) && *p != '\0');

            char *name = p;
            while (*p != '\n' && *p != '\0') p++;
            *p = '\0';
            if (! strlen(name)) continue;

            const char *a = ether;
            uint8_t mac[ETH_ALEN], *m = mac;
            for (int j = 0; j < ND_STR_ETHALEN; j += 3, m++)
                sscanf(a + j, "%2hhx", m);
            string key;
            key.assign((const char *)mac, ETH_ALEN);
            nd_device_ethers[key] = name;
            //nd_dprintf("%2lu: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx (%s): %s\n", line,
            //    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ether, name);
        }
    }

    fclose(fh);

    nd_dprintf("Loaded %lu entries from: %s\n",
        nd_device_ethers.size(), ND_ETHERS_FILE_NAME);
}
#endif

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
#elif defined(_ND_USE_LIBJEMALLOC) && defined(HAVE_JEMALLOC_JEMALLOC_H)
    size_t tcm_alloc_bytes = 0;
    size_t je_opt_size = sizeof(size_t);

    const char *je_opt = "stats.allocated";

    mallctl("thread.tcache.flush", NULL, NULL, NULL, 0);

    int rc = mallctl(
        je_opt,
        (void *)&tcm_alloc_bytes, &je_opt_size,
        NULL, 0
    );

    nd_dprintf("JEMALLOC: %s: %d: %ld\n", je_opt, rc, tcm_alloc_bytes);

    if (rc == 0) {
        nd_json_agent_stats.tcm_alloc_kb_prev = nd_json_agent_stats.tcm_alloc_kb;
        nd_json_agent_stats.tcm_alloc_kb = tcm_alloc_bytes / 1024;
    }
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

    if (ND_USE_DHC) {
        nd_json_agent_stats.dhc_status = true;
        nd_json_agent_stats.dhc_size = dns_hint_cache->size();
    }
    else
        nd_json_agent_stats.dhc_status = false;

    if (thread_sink == NULL)
        nd_json_agent_stats.sink_status = false;
    else {
        nd_json_agent_stats.sink_status = true;
        nd_json_agent_stats.sink_queue_size = thread_sink->QueuePendingSize();
    }

    json jstatus;
    string json_string;
    nd_json_agent_status(jstatus);

    json ji, jd;

    nd_json_add_interfaces(ji);
    jstatus["interfaces"] = ji;

    nd_json_add_devices(jd);
    jstatus["devices"] = jd;

    unordered_map<string, json> jflows;

    for (nd_capture_threads::iterator i = capture_threads.begin();
        i != capture_threads.end(); i++) {

        json js, jf;

        string iface_name;
        nd_iface_name(i->first, iface_name);

        jflows[iface_name] = vector<json>();

        i->second->Lock();

        pkt_totals += *stats[i->first];

        struct pcap_stat lpc_stat;
        i->second->GetCaptureStats(lpc_stat);

        nd_json_add_stats(js, stats[i->first], &lpc_stat);

        for (nd_plugins::iterator pi = plugin_stats.begin();
            pi != plugin_stats.end(); pi++) {
            ndPluginStats *p = reinterpret_cast<ndPluginStats *>(
                pi->second->GetPlugin()
            );
            p->ProcessStats(iface_name, stats[i->first]);
        }

        i->second->Unlock();

        jstatus["stats"][iface_name] = js;
    }

    for (nd_plugins::iterator pi = plugin_stats.begin();
        pi != plugin_stats.end(); pi++) {
        ndPluginStats *p = reinterpret_cast<ndPluginStats *>(
            pi->second->GetPlugin()
        );
        p->ProcessStats(pkt_totals);
        p->ProcessStats(nd_flow_buckets);
    }

    nd_process_flows(jflows, (ND_USE_SINK || ND_EXPORT_JSON));

    for (nd_capture_threads::iterator i = capture_threads.begin();
        i != capture_threads.end(); i++) {

        i->second->Lock();
        stats[i->first]->reset();
        i->second->Unlock();
    }

    jstatus["flow_count"] = nd_json_agent_stats.flows;
    jstatus["flow_count_prev"] = nd_json_agent_stats.flows_prev;

    json j = jstatus;

    try {
        jstatus["type"] = "agent_status";

        nd_json_to_string(jstatus, json_string);
        json_string.append("\n");

        if (thread_socket)
            thread_socket->QueueWrite(json_string);

        nd_json_save_to_file(json_string, ND_JSON_FILE_STATUS);
    }
    catch (runtime_error &e) {
        nd_printf("Error saving Agent status to file: %s\n",
            e.what());
    }

    if (ND_USE_SINK || ND_EXPORT_JSON) j["flows"] = jflows;

#ifdef _ND_USE_PLUGINS
    if (ND_USE_SINK) {
        json jsr, jtr, jpd;

        nd_json_add_plugin_replies(jsr, jtr, jpd);

        j["service_replies"] = jsr;
        j["task_replies"] = jtr;
        j["data"] = jpd;
    }
#endif

    if (ND_USE_SINK || ND_EXPORT_JSON)
        nd_json_to_string(j, json_string, ND_DEBUG);

    if (ND_USE_SINK) {
        try {
#ifdef _ND_USE_INOTIFY
            for (nd_inotify_watch::const_iterator i = nd_config.inotify_watches.begin();
                i != nd_config.inotify_watches.end(); i++) {
                if (! inotify->EventOccured(i->first)) continue;

                json jd;

                nd_json_add_file(jd, i->first, i->second);
                j["data"].push_back(jd);
            }
#endif
#ifdef _ND_USE_WATCHDOGS
            nd_touch(ND_WD_UPLOAD);
#endif
            if (ND_UPLOAD_ENABLED)
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
        if (ND_EXPORT_JSON)
            nd_json_save_to_file(json_string, nd_config.path_export_json);
    }
    catch (runtime_error &e) {
        nd_printf("Error writing JSON export playload to file: %s: %s\n",
            nd_config.path_export_json, e.what());
    }

    if (ND_DEBUG) {
#ifndef _ND_LEAN_AND_MEAN
        if (ND_DEBUG_WITH_ETHERS) nd_load_ethers();
#endif
        nd_print_stats();
    }
}

#ifndef _ND_LEAN_AND_MEAN
enum ndDumpFlags {
    ndDUMP_NONE = 0x00,
    ndDUMP_TYPE_PROTOS = 0x01,
    ndDUMP_TYPE_APPS = 0x02,
    ndDUMP_TYPE_CAT_APP = 0x04,
    ndDUMP_TYPE_CAT_PROTO = 0x08,
    ndDUMP_TYPE_RISKS = 0x10,
    ndDUMP_TYPE_VALID = 0x20,
    ndDUMP_SORT_BY_TAG = 0x40,
    ndDUMP_TYPE_CATS = (ndDUMP_TYPE_CAT_APP | ndDUMP_TYPE_CAT_PROTO),
    ndDUMP_TYPE_ALL = (ndDUMP_TYPE_PROTOS | ndDUMP_TYPE_APPS)
};

static void nd_dump_protocols(uint8_t type = ndDUMP_TYPE_ALL)
{
    struct ndpi_detection_module_struct *ndpi;

    if (! (type & ndDUMP_TYPE_PROTOS) && ! (type & ndDUMP_TYPE_APPS) &&
        ! (type & ndDUMP_TYPE_CATS) && ! (type & ndDUMP_TYPE_RISKS)) {
        printf("No filter type specified (application, protocol).\n");
        return;
    }

    if (type & ndDUMP_TYPE_CATS &&
        !(type & ndDUMP_TYPE_PROTOS) && !(type & ndDUMP_TYPE_APPS)) {
        ndCategories categories;

        if (categories.Load()) {
            if (type & ndDUMP_TYPE_CAT_APP && ! (type & ndDUMP_TYPE_CAT_PROTO))
                categories.Dump(ndCAT_TYPE_APP);
            else if (! (type & ndDUMP_TYPE_CAT_APP) && type & ndDUMP_TYPE_CAT_PROTO)
                categories.Dump(ndCAT_TYPE_PROTO);
            else
                categories.Dump();
        }
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

        if (nd_apps == NULL) {
            nd_apps = new ndApplications();
            if (! nd_apps->Load(nd_config.path_app_config))
                nd_apps->LoadLegacy(nd_config.path_legacy_config);
        }

        nd_apps_t apps;
        nd_apps->Get(apps);
        for (auto &app : apps) {

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
}

int static nd_lookup_ip(const char *ip)
{
    if (nd_apps == NULL) {
        nd_apps = new ndApplications();
        if (! nd_apps->Load(nd_config.path_app_config))
            nd_apps->LoadLegacy(nd_config.path_legacy_config);
    }

    nd_app_id_t id = 0;
    struct sockaddr_in ip4;
    struct sockaddr_in6 ip6;

    if (inet_pton(AF_INET, ip, &ip4.sin_addr) == 1) {
        id = nd_apps->Find(AF_INET,
            static_cast<void *>(&ip4.sin_addr)
        );
    }
    else if (inet_pton(AF_INET6, ip, &ip6.sin6_addr) == 1) {
        id = nd_apps->Find(AF_INET6,
            static_cast<void *>(&ip6.sin6_addr)
        );
    }
    else {
        fprintf(stderr, "WARNING: Not an IPv4 or IPv6 address: %s\n", ip);
        return 1;
    }

    fprintf(stdout, "%u: %s\n", id, nd_apps->Lookup(id));

    return 0;
}

int static nd_export_applications(void)
{
    if (nd_apps == NULL) {
        nd_apps = new ndApplications();
        if (! nd_apps->Load(nd_config.path_app_config))
            nd_apps->LoadLegacy(nd_config.path_legacy_config);
    }

    if (! nd_apps->Save("/dev/stdout")) return 1;

    return 0;
}
#endif

static void nd_status(void)
{
    const char *color = ND_C_GREEN;

    fprintf(stderr, "%s\n", nd_get_version_and_features().c_str());

    pid_t nd_pid = -1;
    FILE *hpid = fopen(ND_PID_FILE_NAME, "r");
    if (hpid != NULL) {
        char pid[32];
        if (fgets(pid, sizeof(pid), hpid)) {
            nd_pid = nd_is_running(
                (pid_t)strtol(pid, NULL, 0),
                "netifyd"
            );
        }
        fclose(hpid);
    }
    else if (errno == ENOENT)
        nd_pid = 0;

    if (nd_conf_filename == NULL)
        nd_conf_filename = strdup(ND_CONF_FILE_NAME);

    if (nd_config.Load(nd_conf_filename) < 0)
        return;

    if (nd_file_exists(ND_URL_SINK_PATH) > 0) {
        string url_sink;
        if (nd_load_sink_url(url_sink)) {
            free(nd_config.url_sink);
            nd_config.url_sink = strdup(url_sink.c_str());
        }
    }

    fprintf(stderr, "%s-%s agent %s.\n",
        (nd_pid < 0) ? ND_C_YELLOW :
            (nd_pid == 0) ? ND_C_RED : ND_C_GREEN,
        ND_C_RESET,
        (nd_pid < 0) ? "status could not be determined" :
            (nd_pid == 0) ? "is not running" : "is running");

    fprintf(stderr, "- persistent state path: %s\n", ND_PERSISTENT_STATEDIR);
    fprintf(stderr, "- volatile state path: %s\n", ND_VOLATILE_STATEDIR);

    ndJsonStatus json_status;
    bool json_status_valid = false;

    try {
        string status;
        if (nd_file_load(ND_JSON_FILE_STATUS, status) < 0) {
            fprintf(stderr,
                "%s-%s agent run-time status could not be determined.\n",
                ND_C_YELLOW, ND_C_RESET
            );
        }
        else {
            json_status.Parse(status);
            json_status_valid = true;
        }
    }
    catch (runtime_error &e) {
        fprintf(stderr, "%s-%s agent run-time status exception: %s%s%s\n",
            ND_C_RED, ND_C_RESET, ND_C_RED, e.what(), ND_C_RESET);
    }

    if (json_status_valid) {
        char timestamp[64];
        struct tm *tm_local = localtime(&json_status.timestamp);

        if (nd_pid <= 0) {
            fprintf(stderr, "%sThe following information may be out-dated:%s\n",
                ND_C_YELLOW, ND_C_RESET);
        }

        if (strftime(timestamp, sizeof(timestamp), "%c", tm_local) > 0) {
            fprintf(stderr, "%s-%s agent timestamp: %s\n",
                ND_C_GREEN, ND_C_RESET, timestamp);
        }
        string uptime;
        nd_uptime(json_status.uptime, uptime);
        fprintf(stderr, "%s-%s agent uptime: %s\n",
            ND_C_GREEN, ND_C_RESET, uptime.c_str());
        fprintf(stderr, "%s-%s active flows: %u\n",
            ND_C_GREEN, ND_C_RESET, json_status.stats. flows);

        double cpu_user_delta =
            json_status.stats.cpu_user - json_status.stats.cpu_user_prev;
        double cpu_system_delta =
            json_status.stats.cpu_system - json_status.stats.cpu_system_prev;

        double cpu_max_time =
            (double)json_status.update_interval * (double)json_status.stats.cpus;

        double cpu_user_percent = cpu_user_delta * 100.0 / cpu_max_time;
        double cpu_system_percent = cpu_system_delta * 100.0 / cpu_max_time;
        double cpu_total = cpu_user_percent + cpu_system_percent;

        if (cpu_total < 33.34)
            color = ND_C_GREEN;
        else if (cpu_total < 66.67)
            color = ND_C_YELLOW;
        else
            color = ND_C_RED;

        fprintf(stderr, "%s-%s CPU utilization (user + system): %s%.1f%%%s\n",
            color, ND_C_RESET, color, cpu_total, ND_C_RESET);
        fprintf(stderr, "%s-%s CPU time (user / system): %.1fs / %.1fs\n",
            color, ND_C_RESET, cpu_user_delta, cpu_system_delta);

#if (defined(_ND_USE_LIBTCMALLOC) && defined(HAVE_GPERFTOOLS_MALLOC_EXTENSION_H)) || \
    (defined(_ND_USE_LIBJEMALLOC) && defined(HAVE_JEMALLOC_JEMALLOC_H))
#if (SIZEOF_LONG == 4)
        fprintf(stderr, "%s-%s current memory usage: %u kB\n",
            ND_C_GREEN, ND_C_RESET, json_status.stats.tcm_alloc_kb);
#elif (SIZEOF_LONG == 8)
        fprintf(stderr, "%s-%s current memory usage: %lu kB\n",
            ND_C_GREEN, ND_C_RESET, json_status.stats.tcm_alloc_kb);
#endif
#endif // _ND_USE_LIBTCMALLOC || _ND_USE_LIBJEMALLOC
#if (SIZEOF_LONG == 4)
        fprintf(stderr, "%s-%s maximum memory usage: %u kB\n",
            ND_C_GREEN, ND_C_RESET, json_status.stats.maxrss_kb);
#elif (SIZEOF_LONG == 8)
        fprintf(stderr, "%s-%s maximum memory usage: %lu kB\n",
            ND_C_GREEN, ND_C_RESET, json_status.stats.maxrss_kb);
#endif
        fprintf(stderr, "%s-%s DNS hint cache: %s%s%s\n",
            (json_status.stats.dhc_status) ? ND_C_GREEN : ND_C_YELLOW,
            ND_C_RESET,
            (json_status.stats.dhc_status) ? ND_C_GREEN : ND_C_YELLOW,
            (json_status.stats.dhc_status) ? "enabled" : "disabled",
            ND_C_RESET
        );

        if (json_status.stats.dhc_status) {
#if (SIZEOF_LONG == 4)
            fprintf(stderr, "%s-%s DNS hint cache entries: %u\n",
                ND_C_GREEN, ND_C_RESET, json_status.stats.dhc_size);
#elif (SIZEOF_LONG == 8)
            fprintf(stderr, "%s-%s DNS hint cache entries: %lu\n",
                ND_C_GREEN, ND_C_RESET, json_status.stats.dhc_size);
#endif
        }
    }

    fprintf(stderr, "%s-%s sink URL: %s\n",
        ND_C_GREEN, ND_C_RESET, nd_config.url_sink);
    fprintf(stderr, "%s-%s sink services are %s.\n",
        (ND_USE_SINK) ? ND_C_GREEN : ND_C_RED, ND_C_RESET,
        (ND_USE_SINK) ? "enabled" : "disabled"
    );
    if (! ND_USE_SINK) {
        fprintf(stderr, "  To enable sink services, run the following command:\n");
        fprintf(stderr, "  # netifyd --enable-sink\n");
    }
    fprintf(stderr, "%s-%s sink uploads are %s.\n",
        (json_status.stats.sink_uploads) ? ND_C_GREEN : ND_C_RED, ND_C_RESET,
        (json_status.stats.sink_uploads) ? "enabled" : "disabled"
    );
    if (! json_status.stats.sink_uploads)
        fprintf(stderr, "  To enable sink uploads, ensure your Agent has been provisioned.\n");

    string uuid;

    uuid = (nd_config.uuid != NULL) ? nd_config.uuid : "00-00-00-00";
    if (nd_file_exists(nd_config.path_uuid) > 0)
        nd_load_uuid(uuid, nd_config.path_uuid, ND_AGENT_UUID_LEN);

    if (uuid.size() != ND_AGENT_UUID_LEN || uuid == "00-00-00-00") {
        fprintf(stderr, "%s-%s sink agent UUID is not set.\n",
            ND_C_RED, ND_C_RESET);
        fprintf(stderr, "  To generate a new one, run the following command:\n");
        fprintf(stderr, "  # netifyd --provision\n");
    }
    else {
        fprintf(stderr, "%s-%s sink agent UUID: %s\n",
            ND_C_GREEN, ND_C_RESET, uuid.c_str());
    }

    uuid = (nd_config.uuid_serial != NULL) ? nd_config.uuid_serial : "-";
    if (nd_file_exists(nd_config.path_uuid_serial) > 0)
        nd_load_uuid(uuid, nd_config.path_uuid_serial, ND_AGENT_SERIAL_LEN);

    if (uuid.size() && uuid != "-") {
        fprintf(stderr, "%s-%s sink serial UUID: %s\n",
            ND_C_GREEN, ND_C_RESET, uuid.c_str());
    }

    uuid = (nd_config.uuid_site != NULL) ? nd_config.uuid_site : "-";
    if (nd_file_exists(nd_config.path_uuid_site) > 0)
        nd_load_uuid(uuid, nd_config.path_uuid_site, ND_SITE_UUID_LEN);

    if (! uuid.size() || uuid == "-") {
        fprintf(stderr, "%s-%s sink site UUID is not set.\n",
            ND_C_YELLOW, ND_C_RESET);
        fprintf(stderr, "  A new site UUID will be automatically set "
            "after this agent has been provisioned by the sink server.\n");
    }
    else {
        fprintf(stderr, "%s-%s sink site UUID: %s\n",
            ND_C_GREEN, ND_C_RESET, uuid.c_str());
    }

    if (json_status_valid && json_status.stats.sink_status) {
        string status, help;
        color = ND_C_GREEN;

        switch (json_status.stats.sink_resp_code) {
        case ndJSON_RESP_NULL:
            status = "not available";
            color = ND_C_YELLOW;
            help = "Sink status not yet available, try again.";
            break;
        case ndJSON_RESP_OK:
            status = "ok";
            break;
        case ndJSON_RESP_AUTH_FAIL:
            status = "authorization failed";
            color = ND_C_YELLOW;
            help = "If no site UUID is set, please provision this agent.";
            break;
        case ndJSON_RESP_MALFORMED_DATA:
            status = "malformed data";
            color = ND_C_RED;
            help = "This should never happen, please contact support.";
            break;
        case ndJSON_RESP_SERVER_ERROR:
            status = "server error";
            color = ND_C_RED;
            help = "Contact support if this error persists.";
            break;
        case ndJSON_RESP_POST_ERROR:
            status = "upload error";
            color = ND_C_YELLOW;
            help = "This error should resolve automatically.";
            break;
        case ndJSON_RESP_PARSE_ERROR:
            status = "parse error";
            color = ND_C_RED;
            help = "This should never happen, please contact support.";
            break;
        case ndJSON_RESP_INVALID_RESPONSE:
            status = "invalid response";
            color = ND_C_RED;
            help = "This should never happen, please contact support.";
            break;
        case ndJSON_RESP_INVALID_CONTENT_TYPE:
            status = "invalid response content type";
            color = ND_C_RED;
            help = "This should never happen, please contact support.";
            break;
        default:
            status = "unknown error";
            color = ND_C_RED;
            help = "This should never happen, please contact support.";
            break;
        }

        fprintf(stderr, "%s-%s sink server status: %s%s (%d)%s\n",
            color, ND_C_RESET, color,
            status.c_str(), json_status.stats.sink_resp_code,
            ND_C_RESET
        );

        if (help.size() > 0)
            fprintf(stderr, "  %s\n", help.c_str());

        float sink_util =
            (float)((json_status.stats.sink_queue_size / 1024) * 100.0f) /
            (float)json_status.sink_queue_max_size_kb;
        if (sink_util < 33.34f)
            color = ND_C_GREEN;
        else if (sink_util < 66.67f)
            color = ND_C_YELLOW;
        else
            color = ND_C_RED;

        fprintf(stderr, "%s-%s sink queue utilization: %s%.1f%%%s\n",
            color, ND_C_RESET, color, sink_util, ND_C_RESET);
    }
}

#ifdef _ND_USE_NETLINK
static void nd_add_device_addresses(nd_device_addr &device_addresses)
{
    char *token = NULL;
    struct sockaddr_in network_ip4;
    struct sockaddr_in bcast_ip4;
    struct sockaddr_in6 network_ip6;
    int bit, word, words;
    uint32_t b, word_net[4] = { 0, 0, 0, 0 }, word_bcast[1] = { 0 };
    char netaddr[INET6_ADDRSTRLEN], bcastaddr[INET6_ADDRSTRLEN];

    for (nd_device_addr::const_iterator i = device_addresses.begin();
        i != device_addresses.end(); i++) {

        sa_family_t family = AF_UNSPEC;

        token = (char *)realloc(token, (*i).second.size() + 1);
        strncpy(token, (*i).second.c_str(), (*i).second.size() + 1);

        const char *address = strtok(token, "/");
        if (address == NULL) {
            fprintf(stderr, "WARNING: Invalid address, use CIDR notation: %s\n",
                (*i).second.c_str());
            continue;
        }

        if (inet_pton(AF_INET, address, &network_ip4.sin_addr) == 1) {
            words = 1;
            word_net[0] = ntohl(network_ip4.sin_addr.s_addr);
            word_bcast[0] = ntohl(network_ip4.sin_addr.s_addr);
            family = AF_INET;
        }
        else if (inet_pton(AF_INET6, address, &network_ip6.sin6_addr) == 1) {
            words = 4;
            word_net[0] = ntohl(network_ip6.sin6_addr.s6_addr32[0]);
            word_net[1] = ntohl(network_ip6.sin6_addr.s6_addr32[1]);
            word_net[2] = ntohl(network_ip6.sin6_addr.s6_addr32[2]);
            word_net[3] = ntohl(network_ip6.sin6_addr.s6_addr32[3]);
            family = AF_INET6;
        }
        else {
            fprintf(stderr, "WARNING: Not an IPv4 or IPv6 address: %s\n", address);
            continue;
        }

        const char *length = strtok(NULL, "/");
        if (length == NULL) {
            fprintf(stderr, "WARNING: Invalid address, use CIDR notation: %s\n",
                (*i).second.c_str());
            continue;
        }

        uint8_t _length = (uint8_t)atoi(length);
        if (_length == 0 || (
            (family == AF_INET && _length > 32) ||
            (family == AF_INET6 && _length > 128))) {
            fprintf(stderr, "WARNING: Invalid network length: %hhu\n", _length);
            continue;
        }

        nd_dprintf("%s: %s: address: %s, length: %hu\n",
            __PRETTY_FUNCTION__, (*i).first.c_str(), address, _length);

        bit = (int)_length;

        for (word = 0; word < words; word++) {
            for (b = 0x80000000; b > 0; b >>= 1, bit--) {
                if (bit < 1) word_net[word] &= ~b;
            }
        }

        switch (family) {
        case AF_INET:
            network_ip4.sin_addr.s_addr = htonl(word_net[0]);
            inet_ntop(AF_INET,
                &network_ip4.sin_addr, netaddr, INET_ADDRSTRLEN);

            bit = (int)_length;

            for (word = 0; word < words; word++) {
                for (b = 0x80000000; b > 0; b >>= 1, bit--) {
                    if (bit < 1) word_bcast[word] |= b;
                }
            }

            bcast_ip4.sin_addr.s_addr = htonl(word_bcast[0]);
            inet_ntop(AF_INET,
                &bcast_ip4.sin_addr, bcastaddr, INET_ADDRSTRLEN);

            if (! netlink->AddAddress(family, _ND_NETLINK_BROADCAST, bcastaddr))
                fprintf(stderr, "WARNING: Error adding device address: %s\n", bcastaddr);

            break;

        case AF_INET6:
            network_ip6.sin6_addr.s6_addr32[0] = htonl(word_net[0]);
            network_ip6.sin6_addr.s6_addr32[1] = htonl(word_net[1]);
            network_ip6.sin6_addr.s6_addr32[2] = htonl(word_net[2]);
            network_ip6.sin6_addr.s6_addr32[3] = htonl(word_net[3]);
            inet_ntop(AF_INET6,
                &network_ip6.sin6_addr, netaddr, INET6_ADDRSTRLEN);
            break;
        }

        if (! netlink->AddNetwork(family, (*i).first, netaddr, _length)) {
            fprintf(stderr, "WARNING: Error adding device network: %s\n",
                (*i).second.c_str());
        }

        if (! netlink->AddAddress(family, (*i).first, address)) {
            fprintf(stderr, "WARNING: Error adding device address: %s\n", address);
        }
    }

    if (token != NULL) free(token);
}
#endif // _ND_USE_NETLINK

static int nd_check_agent_uuid(void)
{
    if (nd_config.uuid == NULL ||
        ! strncmp(nd_config.uuid, ND_AGENT_UUID_NULL, ND_AGENT_UUID_LEN)) {
        string uuid;
        if (! nd_load_uuid(uuid, ND_AGENT_UUID_PATH, ND_AGENT_UUID_LEN) ||
            ! uuid.size() ||
            ! strncmp(uuid.c_str(), ND_AGENT_UUID_NULL, ND_AGENT_UUID_LEN)) {
            nd_generate_uuid(uuid);
            printf("Generated a new Agent UUID: %s\n", uuid.c_str());
            if (! nd_save_uuid(uuid, ND_AGENT_UUID_PATH, ND_AGENT_UUID_LEN))
                return 1;
        }
        if (nd_config.uuid != NULL)
            free(nd_config.uuid);
        nd_config.uuid = strdup(uuid.c_str());
    }

    return 0;
}

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
#ifndef _ND_LEAN_AND_MEAN
    uint8_t dump_flags = ndDUMP_NONE;
#endif
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

    nd_conf_filename = strdup(ND_CONF_FILE_NAME);

    openlog(PACKAGE_TARNAME, LOG_NDELAY | LOG_PID | LOG_PERROR, LOG_DAEMON);

    nd_seed_rng();

    nd_flow_count = 0;

    memset(&nd_json_agent_stats, 0, sizeof(nd_agent_stats));
    nd_json_agent_stats.cpus = sysconf(_SC_NPROCESSORS_ONLN);

    static struct option options[] =
    {
        { "config", 1, 0, 'c' },
        { "debug", 0, 0, 'd' },
        { "debug-ether-names", 0, 0, 'e' },
        { "debug-ndpi", 0, 0, 'n' },
        { "debug-uploads", 0, 0, 'D' },
        { "device-address", 1, 0, 'A' },
        { "device-filter", 1, 0, 'F' },
        { "device-netlink", 1, 0, 'N' },
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

    while (true) {
        if ((rc = getopt_long(argc, argv,
            "?A:c:DdE:eF:f:hI:i:j:lN:nPpRrS:stT:Uu:Vv",
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
            nd_config.ca_capture_base = (int16_t)atoi(optarg);
            if (nd_config.ca_capture_base > nd_json_agent_stats.cpus) {
                fprintf(stderr, "Capture thread base greater than online cores.\n");
                exit(1);
            }
            break;
        case _ND_LO_CA_CONNTRACK:
            nd_config.ca_conntrack = (int16_t)atoi(optarg);
            if (nd_config.ca_conntrack > nd_json_agent_stats.cpus) {
                fprintf(stderr, "Conntrack thread ID greater than online cores.\n");
                exit(1);
            }
            break;
        case _ND_LO_CA_DETECTION_BASE:
            nd_config.ca_detection_base = (int16_t)atoi(optarg);
            if (nd_config.ca_detection_base > nd_json_agent_stats.cpus) {
                fprintf(stderr, "Detection thread base greater than online cores.\n");
                exit(1);
            }
            break;
        case _ND_LO_CA_DETECTION_CORES:
            nd_config.ca_detection_cores = (int16_t)atoi(optarg);
            if (nd_config.ca_detection_cores > nd_json_agent_stats.cpus) {
                fprintf(stderr, "Detection cores greater than online cores.\n");
                exit(1);
            }
            break;
        case _ND_LO_CA_SINK:
            nd_config.ca_sink = (int16_t)atoi(optarg);
            if (nd_config.ca_sink > nd_json_agent_stats.cpus) {
                fprintf(stderr, "Sink thread ID greater than online cores.\n");
                exit(1);
            }
            break;
        case _ND_LO_CA_SOCKET:
            nd_config.ca_socket = (int16_t)atoi(optarg);
            if (nd_config.ca_socket > nd_json_agent_stats.cpus) {
                fprintf(stderr, "Socket thread ID greater than online cores.\n");
                exit(1);
            }
            break;
        case _ND_LO_WAIT_FOR_CLIENT:
            nd_config.flags |= ndGF_WAIT_FOR_CLIENT;
            break;

        case _ND_LO_DUMP_SORT_BY_TAG:
#ifndef _ND_LEAN_AND_MEAN
            dump_flags |= ndDUMP_SORT_BY_TAG;
#else
            fprintf(stderr, "Sorry, this feature was disabled (embedded).\n");
            exit(1);
#endif
            break;

        case _ND_LO_EXPORT_APPS:
#ifndef _ND_LEAN_AND_MEAN
            exit(nd_export_applications());
#else
            fprintf(stderr, "Sorry, this feature was disabled (embedded).\n");
            exit(1);
#endif
        case _ND_LO_DUMP_PROTOS:
#ifndef _ND_LEAN_AND_MEAN
            nd_dump_protocols(ndDUMP_TYPE_PROTOS | dump_flags);
            exit(0);
#else
            fprintf(stderr, "Sorry, this feature was disabled (embedded).\n");
            exit(1);
#endif
        case _ND_LO_DUMP_APPS:
#ifndef _ND_LEAN_AND_MEAN
            nd_dump_protocols(ndDUMP_TYPE_APPS | dump_flags);
            exit(0);
#else
            fprintf(stderr, "Sorry, this feature was disabled (embedded).\n");
            exit(1);
#endif
        case _ND_LO_DUMP_CAT:
#ifndef _ND_LEAN_AND_MEAN
            if (strncasecmp("protocol", optarg, 8) == 0)
                nd_dump_protocols(ndDUMP_TYPE_CAT_APP | dump_flags);
            else if (strncasecmp("application", optarg, 11) == 0)
                nd_dump_protocols(ndDUMP_TYPE_CAT_PROTO | dump_flags);
            exit(0);
#else
            fprintf(stderr, "Sorry, this feature was disabled (embedded).\n");
            exit(1);
#endif
        case _ND_LO_DUMP_CATS:
#ifndef _ND_LEAN_AND_MEAN
            nd_dump_protocols(ndDUMP_TYPE_CATS | dump_flags);
            exit(0);
#else
            fprintf(stderr, "Sorry, this feature was disabled (embedded).\n");
            exit(1);
#endif
        case _ND_LO_DUMP_RISKS:
#ifndef _ND_LEAN_AND_MEAN
            nd_dump_protocols(ndDUMP_TYPE_RISKS | dump_flags);
            exit(0);
#else
            fprintf(stderr, "Sorry, this feature was disabled (embedded).\n");
            exit(1);
#endif
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
            device_addresses.push_back(make_pair(last_device, optarg));
            break;
        case 'c':
            if (nd_conf_filename != NULL) free(nd_conf_filename);
            nd_conf_filename = strdup(optarg);
            break;
        case 'd':
            nd_config.flags |= ndGF_DEBUG;
            break;
        case 'D':
            nd_config.flags |= ndGF_DEBUG_UPLOAD;
            break;
        case 'E':
            for (nd_interface::iterator i = nd_interfaces.begin();
                i != nd_interfaces.end(); i++) {
                if (strcasecmp((*i).second.c_str(), optarg) == 0) {
                    fprintf(stderr, "Duplicate interface specified: %s\n", optarg);
                    exit(1);
                }
            }
            last_device = optarg;
            nd_interfaces.push_back(make_pair(false, optarg));
            break;
        case 'e':
            nd_config.flags |= ndGF_DEBUG_WITH_ETHERS;
            break;
        case 'F':
            if (last_device.size() == 0) {
                fprintf(stderr, "You must specify an interface first (-I/E).\n");
                exit(1);
            }
            if (nd_config.device_filters
                .find(last_device) != nd_config.device_filters.end()) {
                fprintf(stderr, "Only one filter can be applied to a device.\n");
                exit(1);
            }
            nd_config.device_filters[last_device] = optarg;
            break;
        case 'f':
            free(nd_config.path_legacy_config);
            nd_config.path_legacy_config = strdup(optarg);
            break;
        case 'h':
            nd_usage();
        case 'I':
            for (nd_interface::iterator i = nd_interfaces.begin(); i != nd_interfaces.end(); i++) {
                if (strcasecmp((*i).second.c_str(), optarg) == 0) {
                    fprintf(stderr, "Duplicate interface specified: %s\n", optarg);
                    exit(1);
                }
            }
            last_device = optarg;
            nd_interfaces.push_back(make_pair(true, optarg));
            break;
        case 'i':
            nd_config.update_interval = atoi(optarg);
            break;
        case 'j':
            nd_config.path_export_json = strdup(optarg);
            break;
        case 'l':
            nd_config.flags &= ~ndGF_USE_NETLINK;
            break;
        case 'n':
            nd_config.flags |= ndGF_DEBUG_NDPI;
            break;
        case 'N':
#if _ND_USE_NETLINK
            if (last_device.size() == 0) {
                fprintf(stderr, "You must specify an interface first (-I/E).\n");
                exit(1);
            }
            nd_netlink_devices[last_device] = optarg;
#else
            fprintf(stderr, "Sorry, this feature was disabled (embedded).\n");
            return 1;
#endif
            break;
        case 'P':
#ifndef _ND_LEAN_AND_MEAN
            nd_dump_protocols(ndDUMP_TYPE_ALL | dump_flags);
            exit(0);
#else
            fprintf(stderr, "Sorry, this feature was disabled (embedded).\n");
            exit(1);
#endif
        case 'p':
            if (nd_conf_filename == NULL)
                nd_conf_filename = strdup(ND_CONF_FILE_NAME);
            if (nd_config.Load(nd_conf_filename) < 0)
                return 1;
            if (nd_check_agent_uuid() || nd_config.uuid == NULL) return 1;
            printf("Agent UUID: %s\n", nd_config.uuid);
            return 0;
        case 'R':
            nd_config.flags |= ndGF_REMAIN_IN_FOREGROUND;
            break;
        case 'r':
            nd_config.flags |= ndGF_REPLAY_DELAY;
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
            nd_config.flags &= ~ndGF_USE_CONNTRACK;
            break;
        case 'T':
            if ((nd_config.h_flow = fopen(optarg, "w")) == NULL) {
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
            nd_config.uuid = strdup(optarg);
            break;
        case 'V':
            nd_usage(0, true);
            break;
        case 'v':
            nd_config.flags |= ndGF_VERBOSE;
            break;
        default:
            nd_usage(1);
        }
    }

    if (nd_config.path_export_json == NULL)
        nd_config.path_export_json = strdup(ND_JSON_FILE_EXPORT);

    if (nd_conf_filename == NULL)
        nd_conf_filename = strdup(ND_CONF_FILE_NAME);

    if (nd_config.Load(nd_conf_filename) < 0)
        return 1;

    {
        string url_sink;
        if (nd_load_sink_url(url_sink)) {
            free(nd_config.url_sink);
            nd_config.url_sink = strdup(url_sink.c_str());
        }
    }

    if (nd_config.h_flow != stderr) {
        // Test mode enabled, disable/set certain config parameters
        ND_GF_SET_FLAG(ndGF_USE_DHC, true);
        ND_GF_SET_FLAG(ndGF_USE_FHC, true);
        ND_GF_SET_FLAG(ndGF_USE_SINK, false);
        ND_GF_SET_FLAG(ndGF_EXPORT_JSON, false);
        ND_GF_SET_FLAG(ndGF_REMAIN_IN_FOREGROUND, true);

        nd_config.update_interval = 1;
#ifdef _ND_USE_PLUGINS
        nd_config.plugin_services.clear();
        nd_config.plugin_tasks.clear();
        nd_config.plugin_detections.clear();
        nd_config.plugin_stats.clear();
#endif
        nd_config.dhc_save = ndDHC_DISABLED;
        nd_config.fhc_save = ndFHC_DISABLED;
    }

    if (nd_interfaces.size() == 0) {
        fprintf(stderr,
            "Required argument, (-I, --internal, or -E, --external) missing.\n");
        return 1;
    }

    CURLcode cc;
    if ((cc = curl_global_init(CURL_GLOBAL_ALL)) != 0) {
        fprintf(stderr, "Unable to initialize libCURL: %d\n", cc);
        return 1;
    }

    if (! ND_DEBUG && ! ND_REMAIN_IN_FOREGROUND) {
        if (daemon(1, 0) != 0) {
            nd_printf("daemon: %s\n", strerror(errno));
            return 1;
        }
    }

    if (ND_USE_DHC)
        dns_hint_cache = new ndDNSHintCache();

    if (ND_USE_FHC)
        flow_hash_cache = new ndFlowHashCache(nd_config.max_fhc);

    nd_printf("%s\n", nd_get_version_and_features().c_str());

    nd_check_agent_uuid();
#ifndef _ND_LEAN_AND_MEAN
    nd_dprintf("Flow entry size: %lu\n", sizeof(struct ndFlow) +
        sizeof(struct ndpi_flow_struct));
#endif
#if defined(_ND_USE_LIBJEMALLOC) && defined(HAVE_JEMALLOC_JEMALLOC_H)
    bool je_state = false, je_enable = true;
    size_t je_opt_size = sizeof(bool);
    const char *je_opt = "thread.tcache.enabled";

    rc = mallctl(
        je_opt,
        (void *)&je_state, &je_opt_size,
        (void *)&je_enable, je_opt_size
    );

    if (rc != 0)
        nd_printf("JEMALLOC::mallctl: %s: %d\n", je_opt, rc);
    else {
        nd_dprintf("JEMALLOC:mallctl: %s: enabled: %s (%s)\n", je_opt,
            (je_enable) ? "yes" : "no", (je_state) ? "yes" : "no");
    }
#endif
    if (! ND_DEBUG) {
        FILE *hpid = fopen(ND_PID_FILE_NAME, "w+");

        do {
            if (hpid == NULL) {
                nd_printf("Error opening PID file: %s: %s\n",
                    ND_PID_FILE_NAME, strerror(errno));

                if (mkdir(ND_VOLATILE_STATEDIR, 0755) == 0)
                    hpid = fopen(ND_PID_FILE_NAME, "w+");
                else {
                    nd_printf("Unable to create volatile state directory: %s: %s\n",
                        ND_VOLATILE_STATEDIR, strerror(errno));
                    return 1;
                }
            }
        } while(hpid == NULL);

        fprintf(hpid, "%d\n", getpid());
        fclose(hpid);
    }

    memset(&pkt_totals, 0, sizeof(nd_packet_stats));

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &nd_json_agent_stats.ts_epoch) != 0) {
        nd_printf("Error getting epoch time: %s\n", strerror(errno));
        return 1;
    }

    if (dns_hint_cache) dns_hint_cache->load();
    if (flow_hash_cache) flow_hash_cache->load();

    nd_sha1_file(
        nd_config.path_app_config, nd_config.digest_app_config
    );
    nd_sha1_file(
        nd_config.path_legacy_config, nd_config.digest_legacy_config
    );

    sigfillset(&sigset);
    //sigdelset(&sigset, SIGPROF);
    //sigdelset(&sigset, SIGINT);
    sigdelset(&sigset, SIGQUIT);
    sigprocmask(SIG_BLOCK, &sigset, NULL);

    sigemptyset(&sigset);
    sigaddset(&sigset, ND_SIG_SINK_REPLY);
    sigaddset(&sigset, ND_SIG_UPDATE);
    sigaddset(&sigset, ND_SIG_CONNECT);
    sigaddset(&sigset, ND_SIG_NAPI_UPDATE);
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

#ifndef _ND_LEAN_AND_MEAN
    if (ND_DEBUG_WITH_ETHERS) nd_load_ethers();
#endif

    try {
#ifdef _ND_USE_CONNTRACK
        if (ND_USE_CONNTRACK) {
            thread_conntrack = new ndConntrackThread(nd_config.ca_conntrack);
            thread_conntrack->Create();
        }
#endif
        if (nd_config.socket_host.size() || nd_config.socket_path.size())
            thread_socket = new ndSocketThread(nd_config.ca_socket);

        if (ND_USE_SINK) {
            thread_sink = new ndSinkThread(nd_config.ca_sink);
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
#ifdef _ND_USE_INOTIFY
    try {
        inotify = new ndInotify();
        for (nd_inotify_watch::const_iterator i = nd_config.inotify_watches.begin();
            i != nd_config.inotify_watches.end(); i++)
            inotify->AddWatch(i->first, i->second);
        if (nd_config.inotify_watches.size()) inotify->RefreshWatches();
    }
    catch (exception &e) {
        nd_printf("Error creating file watches: %s\n", e.what());
        return 1;
    }
#endif
#ifdef _ND_USE_NETLINK
    if (ND_USE_NETLINK) {
        try {
            netlink = new ndNetlink(nd_interfaces);

            nd_netlink_device::const_iterator i;
            for (i = nd_netlink_devices.begin(); i != nd_netlink_devices.end(); i++)
                netlink->AddInterface(i->second);
        }
        catch (exception &e) {
            nd_printf("Error creating netlink watch: %s\n", e.what());
            return 1;
        }

        nd_add_device_addresses(device_addresses);
    }
#endif
    nd_init();
    ndpi_global_init();

    nd_dprintf("Online CPU cores: %ld\n", nd_json_agent_stats.cpus);

    if (nd_start_detection_threads() < 0)
        return 1;

    try {
        if (thread_socket != NULL)
            thread_socket->Create();
    }
    catch (ndThreadException &e) {
        nd_printf("Error starting socket thread: %s\n", e.what());
        return 1;
    }

    if (thread_socket == NULL || ! ND_WAIT_FOR_CLIENT) {
        if (nd_start_capture_threads() < 0)
            return 1;
    }
    else if (thread_socket != NULL && ND_WAIT_FOR_CLIENT) {
        do {
            nd_dprintf("Waiting for a client to connect...\n");
            sleep(1);
        } while (thread_socket->GetClientCount() == 0);

        if (nd_start_capture_threads() < 0)
            return 1;
    }

#ifdef _ND_USE_PLUGINS
    if (nd_plugin_start_services() < 0)
        return 1;
    if (nd_plugin_start_detections() < 0)
        return 1;
    if (nd_plugin_start_stats() < 0)
        return 1;
#endif
    // XXX: Always send an update on start-up...
    nd_dump_stats();

#ifdef _ND_USE_NETLINK
    if (ND_USE_NETLINK) netlink->Refresh();
#endif
    memset(&sigev, 0, sizeof(struct sigevent));
    sigev.sigev_notify = SIGEV_SIGNAL;
    sigev.sigev_signo = ND_SIG_UPDATE;

    if (timer_create(CLOCK_MONOTONIC, &sigev, &timer_update) < 0) {
        nd_printf("timer_create: %s\n", strerror(errno));
        return 1;
    }

    itspec_update.it_value.tv_sec = nd_config.update_interval;
    itspec_update.it_value.tv_nsec = 0;
    itspec_update.it_interval.tv_sec = nd_config.update_interval;
    itspec_update.it_interval.tv_nsec = 0;

    timer_settime(timer_update, 0, &itspec_update, NULL);

    if (ND_USE_NAPI) {
        memset(&sigev, 0, sizeof(struct sigevent));
        sigev.sigev_notify = SIGEV_SIGNAL;
        sigev.sigev_signo = ND_SIG_NAPI_UPDATE;

        if (timer_create(CLOCK_MONOTONIC, &sigev, &timer_napi) < 0) {
            nd_printf("timer_create: %s\n", strerror(errno));
            return 1;
        }

        time_t ttl = 3;
        if (nd_categories->GetLastUpdate() > 0) {
            time_t age = time(NULL) - nd_categories->GetLastUpdate();
            if (age < nd_config.ttl_napi_update)
                ttl = nd_config.ttl_napi_update - age;
            else if (age == nd_config.ttl_napi_update)
                ttl = nd_config.ttl_napi_update;
        }

        itspec_update.it_value.tv_sec = ttl;
        itspec_update.it_value.tv_nsec = 0;
        itspec_update.it_interval.tv_sec = nd_config.ttl_napi_update;
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
        else if (sig == ND_SIG_CONNECT) {
            nd_dprintf("Caught signal: [%d] %s: Client connected\n", sig, strsignal(sig));
        }
        else if (sig == ND_SIG_NAPI_UPDATE) {
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
#ifdef _ND_USE_INOTIFY
            inotify->RefreshWatches();
#endif
            nd_dump_stats();
            nd_plugin_event(ndPlugin::EVENT_STATUS_UPDATE);
#ifdef _ND_USE_PLUGINS
            nd_plugin_reap_tasks();
#endif
            if (dns_hint_cache)
                dns_hint_cache->purge();
#if !defined(_ND_USE_LIBTCMALLOC) && !defined(_ND_USE_LIBJEMALLOC) && defined(HAVE_MALLOC_TRIM)
            // Attempt to release heap back to OS when supported
            malloc_trim(0);
#endif
#if defined(_ND_USE_LIBJEMALLOC) && defined(HAVE_JEMALLOC_JEMALLOC_H)
            malloc_stats_print(NULL, NULL, "");
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
#ifdef _ND_USE_INOTIFY
            if (inotify->GetDescriptor() == si.si_fd)
                inotify->ProcessEvent();
#endif

#if defined(_ND_USE_NETLINK) && defined(HAVE_LINUX_NETLINK_H)
            if (ND_USE_NETLINK &&
                netlink->GetDescriptor() == si.si_fd) {
#ifndef _ND_LEAN_AND_MEAN
                if (netlink->ProcessEvent())
                    if (ND_DEBUG) netlink->Dump();
#else
                netlink->ProcessEvent();
#endif
            }
#endif
            continue;
        }

        if (sig == ND_SIG_SINK_REPLY) {
            if (ND_USE_SINK && nd_sink_process_responses() < 0) {
                nd_dprintf("nd_sink_process_responses failed!\n");
                break;
            }
            continue;
        }

        if (sig == ND_SIG_CONNECT) {
            for (nd_capture_threads::const_iterator t = capture_threads.begin();
                t != capture_threads.end(); t++) (*t).second->SendIPC(ND_SIG_CONNECT);
            continue;
        }

        if (sig == ND_SIG_NAPI_UPDATE) {
            if (thread_napi == NULL) {
                thread_napi = new ndNetifyApiThread();
                thread_napi->Create();
            }
            continue;
        }

        if (sig == ND_SIG_NAPI_UPDATED) {
            if (nd_domains != NULL)
                nd_domains->Load();

            if (nd_categories != NULL)
                nd_categories->Load();

            if (thread_napi != NULL) {
                delete thread_napi;
                thread_napi = NULL;

                nd_plugin_event(ndPlugin::EVENT_CATEGORIES_UPDATE);
            }
            continue;
        }

        if (sig == SIGHUP) {
            nd_printf("Reloading configuration...\n");
            if (! nd_apps->Load(nd_config.path_app_config))
                nd_apps->LoadLegacy(nd_config.path_legacy_config);
            nd_categories->Load();
            nd_domains->Load();
            nd_plugin_event(ndPlugin::EVENT_RELOAD);
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

    if (thread_socket) {
        thread_socket->Terminate();
        delete thread_socket;
    }

    timer_delete(timer_update);
    timer_delete(timer_napi);

    nd_stop_detection_threads();

    nd_destroy();

#ifdef _ND_USE_PLUGINS
    nd_plugin_stop_services();
    nd_plugin_stop_detections();
    nd_plugin_stop_stats();

    nd_plugin_stop_tasks();
    nd_plugin_reap_tasks();
#endif

    if (thread_sink) {
        thread_sink->Terminate();
        delete thread_sink;
    }

#ifdef _ND_USE_CONNTRACK
    if (ND_USE_CONNTRACK && thread_conntrack) {
        thread_conntrack->Terminate();
        delete thread_conntrack;
    }
#endif

    if (dns_hint_cache) {
        dns_hint_cache->save();
        delete dns_hint_cache;
    }

    if (flow_hash_cache) {
        flow_hash_cache->save();
        delete flow_hash_cache;
    }

    nd_ifaddrs_free(nd_interface_addrs);

    nd_dprintf("Normal exit.\n");

    curl_global_cleanup();

    closelog();

    if (! ND_DEBUG) unlink(ND_PID_FILE_NAME);

    return 0;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
