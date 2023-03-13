// Netify Agent 🥷🏿
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
#include <bitset>

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

#include <radix/radix_tree.hpp>

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
#include "nd-socket.h"
#include "nd-sink.h"
#include "nd-base64.h"
#ifdef _ND_USE_PLUGINS
#include "nd-plugin.h"
#endif
#include "nd-signal.h"
#include "nd-napi.h"

extern ndInterfaces nd_interfaces;

ndGlobalConfig nd_config;

ndGlobalConfig::ndGlobalConfig() :
    napi_vendor(NULL),
    path_agent_status(ND_AGENT_STATUS_PATH),
    path_app_config(ND_CONF_APP_PATH),
    path_cat_config(ND_CONF_CAT_PATH),
    path_config(ND_CONF_FILE_NAME),
    path_export_json(ND_JSON_FILE_EXPORT),
    path_legacy_config(ND_CONF_LEGACY_PATH),
    path_pid_file(ND_PID_FILE_NAME),
    path_state_persistent(ND_PERSISTENT_STATEDIR),
    path_state_volatile(ND_VOLATILE_STATEDIR),
    path_uuid(ND_AGENT_UUID_PATH),
    path_uuid_serial(ND_AGENT_SERIAL_PATH),
    path_uuid_site(ND_SITE_UUID_PATH),
    url_napi(NULL),
    url_sink(NULL),
    url_sink_provision(NULL),
    uuid(NULL),
    uuid_serial(NULL),
    uuid_site(NULL),
    dhc_save(ndDHC_PERSISTENT),
    fhc_save(ndFHC_PERSISTENT),
    capture_type(ndCT_NONE),
    capture_read_timeout(ND_CAPTURE_READ_TIMEOUT),
    tpv3_defaults {
        ndFOM_DISABLED, // fanout_mode
        ndFOF_NONE, // fanout_flags
        0, // fanout_instances
        ND_TPV3_RB_BLOCK_SIZE, // rb_block_size
        ND_TPV3_RB_FRAME_SIZE, // rb_frame_size
        ND_TPV3_RB_BLOCKS // rb_blocks
    },
    h_flow(stderr),
    ca_capture_base(0),
    ca_conntrack(-1),
    ca_detection_base(0),
    ca_detection_cores(-1),
    ca_sink(-1),
    ca_socket(-1),
    max_backlog(ND_MAX_BACKLOG_KB * 1024),
    max_packet_queue(ND_MAX_PKT_QUEUE_KB * 1024),
    max_capture_length(ND_PCAP_SNAPLEN),
    flags(0),
    digest_app_config{0},
    digest_legacy_config{0},
    fhc_purge_divisor(ND_FHC_PURGE_DIVISOR),
    fm_buckets(ND_FLOW_MAP_BUCKETS),
    max_detection_pkts(ND_MAX_DETECTION_PKTS),
    max_fhc(ND_MAX_FHC_ENTRIES),
    max_flows(0),
    sink_connect_timeout(ND_SINK_CONNECT_TIMEOUT),
    sink_max_post_errors(ND_SINK_MAX_POST_ERRORS),
    sink_xfer_timeout(ND_SINK_XFER_TIMEOUT),
    ttl_dns_entry(ND_TTL_IDLE_DHC_ENTRY),
    ttl_idle_flow(ND_TTL_IDLE_FLOW),
    ttl_idle_tcp_flow(ND_TTL_IDLE_TCP_FLOW),
    ttl_napi_update(ND_API_UPDATE_TTL),
    update_imf(1),
    update_interval(ND_STATS_INTERVAL),
    reader(nullptr)
{
    flags |= ndGF_SSL_VERIFY;
#ifdef _ND_USE_CONNTRACK
    flags |= ndGF_USE_CONNTRACK;
#endif
#ifdef _ND_USE_NETLINK
    flags |= ndGF_USE_NETLINK;
#endif
    flags |= ndGF_SOFT_DISSECTORS;
}

ndGlobalConfig::~ndGlobalConfig()
{
    Close();

    if (interfaces.size()) {
        for (auto &r : interfaces) {
            for (auto &i : r.second) {
                if (i.second.second == nullptr) continue;

                switch (i.second.first) {
                case ndCT_PCAP:
                    break;
                case ndCT_TPV3:
                    delete static_cast<nd_config_tpv3 *>(
                        i.second.second
                    );
                    break;
                default:
                    break;
                }
            }

            interfaces.clear();
        }
    }
}

void ndGlobalConfig::Close(void)
{
    if (reader != nullptr) {
        delete static_cast<INIReader *>(reader);
        reader = nullptr;
    }
}

int ndGlobalConfig::Load(const string &filename)
{
    typedef map<string, string> nd_config_section;

    struct stat extern_config_stat;
    if (stat(filename.c_str(), &extern_config_stat) < 0) {
        fprintf(stderr, "Can not stat configuration file: %s: %s\n",
            filename.c_str(), strerror(errno));
        return -1;
    }

    if (reader != nullptr)
        delete static_cast<INIReader *>(reader);

    reader = static_cast<void *>(new INIReader(filename));
    if (reader == nullptr) {
        fprintf(
            stderr,
            "Can not allocated reader: %s\n", strerror(ENOMEM)
        );
        return -1;
    }

    INIReader *r = static_cast<INIReader *>(reader);

    int rc = r->ParseError();

    switch (rc) {
    case -1:
        fprintf(stderr, "Error opening configuration file: %s: %s\n",
            filename.c_str(), strerror(errno));
        return -1;
    case 0:
        break;
    default:
        fprintf(stderr,
            "Error while parsing line #%d of configuration file: %s\n",
            rc, filename.c_str()
        );
        return -1;
    }

    // Netify section
    nd_config_section netifyd_section;
    r->GetSection("netifyd", netifyd_section);

    if (this->uuid == NULL) {
        string uuid = r->Get("netifyd", "uuid", ND_AGENT_UUID_NULL);
        if (uuid.size() > 0)
            this->uuid = strdup(uuid.c_str());
    }

    if (this->uuid_serial == NULL) {
        string serial = r->Get("netifyd", "uuid_serial", ND_AGENT_SERIAL_NULL);
        if (serial.size() > 0)
            this->uuid_serial = strdup(serial.c_str());
    }

    if (this->uuid_site == NULL) {
        string uuid_site = r->Get("netifyd", "uuid_site", ND_SITE_UUID_NULL);
        if (uuid_site.size() > 0)
            this->uuid_site = strdup(uuid_site.c_str());
    }

    path_state_persistent = r->Get(
        "netifyd", "path_persistent_state", ND_PERSISTENT_STATEDIR);

    path_state_volatile = r->Get(
        "netifyd", "path_volatile_state", ND_VOLATILE_STATEDIR);

    UpdatePaths();

    path_pid_file = r->Get(
        "netifyd", "path_pid_file", ND_PID_FILE_NAME);

    path_uuid = r->Get(
        "netifyd", "path_uuid", ND_AGENT_UUID_PATH);

    path_uuid_serial = r->Get(
        "netifyd", "path_uuid_serial", ND_AGENT_SERIAL_PATH);

    path_uuid_site = r->Get(
        "netifyd", "path_uuid_site", ND_SITE_UUID_PATH);

    string url_sink_provision = r->Get(
        "netifyd", "url_sink", ND_URL_SINK);
    this->url_sink_provision = strdup(url_sink_provision.c_str());
    this->url_sink = strdup(url_sink_provision.c_str());

    this->update_interval = (unsigned)r->GetInteger(
        "netifyd", "update_interval", ND_STATS_INTERVAL);

    this->sink_connect_timeout = (unsigned)r->GetInteger(
        "netifyd", "upload_connect_timeout", ND_SINK_CONNECT_TIMEOUT);
    this->sink_xfer_timeout = (unsigned)r->GetInteger(
        "netifyd", "upload_timeout", ND_SINK_XFER_TIMEOUT);
    ND_GF_SET_FLAG(ndGF_UPLOAD_NAT_FLOWS, r->GetBoolean(
        "netifyd", "upload_nat_flows", false));

    ND_GF_SET_FLAG(ndGF_EXPORT_JSON,
        r->GetBoolean("netifyd", "export_json", false));
    if (! ND_EXPORT_JSON) {
        ND_GF_SET_FLAG(ndGF_EXPORT_JSON,
            r->GetBoolean("netifyd", "json_save", false));
    }

    this->max_backlog = r->GetInteger(
        "netifyd", "max_backlog_kb", ND_MAX_BACKLOG_KB) * 1024;

    this->max_packet_queue = r->GetInteger(
        "netifyd", "max_packet_queue_kb", ND_MAX_PKT_QUEUE_KB) * 1024;

    ND_GF_SET_FLAG(ndGF_USE_SINK,
        r->GetBoolean("netifyd", "enable_sink", false));

    if (netifyd_section.find("ssl_verify") != netifyd_section.end()) {
        ND_GF_SET_FLAG(ndGF_SSL_VERIFY,
            r->GetBoolean("netifyd", "ssl_verify", true));
    }
    else if (netifyd_section.find("ssl_verify_peer") != netifyd_section.end()) {
        ND_GF_SET_FLAG(ndGF_SSL_VERIFY,
            r->GetBoolean("netifyd", "ssl_verify_peer", true));
    }

    ND_GF_SET_FLAG(ndGF_SSL_USE_TLSv1,
        r->GetBoolean("netifyd", "ssl_use_tlsv1", false));

    this->max_capture_length = (uint16_t)r->GetInteger(
        "netifyd", "max_capture_length", ND_PCAP_SNAPLEN);

    // TODO: Deprecated:
    // max_tcp_pkts, max_udp_pkts
    this->max_detection_pkts = (unsigned)r->GetInteger(
        "netifyd", "max_detection_pkts", ND_MAX_DETECTION_PKTS);

    this->sink_max_post_errors = (unsigned)r->GetInteger(
        "netifyd", "sink_max_post_errors", ND_SINK_MAX_POST_ERRORS);

    this->ttl_idle_flow = (unsigned)r->GetInteger(
        "netifyd", "ttl_idle_flow", ND_TTL_IDLE_FLOW);
    this->ttl_idle_tcp_flow = (unsigned)r->GetInteger(
        "netifyd", "ttl_idle_tcp_flow", ND_TTL_IDLE_TCP_FLOW);

    ND_GF_SET_FLAG(ndGF_CAPTURE_UNKNOWN_FLOWS,
        r->GetBoolean("netifyd", "capture_unknown_flows", false));

    this->max_flows = (size_t)r->GetInteger(
        "netifyd", "max_flows", 0);

    ND_GF_SET_FLAG(ndGF_SOFT_DISSECTORS,
        r->GetBoolean("netifyd", "soft_dissectors", true));

    ND_GF_SET_FLAG(ndGF_LOAD_DOMAINS,
        r->GetBoolean("netifyd", "load_domains", true));

    this->fm_buckets = (unsigned)r->GetInteger(
        "netifyd", "flow_map_buckets", ND_FLOW_MAP_BUCKETS);

    // Threading section
    this->ca_capture_base = (int16_t)r->GetInteger(
        "threads", "capture_base", this->ca_capture_base);
    this->ca_conntrack = (int16_t)r->GetInteger(
        "threads", "conntrack", this->ca_conntrack);
    this->ca_detection_base = (int16_t)r->GetInteger(
        "threads", "detection_base", this->ca_detection_base);
    this->ca_detection_cores = (int16_t)r->GetInteger(
        "threads", "detection_cores", this->ca_detection_cores);
    this->ca_sink = (int16_t)r->GetInteger(
        "threads", "sink", this->ca_sink);
    this->ca_socket = (int16_t)r->GetInteger(
        "threads", "socket", this->ca_socket);

    // Capture defaults section
    this->capture_read_timeout = (unsigned)r->GetInteger(
        "capture_defaults", "read_timeout", ND_CAPTURE_READ_TIMEOUT);
    this->capture_type = LoadCaptureType(
        "capture_defaults", "capture_type"
    );

    if (this->capture_type == ndCT_NONE) {
#if defined(_ND_USE_LIBPCAP)
        this->capture_type = ndCT_PCAP;
#elif defined(_ND_USE_TPACKETV3)
        this->capture_type = ndCT_TPV3;
#else
        fprintf(stderr,
            "Not default capture type could be determined.\n");
        return -1;
#endif
    }

    // TPv3 capture defaults section
    LoadCaptureSettings("capture_defaults_tpv3",
        ndCT_TPV3, static_cast<void *>(&tpv3_defaults)
    );

    // Flow Hash Cache section
    ND_GF_SET_FLAG(ndGF_USE_FHC,
        r->GetBoolean("flow_hash_cache", "enable", true));

    string fhc_save_mode = r->Get(
        "flow_hash_cache", "save", "persistent"
    );

    if (fhc_save_mode == "persistent")
        this->fhc_save = ndFHC_PERSISTENT;
    else if (fhc_save_mode == "volatile")
        this->fhc_save = ndFHC_VOLATILE;
    else
        this->fhc_save = ndFHC_DISABLED;

    this->max_fhc = (size_t)r->GetInteger(
        "flow_hash_cache", "cache_size", ND_MAX_FHC_ENTRIES);
    this->fhc_purge_divisor = (size_t)r->GetInteger(
        "flow_hash_cache", "purge_divisor", ND_FHC_PURGE_DIVISOR);

    // DNS Cache section
    ND_GF_SET_FLAG(ndGF_USE_DHC,
        r->GetBoolean("dns_hint_cache", "enable", true));

    string dhc_save_mode = r->Get(
        "dns_hint_cache", "save", "persistent"
    );

    if (dhc_save_mode == "persistent" ||
        dhc_save_mode == "1" ||
        dhc_save_mode == "yes" ||
        dhc_save_mode == "true")
        this->dhc_save = ndDHC_PERSISTENT;
    else if (dhc_save_mode == "volatile")
        this->dhc_save = ndDHC_VOLATILE;
    else
        this->dhc_save = ndDHC_DISABLED;

    this->ttl_dns_entry = (unsigned)r->GetInteger(
        "dns_hint_cache", "ttl", ND_TTL_IDLE_DHC_ENTRY);

    // Socket section
    ND_GF_SET_FLAG(ndGF_FLOW_DUMP_ESTABLISHED,
        r->GetBoolean("socket", "dump_established_flows", false));
    ND_GF_SET_FLAG(ndGF_FLOW_DUMP_UNKNOWN,
        r->GetBoolean("socket", "dump_unknown_flows", false));

    for (int i = 0; ; i++) {
        ostringstream os;
        os << "listen_address[" << i << "]";
        string socket_node = r->Get("socket", os.str(), "");
        if (socket_node.size() > 0) {
            os.str("");
            os << "listen_port[" << i << "]";
            string socket_port = r->Get(
                "socket", os.str(), ND_SOCKET_PORT);
            this->socket_host.push_back(
                make_pair(socket_node, socket_port));
            continue;
        }

        break;
    }

    for (int i = 0; ; i++) {
        ostringstream os;
        os << "listen_path[" << i << "]";
        string socket_node = r->Get("socket", os.str(), "");
        if (socket_node.size() > 0) {
            this->socket_path.push_back(socket_node);
            continue;
        }

        break;
    }

    // Privacy filter section
    for (int i = 0; ; i++) {
        ostringstream os;
        os << "mac[" << i << "]";
        string mac_addr = r->Get("privacy_filter", os.str(), "");

        if (mac_addr.size() == 0) break;

        /*
        if (mac_addr.size() != ND_STR_ETHALEN) continue;

        uint8_t mac[ETH_ALEN], *p = mac;
        const char *a = mac_addr.c_str();
        for (int j = 0; j < ND_STR_ETHALEN; j += 3, p++)
            sscanf(a + j, "%2hhx", p);
        p = new uint8_t[ETH_ALEN];
        */
        uint8_t mac[ETH_ALEN];
        if (nd_string_to_mac(mac_addr, mac)) {
            uint8_t *p = new uint8_t[ETH_ALEN];
            memcpy(p, mac, ETH_ALEN);
            this->privacy_filter_mac.push_back(p);
        }
    }

    for (int i = 0; ; i++) {
        ostringstream os;
        os << "host[" << i << "]";
        string host_addr = r->Get("privacy_filter", os.str(), "");

        if (host_addr.size() == 0) break;

        struct addrinfo hints;
        struct addrinfo *result, *rp;

        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = AF_UNSPEC;

        int rc = getaddrinfo(host_addr.c_str(), NULL, &hints, &result);
        if (rc != 0) {
            fprintf(stderr, "host[%d]: %s: %s\n",
                i, host_addr.c_str(), gai_strerror(rc));
            continue;
        }

        for (rp = result; rp != NULL; rp = rp->ai_next) {
            struct sockaddr *saddr = reinterpret_cast<struct sockaddr *>(
                new uint8_t[rp->ai_addrlen]
            );
            if (! saddr)
                throw ndSystemException(__PRETTY_FUNCTION__, "new", ENOMEM);
            memcpy(saddr, rp->ai_addr, rp->ai_addrlen);
            this->privacy_filter_host.push_back(saddr);
        }

        freeaddrinfo(result);
    }

    for (int i = 0; ; i++) {
        ostringstream os;
        os << "regex_search[" << i << "]";
        string search = r->Get("privacy_filter", os.str(), "");

        os.str("");
        os << "regex_replace[" << i << "]";
        string replace = r->Get("privacy_filter", os.str(), "");

        if (search.size() == 0 || replace.size() == 0) break;

        try {
            regex *rx_search = new regex(
                search,
                regex::extended |
                regex::icase |
                regex::optimize
            );
            this->privacy_regex.push_back(make_pair(rx_search, replace));
        } catch (const regex_error &e) {
            string error;
            nd_regex_error(e, error);
            fprintf(stderr, "WARNING: %s: Error compiling privacy regex: %s: %s [%d]\n",
                filename.c_str(), search.c_str(), error.c_str(), e.code());
        } catch (bad_alloc &e) {
            throw ndSystemException(__PRETTY_FUNCTION__, "new", ENOMEM);
        }
    }

    ND_GF_SET_FLAG(ndGF_PRIVATE_EXTADDR,
        r->GetBoolean("privacy_filter", "private_external_addresses", false));

#ifdef _ND_USE_PLUGINS
    // Plugins section
    r->GetSection("plugin_detections", this->plugin_detections);
    r->GetSection("plugin_sinks", this->plugin_sinks);
    r->GetSection("plugin_stats", this->plugin_stats);
#endif

    // Sink headers section
    r->GetSection("sink_headers", this->custom_headers);

    // Netify API section
    ND_GF_SET_FLAG(ndGF_USE_NAPI,
        r->GetBoolean("netify_api", "enable_updates", true));

    this->ttl_napi_update = r->GetInteger(
        "netify_api", "update_interval", ND_API_UPDATE_TTL);

    string url_napi = r->Get(
        "netify_api", "url_api", ND_API_UPDATE_URL);
    this->url_napi = strdup(url_napi.c_str());

    string napi_vendor = r->Get(
        "netify_api", "vendor", ND_API_VENDOR);
    this->napi_vendor = strdup(napi_vendor.c_str());

    // Protocols section
    r->GetSection("protocols", this->protocols);

    // Added static (non-command-line) capture interfaces
    AddInterfaces();

    return 0;
}

bool ndGlobalConfig::AddInterface(const string &iface,
    nd_interface_role role, nd_capture_type type, void *config)
{
    for (auto &r : interfaces) {
        auto i = interfaces[r.first].find(iface);
        if (i != interfaces[r.first].end()) {
            fprintf(stderr,
                "WARNING: interface already configured: %s\n",
                iface.c_str()
            );
            return false;
        }
    }

    if (type == ndCT_NONE) {
        if (capture_type == ndCT_NONE) {
            fprintf(stderr,
                "WARNING: capture type not set for interface: %s\n",
                iface.c_str()
            );
            return false;
        }

        type = capture_type;
    }

    if (type == ndCT_TPV3 && config == nullptr) {
        config = static_cast<void *>(new nd_config_tpv3);
        if (config == nullptr)
            throw ndSystemException(__PRETTY_FUNCTION__, "new", ENOMEM);
        memcpy(config, &tpv3_defaults, sizeof(nd_config_tpv3));
    }

    auto result = interfaces[role].insert(
        make_pair(
            iface,
            make_pair(type, config)
        )
    );

    if (! result.second) {
        switch (type) {
        case ndCT_PCAP:
            break;

        case ndCT_TPV3:
            delete static_cast<nd_config_tpv3 *>(config);
            break;

        default:
            break;
        }
    }

    return result.second;
}

bool ndGlobalConfig::AddInterfaceAddress(
    const string &iface, const string &addr)
{
    auto it = interface_addrs.find(iface);

    if (it != interface_addrs.end()) {
        auto result = it->second.insert(addr);

        if (result.second == false) {
            fprintf(stderr,
                "WARNING: address (%s) already associated with interface: %s\n",
                addr.c_str(), iface.c_str()
            );

            return false;
        }

        return true;
    }

    auto result = interface_addrs[iface].insert(addr);

    return result.second;
}

bool ndGlobalConfig::AddInterfacePeer(
    const string &iface, const string &peer)
{
    auto result = interface_peers.insert(make_pair(iface, peer));

    if (result.second == false) {
        fprintf(stderr,
            "WARNING: peer (%s) already associated with interface: %s\n",
            peer.c_str(), iface.c_str()
        );
    }

    return result.second;
}

bool ndGlobalConfig::AddInterfaceFilter(
    const string &iface, const string &filter)
{
    auto result = interface_filters.insert(make_pair(iface, filter));

    if (result.second == false) {
        fprintf(stderr,
            "WARNING: a filter is already attached to interface: %s\n",
            iface.c_str()
        );
    }

    return result.second;
}

bool ndGlobalConfig::AddInterfaces(void)
{
    INIReader *r = static_cast<INIReader *>(reader);

    set<string> sections;
    r->GetSections(sections);

    for (auto &s : sections) {
        static const char *key = "capture_interface_";
        static const size_t key_len = strlen(key);

        if (strncasecmp(s.c_str(), key, key_len))
            continue;

        size_t p = s.find_last_of("_");
        if (p == string::npos) continue;

        string iface = s.substr(p + 1);

        string interface_role = r->Get(
            s, "role", "none"
        );

        nd_interface_role role = ndIR_NONE;

        if (! strcasecmp("LAN", interface_role.c_str()) ||
            ! strncasecmp("INT", interface_role.c_str(), 3))
            role = ndIR_LAN;
        else if (! strcasecmp("WAN", interface_role.c_str()) ||
            ! strncasecmp("EXT", interface_role.c_str(), 3))
            role = ndIR_WAN;

        if (role == ndIR_NONE) {
            fprintf(stderr,
                "WARNING: interface role not set or invalid: %s\n",
                iface.c_str()
            );
            continue;
        }

        auto ri = interfaces.find(role);
        if (ri != interfaces.end()) {
            auto i = interfaces[ri->first].find(iface);
            if (i != interfaces[ri->first].end()) {
                fprintf(stderr,
                    "WARNING: interface already configured: %s\n",
                    iface.c_str()
                );
                continue;
            }
        }

        nd_capture_type type = LoadCaptureType(
            s, "capture_type"
        );

        void *config = nullptr;

        switch (type) {
        case ndCT_PCAP:
            break;

        case ndCT_TPV3:
            config = static_cast<void *>(new nd_config_tpv3);
            memcpy(config, &tpv3_defaults, sizeof(nd_config_tpv3));
            LoadCaptureSettings(s, type, config);
            break;

        default:
            break;
        }

        AddInterface(iface, role, type, config);

        for (int i = 0; ; i++) {
            ostringstream os;
            os << "address[" << i << "]";
            string addr = r->Get(s, os.str(), "");

            if (addr.size() == 0) break;

            AddInterfaceAddress(iface, addr);
        }

        string peer = r->Get(s, "peer", "");

        if (peer.size())
            AddInterfacePeer(iface, peer);

        string filter = r->Get(s, "filter", "");

        if (filter.size())
            AddInterfaceFilter(iface, filter);
    }

    return false;
}

enum nd_capture_type ndGlobalConfig::LoadCaptureType(
    const string &section, const string &key)
{
    INIReader *r = static_cast<INIReader *>(reader);

    enum nd_capture_type ct = ndCT_NONE;
    string capture_type = r->Get(section, key, "auto");

    if (capture_type == "auto") {
#if defined(_ND_USE_LIBPCAP)
        ct = ndCT_PCAP;
#elif defined(_ND_USE_TPACKETV3)
        ct = ndCT_TPV3;
#else
#error "No available capture types!"
#endif
    }
#if defined(_ND_USE_LIBPCAP)
    else if (capture_type == "pcap")
        ct = ndCT_PCAP;
#endif
#if defined(_ND_USE_TPACKETV3)
    else if (capture_type == "tpv3")
        ct = ndCT_TPV3;
#endif
    else {
        fprintf(stderr, "Invalid capture type: %s\n",
            capture_type.c_str()
        );
    }

    return ct;
}

void ndGlobalConfig::LoadCaptureSettings(
    const string &section, nd_capture_type type, void *config)
{
    INIReader *r = static_cast<INIReader *>(reader);

    if (type == ndCT_PCAP) {
    }
    else if (type == ndCT_TPV3) {
        nd_config_tpv3 *tpv3 = static_cast<nd_config_tpv3 *>(config);

        string fanout_mode = r->Get(
            section, "fanout_mode", "none"
        );

        if (fanout_mode == "hash")
            tpv3->fanout_mode = ndFOM_HASH;
        else if (fanout_mode == "lb" ||
                fanout_mode == "load_balanced")
            tpv3->fanout_mode = ndFOM_LOAD_BALANCED;
        else if (fanout_mode == "cpu")
            tpv3->fanout_mode = ndFOM_CPU;
        else if (fanout_mode == "rollover")
            tpv3->fanout_mode = ndFOM_ROLLOVER;
        else if (fanout_mode == "random")
            tpv3->fanout_mode = ndFOM_RANDOM;
        else
            tpv3->fanout_mode = ndFOM_DISABLED;

        string fanout_flags = r->Get(
            section, "fanout_flags", "none"
        );

        if (fanout_flags != "none") {
            stringstream ss(fanout_flags);

            while (ss.good()) {
                string flag;
                getline(ss, flag, ',');

                nd_trim(flag, ' ');

                if (flag == "defrag")
                    tpv3->fanout_flags |= ndFOF_DEFRAG;
                else if (flag == "rollover")
                    tpv3->fanout_flags |= ndFOF_ROLLOVER;
                else {
                    fprintf(stderr, "Invalid fanout flag: %s\n",
                        flag.c_str()
                    );
                }
            }
        }

        tpv3->fanout_instances = (unsigned)r->GetInteger(
            section, "fanout_instances", 0);

        if (tpv3->fanout_mode != ndFOM_DISABLED &&
            tpv3->fanout_instances < 2) {
            tpv3->fanout_mode = ndFOM_DISABLED;
            tpv3->fanout_instances = 0;
        }

        tpv3->rb_block_size = (unsigned)r->GetInteger(
            section, "rb_block_size", tpv3_defaults.rb_block_size);

        tpv3->rb_frame_size = (unsigned)r->GetInteger(
            section, "rb_frame_size", tpv3_defaults.rb_frame_size);

        tpv3->rb_blocks = (unsigned)r->GetInteger(
            section, "rb_blocks", tpv3_defaults.rb_blocks);
    }
}

void ndGlobalConfig::UpdatePaths(void)
{
    path_app_config =
        path_state_persistent + "/" + ND_CONF_APP_BASE;

    path_cat_config =
        path_state_persistent + "/" + ND_CONF_CAT_BASE;

    path_legacy_config =
        path_state_persistent + "/" + ND_CONF_LEGACY_BASE;

    path_agent_status =
        path_state_volatile + "/" + ND_AGENT_STATUS_BASE;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
