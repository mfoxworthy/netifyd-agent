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

nd_global_config *nd_config = NULL;

void nd_config_init(void)
{
    if (nd_config == NULL) {
        nd_config = new nd_global_config;
        if (nd_config == NULL)
            throw ndSystemException(__PRETTY_FUNCTION__, "new", ENOMEM);
    }

    nd_config->h_flow = stderr;

    nd_config->path_config = NULL;
    nd_config->path_export_json = NULL;
    nd_config->path_app_config = strdup(ND_CONF_APP_PATH);
    nd_config->path_cat_config = strdup(ND_CONF_CAT_PATH);
    nd_config->path_legacy_config = strdup(ND_CONF_LEGACY_PATH);
    nd_config->path_uuid = NULL;
    nd_config->path_uuid_serial = NULL;
    nd_config->path_uuid_site = NULL;
    nd_config->url_sink = NULL;
    nd_config->url_sink_provision = NULL;
    nd_config->uuid = NULL;
    nd_config->uuid_serial = NULL;
    nd_config->uuid_site = NULL;

    nd_config->max_backlog = ND_MAX_BACKLOG_KB * 1024;
    nd_config->max_packet_queue = ND_MAX_PKT_QUEUE_KB * 1024;

    nd_config->flags |= ndGF_SSL_VERIFY;
#ifdef _ND_USE_CONNTRACK
    nd_config->flags |= ndGF_USE_CONNTRACK;
#endif
#ifdef _ND_USE_NETLINK
    nd_config->flags |= ndGF_USE_NETLINK;
#endif
    nd_config->flags |= ndGF_SOFT_DISSECTORS;

    nd_config->max_detection_pkts = ND_MAX_DETECTION_PKTS;
    nd_config->max_fhc = ND_MAX_FHC_ENTRIES;
    nd_config->max_flows = 0;
    nd_config->sink_max_post_errors = ND_SINK_MAX_POST_ERRORS;
    nd_config->sink_connect_timeout = ND_SINK_CONNECT_TIMEOUT;
    nd_config->sink_xfer_timeout = ND_SINK_XFER_TIMEOUT;
    nd_config->ttl_dns_entry = ND_TTL_IDLE_DHC_ENTRY;
    nd_config->ttl_idle_flow = ND_TTL_IDLE_FLOW;
    nd_config->ttl_idle_tcp_flow = ND_TTL_IDLE_TCP_FLOW;
    nd_config->update_interval = ND_STATS_INTERVAL;
    nd_config->update_imf = 1;
    nd_config->ca_capture_base = 0;
    nd_config->ca_conntrack = -1;
    nd_config->ca_detection_base = 0;
    nd_config->ca_detection_cores = -1;
    nd_config->ca_sink = -1;
    nd_config->ca_socket = -1;

    memset(nd_config->digest_app_config, 0, SHA1_DIGEST_LENGTH);
    memset(nd_config->digest_legacy_config, 0, SHA1_DIGEST_LENGTH);

    nd_config->fhc_save = ndFHC_PERSISTENT;
    nd_config->fhc_purge_divisor = ND_FHC_PURGE_DIVISOR;
}

int nd_config_load(const string &filename)
{
    typedef map<string, string> nd_config_section;

    struct stat extern_config_stat;
    if (stat(filename.c_str(), &extern_config_stat) < 0) {
        fprintf(stderr, "Can not stat configuration file: %s: %s\n",
            filename.c_str(), strerror(errno));
        return -1;
    }

    INIReader reader(filename.c_str());

    if (reader.ParseError() != 0) {
        fprintf(stderr, "Error while parsing configuration file: %s\n",
            filename.c_str());
        return -1;
    }

    // Netify section
    nd_config_section netifyd_section;
    reader.GetSection("netifyd", netifyd_section);

    if (nd_config->uuid == NULL) {
        string uuid = reader.Get("netifyd", "uuid", ND_AGENT_UUID_NULL);
        if (uuid.size() > 0)
            nd_config->uuid = strdup(uuid.c_str());
    }

    if (nd_config->uuid_serial == NULL) {
        string serial = reader.Get("netifyd", "uuid_serial", ND_AGENT_SERIAL_NULL);
        if (serial.size() > 0)
            nd_config->uuid_serial = strdup(serial.c_str());
    }

    if (nd_config->uuid_site == NULL) {
        string uuid_site = reader.Get("netifyd", "uuid_site", ND_SITE_UUID_NULL);
        if (uuid_site.size() > 0)
            nd_config->uuid_site = strdup(uuid_site.c_str());
    }

    string path_uuid = reader.Get(
        "netifyd", "path_uuid", ND_AGENT_UUID_PATH);
    nd_config->path_uuid = strdup(path_uuid.c_str());

    string path_uuid_serial = reader.Get(
        "netifyd", "path_uuid_serial", ND_AGENT_SERIAL_PATH);
    nd_config->path_uuid_serial = strdup(path_uuid_serial.c_str());

    string path_uuid_site = reader.Get(
        "netifyd", "path_uuid_site", ND_SITE_UUID_PATH);
    nd_config->path_uuid_site = strdup(path_uuid_site.c_str());

    string url_sink_provision = reader.Get(
        "netifyd", "url_sink", ND_URL_SINK);
    nd_config->url_sink_provision = strdup(url_sink_provision.c_str());
    nd_config->url_sink = strdup(url_sink_provision.c_str());

    nd_config->update_interval = (unsigned)reader.GetInteger(
        "netifyd", "update_interval", ND_STATS_INTERVAL);

    nd_config->sink_connect_timeout = (unsigned)reader.GetInteger(
        "netifyd", "upload_connect_timeout", ND_SINK_CONNECT_TIMEOUT);
    nd_config->sink_xfer_timeout = (unsigned)reader.GetInteger(
        "netifyd", "upload_timeout", ND_SINK_XFER_TIMEOUT);
    ND_GF_SET_FLAG(ndGF_UPLOAD_NAT_FLOWS, reader.GetBoolean(
        "netifyd", "upload_nat_flows", false));

    ND_GF_SET_FLAG(ndGF_EXPORT_JSON,
        reader.GetBoolean("netifyd", "export_json", false));
    if (! ND_EXPORT_JSON) {
        ND_GF_SET_FLAG(ndGF_EXPORT_JSON,
            reader.GetBoolean("netifyd", "json_save", false));
    }

    nd_config->max_backlog = reader.GetInteger(
        "netifyd", "max_backlog_kb", ND_MAX_BACKLOG_KB) * 1024;

    nd_config->max_packet_queue = reader.GetInteger(
        "netifyd", "max_packet_queue_kb", ND_MAX_PKT_QUEUE_KB) * 1024;

    ND_GF_SET_FLAG(ndGF_USE_SINK,
        reader.GetBoolean("netifyd", "enable_sink", false));

    if (netifyd_section.find("ssl_verify") != netifyd_section.end()) {
        ND_GF_SET_FLAG(ndGF_SSL_VERIFY,
            reader.GetBoolean("netifyd", "ssl_verify", true));
    } else if (netifyd_section.find("ssl_verify_peer") != netifyd_section.end()) {
        ND_GF_SET_FLAG(ndGF_SSL_VERIFY,
            reader.GetBoolean("netifyd", "ssl_verify_peer", true));
    }

    ND_GF_SET_FLAG(ndGF_SSL_USE_TLSv1,
        reader.GetBoolean("netifyd", "ssl_use_tlsv1", false));

    nd_config->max_capture_length = (uint16_t)reader.GetInteger(
        "netifyd", "max_capture_length", ND_PCAP_SNAPLEN);

    // TODO: Deprecated:
    // max_tcp_pkts, max_udp_pkts
    nd_config->max_detection_pkts = (unsigned)reader.GetInteger(
        "netifyd", "max_detection_pkts", ND_MAX_DETECTION_PKTS);

    nd_config->sink_max_post_errors = (unsigned)reader.GetInteger(
        "netifyd", "sink_max_post_errors", ND_SINK_MAX_POST_ERRORS);

    nd_config->ttl_idle_flow = (unsigned)reader.GetInteger(
        "netifyd", "ttl_idle_flow", ND_TTL_IDLE_FLOW);
    nd_config->ttl_idle_tcp_flow = (unsigned)reader.GetInteger(
        "netifyd", "ttl_idle_tcp_flow", ND_TTL_IDLE_TCP_FLOW);

    ND_GF_SET_FLAG(ndGF_CAPTURE_UNKNOWN_FLOWS,
        reader.GetBoolean("netifyd", "capture_unknown_flows", false));

    nd_config->max_flows = (size_t)reader.GetInteger(
        "netifyd", "max_flows", 0);

    ND_GF_SET_FLAG(ndGF_SOFT_DISSECTORS,
        reader.GetBoolean("netifyd", "soft_dissectors", true));

    // Threading section
    nd_config->ca_capture_base = (int16_t)reader.GetInteger(
        "threads", "capture_base", nd_config->ca_capture_base);
    nd_config->ca_conntrack = (int16_t)reader.GetInteger(
        "threads", "conntrack", nd_config->ca_conntrack);
    nd_config->ca_detection_base = (int16_t)reader.GetInteger(
        "threads", "detection_base", nd_config->ca_detection_base);
    nd_config->ca_detection_cores = (int16_t)reader.GetInteger(
        "threads", "detection_cores", nd_config->ca_detection_cores);
    nd_config->ca_sink = (int16_t)reader.GetInteger(
        "threads", "sink", nd_config->ca_sink);
    nd_config->ca_socket = (int16_t)reader.GetInteger(
        "threads", "socket", nd_config->ca_socket);

    // Flow Hash Cache section
    ND_GF_SET_FLAG(ndGF_USE_FHC,
        reader.GetBoolean("flow_hash_cache", "enable", true));

    string fhc_save_mode = reader.Get(
        "flow_hash_cache", "save", "persistent"
    );

    if (fhc_save_mode == "persistent")
        nd_config->fhc_save = ndFHC_PERSISTENT;
    else if (fhc_save_mode == "volatile")
        nd_config->fhc_save = ndFHC_VOLATILE;
    else
        nd_config->fhc_save = ndFHC_DISABLED;

    nd_config->max_fhc = (size_t)reader.GetInteger(
        "flow_hash_cache", "cache_size", ND_MAX_FHC_ENTRIES);
    nd_config->fhc_purge_divisor = (size_t)reader.GetInteger(
        "flow_hash_cache", "purge_divisor", ND_FHC_PURGE_DIVISOR);

    // DNS Cache section
    ND_GF_SET_FLAG(ndGF_USE_DHC,
        reader.GetBoolean("dns_hint_cache", "enable", true));

    string dhc_save_mode = reader.Get(
        "dns_hint_cache", "save", "persistent"
    );

    if (dhc_save_mode == "persistent" ||
        dhc_save_mode == "1" ||
        dhc_save_mode == "yes" ||
        dhc_save_mode == "true")
        nd_config->dhc_save = ndDHC_PERSISTENT;
    else if (dhc_save_mode == "volatile")
        nd_config->dhc_save = ndDHC_VOLATILE;
    else
        nd_config->dhc_save = ndDHC_DISABLED;

    nd_config->ttl_dns_entry = (unsigned)reader.GetInteger(
        "dns_hint_cache", "ttl", ND_TTL_IDLE_DHC_ENTRY);

    // Socket section
    ND_GF_SET_FLAG(ndGF_FLOW_DUMP_ESTABLISHED,
        reader.GetBoolean("socket", "dump_established_flows", false));
    ND_GF_SET_FLAG(ndGF_FLOW_DUMP_UNKNOWN,
        reader.GetBoolean("socket", "dump_unknown_flows", false));

    for (int i = 0; ; i++) {
        ostringstream os;
        os << "listen_address[" << i << "]";
        string socket_node = reader.Get("socket", os.str(), "");
        if (socket_node.size() > 0) {
            os.str("");
            os << "listen_port[" << i << "]";
            string socket_port = reader.Get(
                "socket", os.str(), ND_SOCKET_PORT);
            nd_config->socket_host.push_back(
                make_pair(socket_node, socket_port));
            continue;
        }

        break;
    }

    for (int i = 0; ; i++) {
        ostringstream os;
        os << "listen_path[" << i << "]";
        string socket_node = reader.Get("socket", os.str(), "");
        if (socket_node.size() > 0) {
            nd_config->socket_path.push_back(socket_node);
            continue;
        }

        break;
    }

    // Privacy filter section
    for (int i = 0; ; i++) {
        ostringstream os;
        os << "mac[" << i << "]";
        string mac_addr = reader.Get("privacy_filter", os.str(), "");

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
            nd_config->privacy_filter_mac.push_back(p);
        }
    }

    for (int i = 0; ; i++) {
        ostringstream os;
        os << "host[" << i << "]";
        string host_addr = reader.Get("privacy_filter", os.str(), "");

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
            nd_config->privacy_filter_host.push_back(saddr);
        }

        freeaddrinfo(result);
    }

    for (int i = 0; ; i++) {
        ostringstream os;
        os << "regex_search[" << i << "]";
        string search = reader.Get("privacy_filter", os.str(), "");

        os.str("");
        os << "regex_replace[" << i << "]";
        string replace = reader.Get("privacy_filter", os.str(), "");

        if (search.size() == 0 || replace.size() == 0) break;

        try {
            regex *rx_search = new regex(
                search,
                regex::extended |
                regex::icase |
                regex::optimize
            );
            nd_config->privacy_regex.push_back(make_pair(rx_search, replace));
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
        reader.GetBoolean("privacy_filter", "private_external_addresses", false));

#ifdef _ND_USE_INOTIFY
    // Watches section
    reader.GetSection("watches", nd_config->inotify_watches);
#endif
#ifdef _ND_USE_PLUGINS
    // Plugins section
    reader.GetSection("plugin_services", nd_config->plugin_services);
    reader.GetSection("plugin_tasks", nd_config->plugin_tasks);
    reader.GetSection("plugin_detections", nd_config->plugin_detections);
    reader.GetSection("plugin_stats", nd_config->plugin_stats);
#endif

    // Sink headers section
    reader.GetSection("sink_headers", nd_config->custom_headers);

    // Netify API section
    ND_GF_SET_FLAG(ndGF_USE_NAPI,
        reader.GetBoolean("netify_api", "enable_updates", true));

    nd_config->ttl_napi_update = reader.GetInteger(
        "netify_api", "update_interval", ND_API_UPDATE_TTL);

    string url_napi = reader.Get(
        "netify_api", "url_api", ND_API_UPDATE_URL);
    nd_config->url_napi = strdup(url_napi.c_str());

    string napi_vendor = reader.Get(
        "netify_api", "vendor", ND_API_VENDOR);
    nd_config->napi_vendor = strdup(napi_vendor.c_str());

    // Protocols section
    reader.GetSection("protocols", nd_config->protocols);

    return 0;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
