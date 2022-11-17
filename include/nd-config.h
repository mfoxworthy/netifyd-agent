// Netify Agent
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

#ifndef _ND_CONFIG_H
#define _ND_CONFIG_H

enum nd_dhc_save {
    ndDHC_DISABLED = 0,
    ndDHC_PERSISTENT = 1,
    ndDHC_VOLATILE = 2
};

enum nd_fhc_save {
    ndFHC_DISABLED = 0,
    ndFHC_PERSISTENT = 1,
    ndFHC_VOLATILE = 2
};

enum nd_global_flags {
    ndGF_DEBUG = 0x1,
    ndGF_DEBUG_UPLOAD = 0x2,
    ndGF_DEBUG_WITH_ETHERS = 0x4,
    ndGF_DEBUG_NDPI= 0x8,
    ndGF_QUIET = 0x10,
    ndGF_CAPTURE_UNKNOWN_FLOWS = 0x20,
    ndGF_PRIVATE_EXTADDR = 0x40,
    ndGF_SSL_USE_TLSv1 = 0x80,
    ndGF_SSL_VERIFY = 0x100,
    ndGF_USE_CONNTRACK = 0x200,
    ndGF_USE_NETLINK = 0x400,
    ndGF_USE_NAPI = 0x800,
    ndGF_USE_SINK = 0x1000,
    ndGF_USE_DHC = 0x2000,
    ndGF_USE_FHC = 0x4000,
    ndGF_EXPORT_JSON = 0x8000,
    ndGF_VERBOSE = 0x10000,
    ndGF_REPLAY_DELAY = 0x20000,
    ndGF_REMAIN_IN_FOREGROUND = 0x40000,
    ndGF_FLOW_DUMP_ESTABLISHED = 0x80000,
    ndGF_FLOW_DUMP_UNKNOWN = 0x100000,
    ndGF_UPLOAD_ENABLED = 0x200000,
    ndGF_UPLOAD_NAT_FLOWS = 0x400000,
    ndGF_WAIT_FOR_CLIENT = 0x800000,
    ndGF_SOFT_DISSECTORS = 0x1000000,
    ndGF_LOAD_DOMAINS = 0x2000000,
};

#define ND_DEBUG (nd_config.flags & ndGF_DEBUG)
#define ND_DEBUG_UPLOAD (nd_config.flags & ndGF_DEBUG_UPLOAD)
#define ND_DEBUG_WITH_ETHERS (nd_config.flags & ndGF_DEBUG_WITH_ETHERS)
#define ND_DEBUG_NDPI (nd_config.flags & ndGF_DEBUG_NDPI)
#define ND_QUIET (nd_config.flags & ndGF_QUIET)
#define ND_OVERRIDE_LEGACY_CONFIG (nd_config.flags & ndGF_OVERRIDE_LEGACY_CONFIG)
#define ND_CAPTURE_UNKNOWN_FLOWS (nd_config.flags & ndGF_CAPTURE_UNKNOWN_FLOWS)
#define ND_PRIVATE_EXTADDR (nd_config.flags & ndGF_PRIVATE_EXTADDR)
#define ND_SSL_USE_TLSv1 (nd_config.flags & ndGF_SSL_USE_TLSv1)
#define ND_SSL_VERIFY (nd_config.flags & ndGF_SSL_VERIFY)
#define ND_USE_CONNTRACK (nd_config.flags & ndGF_USE_CONNTRACK)
#define ND_USE_NETLINK (nd_config.flags & ndGF_USE_NETLINK)
#define ND_USE_NAPI (nd_config.flags & ndGF_USE_NAPI)
#define ND_USE_SINK (nd_config.flags & ndGF_USE_SINK)
#define ND_USE_DHC (nd_config.flags & ndGF_USE_DHC)
#define ND_USE_FHC (nd_config.flags & ndGF_USE_FHC)
#define ND_EXPORT_JSON (nd_config.flags & ndGF_EXPORT_JSON)
#define ND_VERBOSE (nd_config.flags & ndGF_VERBOSE)
#define ND_REPLAY_DELAY (nd_config.flags & ndGF_REPLAY_DELAY)
#define ND_REMAIN_IN_FOREGROUND (nd_config.flags & ndGF_REMAIN_IN_FOREGROUND)
#define ND_FLOW_DUMP_ESTABLISHED (nd_config.flags & ndGF_FLOW_DUMP_ESTABLISHED)
#define ND_FLOW_DUMP_UNKNOWN (nd_config.flags & ndGF_FLOW_DUMP_UNKNOWN)
#define ND_UPLOAD_ENABLED (nd_config.flags & ndGF_UPLOAD_ENABLED)
#define ND_UPLOAD_NAT_FLOWS (nd_config.flags & ndGF_UPLOAD_NAT_FLOWS)
#define ND_WAIT_FOR_CLIENT (nd_config.flags & ndGF_WAIT_FOR_CLIENT)
#define ND_SOFT_DISSECTORS (nd_config.flags & ndGF_SOFT_DISSECTORS)
#define ND_LOAD_DOMAINS (nd_config.flags & ndGF_LOAD_DOMAINS)

#define ND_GF_SET_FLAG(flag, value) \
{ \
    if (value) nd_config.flags |= flag; \
    else nd_config.flags &= ~flag; \
}

class ndGlobalConfig
{
public:
    char *napi_vendor;
    char *path_app_config;
    char *path_cat_config;
    char *path_config;
    char *path_export_json;
    char *path_legacy_config;
    char *path_uuid;
    char *path_uuid_serial;
    char *path_uuid_site;
    char *url_napi;
    char *url_sink;
    char *url_sink_provision;
    char *uuid;
    char *uuid_serial;
    char *uuid_site;
    enum nd_dhc_save dhc_save;
    enum nd_fhc_save fhc_save;
    FILE *h_flow;
    int16_t ca_capture_base;
    int16_t ca_conntrack;
    int16_t ca_detection_base;
    int16_t ca_detection_cores;
    int16_t ca_sink;
    int16_t ca_socket;
    size_t max_backlog;
    size_t max_packet_queue;
    uint16_t max_capture_length;
    uint32_t flags;
    uint8_t digest_app_config[SHA1_DIGEST_LENGTH];
    uint8_t digest_legacy_config[SHA1_DIGEST_LENGTH];
    unsigned fhc_purge_divisor;
    unsigned max_detection_pkts;
    unsigned max_fhc;
    unsigned max_flows;
    unsigned sink_connect_timeout;
    unsigned sink_max_post_errors;
    unsigned sink_xfer_timeout;
    unsigned ttl_dns_entry;
    unsigned ttl_idle_flow;
    unsigned ttl_idle_tcp_flow;
    unsigned ttl_napi_update;
    unsigned update_imf;
    unsigned update_interval;

    vector<pair<string, string> > socket_host;
    vector<string> socket_path;
    vector<struct sockaddr *> privacy_filter_host;
    vector<uint8_t *> privacy_filter_mac;
    vector<pair<regex *, string> > privacy_regex;
    nd_device_filter device_filters;
#ifdef _ND_USE_INOTIFY
    nd_inotify_watch inotify_watches;
#endif
#ifdef _ND_USE_PLUGINS
    map<string, string> plugin_services;
    map<string, string> plugin_tasks;
    map<string, string> plugin_detections;
    map<string, string> plugin_stats;
#endif
    map<string, string> custom_headers;
    map<string, string> protocols;

    ndGlobalConfig();
    virtual ~ndGlobalConfig();

    int Load(const string &filename);
};

#endif // _ND_CONFIG_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
