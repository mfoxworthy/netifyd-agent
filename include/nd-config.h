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
    ndDHC_DISABLED,
    ndDHC_PERSISTENT,
    ndDHC_VOLATILE,
};

enum nd_fhc_save {
    ndFHC_DISABLED,
    ndFHC_PERSISTENT,
    ndFHC_VOLATILE,
};

enum nd_capture_type {
    ndCT_NONE,
    ndCT_PCAP,
    ndCT_PCAP_OFFLINE,
    ndCT_TPV3,
    ndCT_NFQ,
};

enum nd_interface_role {
    ndIR_NONE,
    ndIR_LAN,
    ndIR_WAN,
};

enum nd_tpv3_fanout_mode {
    ndFOM_DISABLED,
    ndFOM_HASH,
    ndFOM_LOAD_BALANCED,
    ndFOM_CPU,
    ndFOM_ROLLOVER,
    ndFOM_RANDOM,
    ndFOM_QUEUE_MAP,
};

enum nd_tpv3_fanout_flags {
    ndFOF_NONE = 0x0,
    ndFOF_DEFRAG = 0x1,
    ndFOF_ROLLOVER = 0x2,
};

enum nd_global_flags {
    ndGF_DEBUG = 0x1,
    ndGF_DEBUG_UPLOAD = 0x2,
    ndGF_UNUSED_0x4 = 0x4,
    ndGF_DEBUG_NDPI= 0x8,
    ndGF_QUIET = 0x10,
    ndGF_SYN_SCAN_PROTECTION = 0x20,
    ndGF_PRIVATE_EXTADDR = 0x40,
    ndGF_SSL_USE_TLSv1 = 0x80,
    ndGF_SSL_VERIFY = 0x100,
    ndGF_USE_CONNTRACK = 0x200,
    ndGF_USE_NETLINK = 0x400,
    ndGF_USE_NAPI = 0x800,
    ndGF_UNUSED_0x1000 = 0x1000,
    ndGF_USE_DHC = 0x2000,
    ndGF_USE_FHC = 0x4000,
    ndGF_EXPORT_JSON = 0x8000,
    ndGF_VERBOSE = 0x10000,
    ndGF_REPLAY_DELAY = 0x20000,
    ndGF_REMAIN_IN_FOREGROUND = 0x40000,
    ndGF_UNUSED_0x80000 = 0x80000,
    ndGF_UNUSED_0x100000 = 0x100000,
    ndGF_UPLOAD_ENABLED = 0x200000,
    ndGF_UPLOAD_NAT_FLOWS = 0x400000,
    ndGF_UNUSED_0x800000 = 0x800000,
    ndGF_SOFT_DISSECTORS = 0x1000000,
    ndGF_LOAD_DOMAINS = 0x2000000,
};

#define ndGC_DEBUG (ndGlobalConfig::GetInstance().flags & ndGF_DEBUG)
#define ndGC_DEBUG_UPLOAD (ndGlobalConfig::GetInstance().flags & ndGF_DEBUG_UPLOAD)
#define ndGC_DEBUG_NDPI (ndGlobalConfig::GetInstance().flags & ndGF_DEBUG_NDPI)
#define ndGC_QUIET (ndGlobalConfig::GetInstance().flags & ndGF_QUIET)
#define ndGC_OVERRIDE_LEGACY_CONFIG (ndGlobalConfig::GetInstance().flags & ndGF_OVERRIDE_LEGACY_CONFIG)
#define ndGC_SYN_SCAN_PROTECTION (ndGlobalConfig::GetInstance().flags & ndGF_SYN_SCAN_PROTECTION)
#define ndGC_PRIVATE_EXTADDR (ndGlobalConfig::GetInstance().flags & ndGF_PRIVATE_EXTADDR)
#define ndGC_SSL_USE_TLSv1 (ndGlobalConfig::GetInstance().flags & ndGF_SSL_USE_TLSv1)
#define ndGC_SSL_VERIFY (ndGlobalConfig::GetInstance().flags & ndGF_SSL_VERIFY)
#define ndGC_USE_CONNTRACK (ndGlobalConfig::GetInstance().flags & ndGF_USE_CONNTRACK)
#define ndGC_USE_NETLINK (ndGlobalConfig::GetInstance().flags & ndGF_USE_NETLINK)
#define ndGC_USE_NAPI (ndGlobalConfig::GetInstance().flags & ndGF_USE_NAPI)
#define ndGC_USE_DHC (ndGlobalConfig::GetInstance().flags & ndGF_USE_DHC)
#define ndGC_USE_FHC (ndGlobalConfig::GetInstance().flags & ndGF_USE_FHC)
#define ndGC_EXPORT_JSON (ndGlobalConfig::GetInstance().flags & ndGF_EXPORT_JSON)
#define ndGC_VERBOSE (ndGlobalConfig::GetInstance().flags & ndGF_VERBOSE)
#define ndGC_REPLAY_DELAY (ndGlobalConfig::GetInstance().flags & ndGF_REPLAY_DELAY)
#define ndGC_REMAIN_IN_FOREGROUND (ndGlobalConfig::GetInstance().flags & ndGF_REMAIN_IN_FOREGROUND)
#define ndGC_UPLOAD_ENABLED (ndGlobalConfig::GetInstance().flags & ndGF_UPLOAD_ENABLED)
#define ndGC_UPLOAD_NAT_FLOWS (ndGlobalConfig::GetInstance().flags & ndGF_UPLOAD_NAT_FLOWS)
#define ndGC_SOFT_DISSECTORS (ndGlobalConfig::GetInstance().flags & ndGF_SOFT_DISSECTORS)
#define ndGC_LOAD_DOMAINS (ndGlobalConfig::GetInstance().flags & ndGF_LOAD_DOMAINS)

#define ndGC ndGlobalConfig::GetInstance()

#define ndGC_SetFlag(flag, value) \
{ \
    if (value) ndGlobalConfig::GetInstance().flags |= flag; \
    else ndGlobalConfig::GetInstance().flags &= ~flag; \
}

typedef struct
{
    string capture_filename;
} nd_config_pcap;

typedef struct
{
    unsigned fanout_mode;
    unsigned fanout_flags;
    unsigned fanout_instances;
    unsigned rb_block_size;
    unsigned rb_frame_size;
    unsigned rb_blocks;
} nd_config_tpv3;

typedef struct
{
    unsigned queue_id;
    unsigned instances;
} nd_config_nfq;

class ndGlobalConfig
{
public:
    string napi_vendor;
    string path_agent_status;
    string path_app_config;
    string path_cat_config;
    string path_config;
    string path_domains;
    string path_export_json;
    string path_legacy_config;
    string path_pid_file;
    string path_plugins;
    string path_state_persistent;
    string path_state_volatile;
    string path_uuid;
    string path_uuid_serial;
    string path_uuid_site;
    string url_napi;
    enum nd_dhc_save dhc_save;
    enum nd_fhc_save fhc_save;
    enum nd_capture_type capture_type;
    unsigned capture_read_timeout;
    nd_config_tpv3 tpv3_defaults;
    FILE *h_flow;
    int16_t ca_capture_base;
    int16_t ca_conntrack;
    int16_t ca_detection_base;
    int16_t ca_detection_cores;
    size_t max_packet_queue;
    uint16_t max_capture_length;
    uint32_t flags;
    uint8_t digest_app_config[SHA1_DIGEST_LENGTH];
    uint8_t digest_legacy_config[SHA1_DIGEST_LENGTH];
    unsigned fhc_purge_divisor;
    unsigned fm_buckets;
    unsigned max_detection_pkts;
    unsigned max_fhc;
    unsigned max_flows;
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
    nd_interface_filter interface_filters;
#ifdef _ND_USE_PLUGINS
    typedef map<string, pair<string, map<string, string>>> map_plugin;
    map_plugin plugin_processors;
    map_plugin plugin_sinks;
#endif
    map<string, string> custom_headers;
    map<string, string> protocols;

    typedef map<string, pair<nd_capture_type, void *>> nd_config_interfaces;
    map<nd_interface_role, nd_config_interfaces> interfaces;
    map<string, set<string>> interface_addrs;
    map<string, string> interface_peers;

    map<string, string> conf_vars;

    ndGlobalConfig(const ndGlobalConfig&) = delete;
    ndGlobalConfig& operator=(const ndGlobalConfig&) = delete;

    static inline ndGlobalConfig& GetInstance() {
        static ndGlobalConfig config;
        return config;
    }

    void Close(void);

    bool Load(const string &filename);

    enum UUID {
        UUID_AGENT,
        UUID_SITE,
        UUID_SERIAL,
    };

    bool LoadUUID(UUID which, string &uuid);
    bool SaveUUID(UUID which, const string &uuid);
    void GetUUID(UUID which, string &uuid);

    bool ForceReset(void);

    void UpdateConfVars(void);

    bool AddInterface(const string &iface, nd_interface_role role,
        nd_capture_type type = ndCT_NONE, void *config = nullptr);

    bool AddInterfaceAddress(const string &iface, const string &addr);
    bool AddInterfacePeer(const string &iface, const string &peer);

    bool AddInterfaceFilter(const string &iface, const string &filter);

protected:
    void *reader;
    mutex lock_uuid;

    string uuid;
    string uuid_serial;
    string uuid_site;

    bool AddInterfaces(void);
#ifdef _ND_USE_PLUGINS
    bool AddPlugin(const string &filename);
#endif
    enum nd_capture_type LoadCaptureType(
        const string &section, const string &key);
    bool LoadCaptureSettings(
        const string &section, nd_capture_type &type, void *config);

    void UpdatePaths(void);

private:
    ndGlobalConfig();
    virtual ~ndGlobalConfig();
};

#endif // _ND_CONFIG_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
