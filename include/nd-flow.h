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

#ifndef _ND_FLOW_H
#define _ND_FLOW_H

// XXX: These lengths are extracted from:
//      ndpi/src/include/ndpi_typedefs.h
//
// Unfortunately they don't define such constants so we have to define
// them here.  If they change in nDPI, they'll need to be updated
// manually.
#define ND_FLOW_HOSTNAME    80      // nDPI host_server_name length
#define ND_FLOW_UA_LEN      512     // User agent length
#define ND_FLOW_URL_LEN     512     // HTTP URL length
#define ND_FLOW_SSH_UALEN   48      // SSH user-agent (signature) length
#define ND_FLOW_TLS_CNLEN   256     // TLS SNI hostname/common-name length
                                    // Reference: RFC 4366
#define ND_FLOW_TLS_ORGLEN  64      // TLS certificate organization name length
#define ND_FLOW_TLS_JA3LEN  33      // TLS JA3 hash length (MD5)
#define ND_FLOW_DHCPFP_LEN  48      // DHCP fingerprint length
#define ND_FLOW_DHCPCI_LEN  96      // DHCP class identifier

// BitTorrent info hash length
#define ND_FLOW_BTIHASH_LEN     SHA1_DIGEST_LENGTH

// SSL certificate fingerprint hash length
#define ND_FLOW_TLS_HASH_LEN    SHA1_DIGEST_LENGTH

// Extra protocol info text
#define ND_FLOW_EXTRA_INFO      16

// Capture filename template
#define ND_FLOW_CAPTURE_TEMPLATE    ND_VOLATILE_STATEDIR "/nd-flow-XXXXXXXX.cap"
#define ND_FLOW_CAPTURE_SUB_OFFSET  (sizeof(ND_FLOW_CAPTURE_TEMPLATE) - 8 - 4 - 1)

typedef pair<const struct pcap_pkthdr *, const uint8_t *> nd_flow_push;
typedef vector<nd_flow_push> nd_flow_capture;

typedef unordered_map<string, string> nd_flow_kvmap;

class ndFlow
{
public:
    const ndInterface iface;

    int16_t dpi_thread_id;

    uint8_t ip_version;
    uint8_t ip_protocol;

    uint16_t vlan_id;

    tcp_seq tcp_last_seq;

    uint64_t ts_first_seen;
    uint64_t ts_first_update;
    uint64_t ts_last_seen;

    enum {
        LOWER_UNKNOWN = 0x00,
        LOWER_LOCAL = 0x01,
        LOWER_OTHER = 0x02
    };

    uint8_t lower_map;

    enum {
        OTHER_UNKNOWN = 0x00,
        OTHER_UNSUPPORTED = 0x01,
        OTHER_LOCAL = 0x02,
        OTHER_MULTICAST = 0x03,
        OTHER_BROADCAST = 0x04,
        OTHER_REMOTE = 0x05,
        OTHER_ERROR = 0x06
    };

    uint8_t other_type;

    ndAddr lower_mac;
    ndAddr upper_mac;

    ndAddr lower_addr;
    ndAddr upper_addr;

    enum {
        TUNNEL_NONE = 0x00,
        TUNNEL_GTP = 0x01
    };

    uint8_t tunnel_type;

    uint64_t lower_bytes;
    uint64_t upper_bytes;
    uint64_t total_bytes;

    uint32_t lower_packets;
    uint32_t upper_packets;
    uint32_t total_packets;

    atomic_uchar detection_packets;

    nd_proto_id_t detected_protocol;
    nd_app_id_t detected_application;

    const char *detected_protocol_name;
    char *detected_application_name;

    struct {
        nd_cat_id_t application;
        nd_cat_id_t protocol;
        nd_cat_id_t domain;
    } category;

    struct ndpi_flow_struct *ndpi_flow;

    uint8_t digest_lower[SHA1_DIGEST_LENGTH];
    uint8_t digest_mdata[SHA1_DIGEST_LENGTH];

    char dns_host_name[ND_FLOW_HOSTNAME];
    char host_server_name[ND_FLOW_HOSTNAME];

    union {
        struct {
            char user_agent[ND_FLOW_UA_LEN];
            char url[ND_FLOW_URL_LEN];
        } http;

        struct {
            char fingerprint[ND_FLOW_DHCPFP_LEN];
            char class_ident[ND_FLOW_DHCPCI_LEN];
        } dhcp;

        struct {
            char client_agent[ND_FLOW_SSH_UALEN];
            char server_agent[ND_FLOW_SSH_UALEN];
        } ssh;

        struct {
            uint16_t version;
            uint16_t cipher_suite;
            char *client_sni, *subject_dn, *issuer_dn;
            char server_cn[ND_FLOW_TLS_CNLEN];
            char client_ja3[ND_FLOW_TLS_JA3LEN];
            char server_ja3[ND_FLOW_TLS_JA3LEN];
            bool cert_fingerprint_found;
            char cert_fingerprint[ND_FLOW_TLS_HASH_LEN];
        } ssl;

        struct {
            bool tls;
        } smtp;

        struct {
            uint8_t info_hash_valid:1;
            char info_hash[ND_FLOW_BTIHASH_LEN];
        } bt;
#if 0
        struct {
            char variant[ND_FLOW_EXTRA_INFO];
        } mining;
#endif
        struct {
            char domain_name[ND_FLOW_HOSTNAME];
        } mdns;
    };

    vector<string> tls_alpn, tls_alpn_server;

    struct {
        nd_flow_kvmap headers;
    } ssdp;

    enum {
        TYPE_LOWER,
        TYPE_UPPER,

        TYPE_MAX
    };

    enum {
        PRIVATE_LOWER = 0x01,
        PRIVATE_UPPER = 0x02
    };

    uint8_t privacy_mask;

    // Indicate flow origin.  This indicates which side sent the first packet.
    // XXX: If the service has missed a flow's initial packets, the origin's
    // accuracy would be 50%.
    enum {
        ORIGIN_UNKNOWN = 0x00,
        ORIGIN_LOWER = 0x01,
        ORIGIN_UPPER = 0x02
    };

    uint8_t origin;

    int direction;

    nd_flow_capture capture;
    char capture_filename[sizeof(ND_FLOW_CAPTURE_TEMPLATE)];

    // Start of conditional members.  These must be at the end or else access
    // from plugins compiled without various options will have incorrect
    // addresses
#if defined(_ND_USE_CONNTRACK) && defined(_ND_WITH_CONNTRACK_MDATA)
    uint32_t ct_id;
    uint32_t ct_mark;
#endif
    ndAddr::Type lower_type;
    ndAddr::Type upper_type;

    struct {
        atomic_bool detection_complete;
        atomic_bool detection_guessed;
        atomic_bool detection_init;
        atomic_bool detection_updated;
        atomic_bool dhc_hit;
        atomic_bool expired;
        atomic_bool expiring;
        atomic_bool ip_nat;
        atomic_bool risk_checked;
        atomic_bool soft_dissector;
        atomic_bool tcp_fin;
        atomic_uchar tcp_fin_ack;
    } flags;

    atomic_uint tickets;

    union {
        struct {
            uint8_t version;
            uint8_t ip_version;
            uint32_t lower_teid;
            uint32_t upper_teid;
            ndAddr::Type lower_type;
            ndAddr::Type upper_type;
            ndAddr lower_addr;
            ndAddr upper_addr;
            uint8_t lower_map;
            uint8_t other_type;
        } gtp;
    };

    vector<nd_risk_id_t> risks;
    uint16_t ndpi_risk_score;
    uint16_t ndpi_risk_score_client;
    uint16_t ndpi_risk_score_server;

    ndFlow(const ndInterface &iface);
    ndFlow(const ndFlow &flow);
    virtual ~ndFlow();

    void hash(const string &device, bool hash_mdata = false,
        const uint8_t *key = NULL, size_t key_length = 0);

    void push(const struct pcap_pkthdr *pkt_header, const uint8_t *pkt_data);

    int dump(pcap_t *pcap, const uint8_t *digest);

    void reset(bool full_reset = false);

    void release(void);

    nd_proto_id_t master_protocol(void) const;

    bool has_dhcp_fingerprint(void) const;
    bool has_dhcp_class_ident(void) const;
    bool has_http_user_agent(void) const;
    bool has_http_url(void) const;
    bool has_ssh_client_agent(void) const;
    bool has_ssh_server_agent(void) const;
    bool has_ssl_client_sni(void) const;
    bool has_ssl_server_cn(void) const;
    bool has_ssl_issuer_dn(void) const;
    bool has_ssl_subject_dn(void) const;
    bool has_ssl_client_ja3(void) const;
    bool has_ssl_server_ja3(void) const;
    bool has_bt_info_hash(void) const;
    bool has_ssdp_headers(void) const;
#if 0
    bool has_mining_variant(void) const;
#endif
    bool has_mdns_domain_name(void) const;

    void print(void) const;

    void update_lower_maps(void);
    void get_lower_map(
        ndAddr::Type lt,
        ndAddr::Type ut,
        uint8_t &lm, uint8_t &ot
    );

    enum nd_encode_include {
        ENCODE_NONE = 0x00,
        ENCODE_METADATA = 0x01,
        ENCODE_TUNNELS = 0x02,
        ENCODE_STATS = 0x04,
        ENCODE_ALL = (ENCODE_METADATA | ENCODE_TUNNELS | ENCODE_STATS)
    };

    template <class T>
    void encode(T &output, uint8_t encode_includes = ENCODE_ALL) const {
        string _other_type = "unknown";
        string _lower_mac = "local_mac", _upper_mac = "other_mac";
        string _lower_ip = "local_ip", _upper_ip = "other_ip";
        string _lower_gtp_ip = "local_ip", _upper_gtp_ip = "other_ip";
        string _lower_port = "local_port", _upper_port = "other_port";
        string _lower_gtp_port = "local_port", _upper_gtp_port = "other_port";
        string _lower_bytes = "local_bytes", _upper_bytes = "other_bytes";
        string _lower_packets = "local_packets", _upper_packets = "other_packets";

        string digest;
        uint8_t digest_null[SHA1_DIGEST_LENGTH] = { '\0' };

        if (memcmp(digest_mdata, digest_null, SHA1_DIGEST_LENGTH) != 0) {
            nd_sha1_to_string(digest_mdata, digest);
            assign(output, { "digest" }, digest);
        } else {
            nd_sha1_to_string(digest_lower, digest);
            assign(output, { "digest" }, digest);
        }

        assign(output, { "last_seen_at" }, ts_last_seen);

        switch (lower_map) {
        case LOWER_LOCAL:
            _lower_mac = "local_mac";
            _lower_ip = "local_ip";
            _lower_port = "local_port";
            _lower_bytes = "local_bytes";
            _lower_packets = "local_packets";
            _upper_mac = "other_mac";
            _upper_ip = "other_ip";
            _upper_port = "other_port";
            _upper_bytes = "other_bytes";
            _upper_packets = "other_packets";
            break;
        case LOWER_OTHER:
            _lower_mac = "other_mac";
            _lower_ip = "other_ip";
            _lower_port = "other_port";
            _lower_bytes = "other_bytes";
            _lower_packets = "other_packets";
            _upper_mac = "local_mac";
            _upper_ip = "local_ip";
            _upper_port = "local_port";
            _upper_bytes = "local_bytes";
            _upper_packets = "local_packets";
            break;
        }

        switch (other_type) {
        case OTHER_LOCAL:
            _other_type = "local";
            break;
        case OTHER_MULTICAST:
            _other_type = "multicast";
            break;
        case OTHER_BROADCAST:
            _other_type = "broadcast";
            break;
        case OTHER_REMOTE:
            _other_type = "remote";
            break;
        case OTHER_UNSUPPORTED:
            _other_type = "unsupported";
            break;
        case OTHER_ERROR:
            _other_type = "error";
            break;
        }

        if (encode_includes & ENCODE_METADATA) {
            assign(output, { "ip_nat" }, (bool)flags.ip_nat.load());
            assign(output, { "dhc_hit" }, (bool)flags.dhc_hit.load());
            assign(output, { "soft_dissector" }, (bool)flags.soft_dissector.load());
#if defined(_ND_USE_CONNTRACK) && defined(_ND_WITH_CONNTRACK_MDATA)
            assign(output, { "ct_id" }, ct_id);
            assign(output, { "ct_mark" }, ct_mark);
#endif
            assign(output, { "ip_version" }, (unsigned)ip_version);
            assign(output, { "ip_protocol" }, (unsigned)ip_protocol);
            assign(output, { "vlan_id" }, (unsigned)vlan_id);
            assign(output, { "other_type" }, _other_type);

            switch (origin) {
            case ORIGIN_UPPER:
                assign(output, { "local_origin" },
                    (_lower_ip == "local_ip") ? false : true);
                break;
            case ORIGIN_LOWER:
            default:
                assign(output, { "local_origin" },
                    (_lower_ip == "local_ip") ? true : false);
                break;
            }

            // 00-52-14 to 00-52-FF: Unassigned (small allocations)
            assign(output, { _lower_mac }, (privacy_mask & PRIVATE_LOWER) ?
                "00:52:14:00:00:00" : lower_mac.GetString());
            assign(output, { _upper_mac }, (privacy_mask & PRIVATE_UPPER) ?
                "00:52:ff:00:00:00" : upper_mac.GetString());

            if (privacy_mask & PRIVATE_LOWER) {
                if (ip_version == 4)
                    assign(output, { _lower_ip }, ND_PRIVATE_IPV4 "253");
                else
                    assign(output, { _lower_ip }, ND_PRIVATE_IPV6 "fd");
            }
            else
                assign(output, { _lower_ip }, lower_addr.GetString());

            if (privacy_mask & PRIVATE_UPPER) {
                if (ip_version == 4)
                    assign(output, { _upper_ip }, ND_PRIVATE_IPV4 "254");
                else
                    assign(output, { _upper_ip }, ND_PRIVATE_IPV6 "fe");
            }
            else
                assign(output, { _upper_ip }, upper_addr.GetString());

            assign(output, { _lower_port }, (unsigned)lower_addr.GetPort());
            assign(output, { _upper_port }, (unsigned)upper_addr.GetPort());

            assign(output, { "detected_protocol" }, (unsigned)detected_protocol);
            assign(output, { "detected_protocol_name"},
                (detected_protocol_name != NULL) ? detected_protocol_name : "Unknown");

            assign(output, { "detected_application" }, (unsigned)detected_application);
            assign(output, { "detected_application_name" },
                (detected_application_name != NULL) ? detected_application_name : "Unknown");

            assign(output, { "detection_guessed" }, flags.detection_guessed.load());
            assign(output, { "detection_updated" }, flags.detection_updated.load());

            assign(output, { "category", "application" }, category.application);
            assign(output, { "category", "protocol" }, category.protocol);
            assign(output, { "category", "domain" }, category.domain);

            if (dns_host_name[0] != '\0')
                assign(output, { "dns_host_name" }, dns_host_name);

            if (host_server_name[0] != '\0')
                assign(output, { "host_server_name" }, host_server_name);

            if (has_http_user_agent() || has_http_url()) {

                if (has_http_user_agent())
                    assign(output, { "http", "user_agent" }, http.user_agent);
                if (has_http_url())
                    assign(output, { "http", "url" }, http.url);
            }

            if (has_dhcp_fingerprint() || has_dhcp_class_ident()) {

                if (has_dhcp_fingerprint())
                    assign(output, { "dhcp", "fingerprint" }, dhcp.fingerprint);

                if (has_dhcp_class_ident())
                    assign(output, { "dhcp", "class_ident" }, dhcp.class_ident);
            }

            if (has_ssh_client_agent() || has_ssh_server_agent()) {

                if (has_ssh_client_agent())
                    assign(output, { "ssh", "client" }, ssh.client_agent);

                if (has_ssh_server_agent())
                    assign(output, { "ssh", "server" }, ssh.server_agent);
            }

            if (master_protocol() == ND_PROTO_TLS
                || detected_protocol == ND_PROTO_QUIC) {

                char tohex[7];

                sprintf(tohex, "0x%04hx", ssl.version);
                assign(output, { "ssl", "version" }, tohex);

                sprintf(tohex, "0x%04hx", ssl.cipher_suite);
                assign(output, { "ssl", "cipher_suite" }, tohex);

                if (has_ssl_client_sni())
                    assign(output, { "ssl", "client_sni" }, ssl.client_sni);

                if (has_ssl_server_cn())
                    assign(output, { "ssl", "server_cn" }, ssl.server_cn);

                if (has_ssl_issuer_dn())
                    assign(output, { "ssl", "issuer_dn" }, ssl.issuer_dn);

                if (has_ssl_subject_dn())
                    assign(output, { "ssl", "subject_dn" }, ssl.subject_dn);

                if (has_ssl_client_ja3())
                    assign(output, { "ssl", "client_ja3" }, ssl.client_ja3);

                if (has_ssl_server_ja3())
                    assign(output, { "ssl", "server_ja3" }, ssl.server_ja3);

                if (ssl.cert_fingerprint_found) {
                    nd_sha1_to_string((const uint8_t *)ssl.cert_fingerprint, digest);
                    assign(output, { "ssl", "fingerprint" }, digest);
                }

                assign(output, { "ssl", "alpn" }, tls_alpn);
                assign(output, { "ssl", "alpn_server" }, tls_alpn_server);
            }

            if (has_bt_info_hash()) {
                nd_sha1_to_string((const uint8_t *)bt.info_hash, digest);
                assign(output, { "bt", "info_hash" }, digest);
            }

            if (has_ssdp_headers())
                assign(output, { "ssdp" }, ssdp.headers);
#if 0
            if (has_mining_variant())
                assign(output, { "mining", "variant" }, mining.variant);
#endif
            if (has_mdns_domain_name())
                assign(output, { "mdns", "answer" }, mdns.domain_name);

            assign(output, { "first_seen_at" }, ts_first_seen);
            assign(output, { "first_update_at" }, ts_first_update);

            assign(output, { "risks", "risks" }, risks);
            assign(output, { "risks", "ndpi_risk_score" }, ndpi_risk_score);
            assign(output, { "risks", "ndpi_risk_score_client" }, ndpi_risk_score_client);
            assign(output, { "risks", "ndpi_risk_score_server" }, ndpi_risk_score_server);
        }

        if (encode_includes & ENCODE_TUNNELS) {
            string _lower_teid = "local_teid", _upper_teid = "other_teid";

            switch (tunnel_type) {
            case TUNNEL_GTP:
                switch (gtp.lower_map) {
                case LOWER_LOCAL:
                    _lower_ip = "local_ip";
                    _lower_port = "local_port";
                    _lower_teid = "local_teid";
                    _upper_ip = "other_ip";
                    _upper_port = "other_port";
                    _upper_teid = "other_teid";
                    break;
                case LOWER_OTHER:
                    _lower_ip = "other_ip";
                    _lower_port = "other_port";
                    _lower_teid = "other_teid";
                    _upper_ip = "local_ip";
                    _upper_port = "local_port";
                    _upper_teid = "local_teid";
                    break;
                }

                switch (gtp.other_type) {
                case OTHER_LOCAL:
                    _other_type = "local";
                    break;
                case OTHER_REMOTE:
                    _other_type = "remote";
                    break;
                case OTHER_ERROR:
                    _other_type = "error";
                    break;
                case OTHER_UNSUPPORTED:
                default:
                    _other_type = "unsupported";
                    break;
                }

                assign(output, { "gtp", "version" }, gtp.version);
                assign(output, { "gtp", "ip_version" }, gtp.ip_version);
                assign(output, { "gtp", _lower_ip }, gtp.lower_addr.GetString());
                assign(output, { "gtp", _upper_ip }, gtp.upper_addr.GetString());
                assign(output, { "gtp", _lower_port }, (unsigned)gtp.lower_addr.GetPort());
                assign(output, { "gtp", _upper_port }, (unsigned)gtp.upper_addr.GetPort());
                assign(output, { "gtp", _lower_teid }, htonl(gtp.lower_teid));
                assign(output, { "gtp", _upper_teid }, htonl(gtp.upper_teid));
                assign(output, { "gtp", "other_type" }, _other_type);

                break;
            }
        }

        if (encode_includes & ENCODE_STATS) {
            assign(output, { _lower_bytes }, lower_bytes);
            assign(output, { _upper_bytes }, upper_bytes);
            assign(output, { _lower_packets }, lower_packets);
            assign(output, { _upper_packets }, upper_packets);
            assign(output, { "total_packets" }, total_packets);
            assign(output, { "total_bytes" }, total_bytes);
            assign(output, { "detection_packets" }, detection_packets.load());
        }
    }

    inline void assign(json &j, const vector<string> &keys, const string &value) const {
        if (keys.empty() || value.empty()) return;
        if (keys.size() == 2)
            j[keys[0]][keys[1]] = value;
        if (keys.size() == 1)
            j[keys[0]] = value;
    }
    inline void assign(json &j, const vector<string> &keys, uint8_t value) const {
        if (keys.empty()) return;
        if (keys.size() == 2)
            j[keys[0]][keys[1]] = value;
        if (keys.size() == 1)
            j[keys[0]] = value;
    }
    inline void assign(json &j, const vector<string> &keys, uint16_t value) const {
        if (keys.empty()) return;
        if (keys.size() == 2)
            j[keys[0]][keys[1]] = value;
        if (keys.size() == 1)
            j[keys[0]] = value;
    }
    inline void assign(json &j, const vector<string> &keys, uint32_t value) const {
        if (keys.empty()) return;
        if (keys.size() == 2)
            j[keys[0]][keys[1]] = value;
        if (keys.size() == 1)
            j[keys[0]] = value;
    }
    inline void assign(json &j, const vector<string> &keys, uint64_t value) const {
        if (keys.empty()) return;
        if (keys.size() == 2)
            j[keys[0]][keys[1]] = value;
        if (keys.size() == 1)
            j[keys[0]] = value;
    }
    inline void assign(json &j, const vector<string> &keys, bool value) const {
        if (keys.empty()) return;
        if (keys.size() == 2)
            j[keys[0]][keys[1]] = value;
        if (keys.size() == 1)
            j[keys[0]] = value;
    }
    inline void assign(json &j, const vector<string> &keys, const char *value) const {
        if (keys.empty()) return;
        if (keys.size() == 2)
            j[keys[0]][keys[1]] = value;
        if (keys.size() == 1)
            j[keys[0]] = value;
    }
    inline void assign(json &j, const vector<string> &keys, const vector<nd_risk_id_t> &values) const {
        if (keys.empty() || values.empty()) return;
        if (keys.size() == 2)
            j[keys[0]][keys[1]] = values;
        if (keys.size() == 1)
            j[keys[0]] = values;
    }
    inline void assign(json &j, const vector<string> &keys, const vector<unsigned> &values) const {
        if (keys.empty() || values.empty()) return;
        if (keys.size() == 2)
            j[keys[0]][keys[1]] = values;
        if (keys.size() == 1)
            j[keys[0]] = values;
    }
    inline void assign(json &j, const vector<string> &keys, const vector<string> &values) const {
        if (keys.empty() || values.empty()) return;
        if (keys.size() == 2)
            j[keys[0]][keys[1]] = values;
        if (keys.size() == 1)
            j[keys[0]] = values;
    }
    inline void assign(json &j, const vector<string> &keys, const unordered_map<string, string> &values) const {
        if (keys.empty() || values.empty()) return;
        if (keys.size() == 2)
            j[keys[0]][keys[1]] = values;
        if (keys.size() == 1)
            j[keys[0]] = values;
    }

    inline void assign(vector<string> &v, const vector<string> &keys, const string &value) const {
        if (keys.empty() || value.empty()) return;
        string key;
        for (auto &k : keys) key.append(key.empty() ? k : string(":") + k);
        v.push_back(key);
        v.push_back(value);
    }
    inline void assign(vector<string> &v, const vector<string> &keys, uint8_t value) const {
        if (keys.empty()) return;
        string key;
        for (auto &k : keys) key.append(key.empty() ? k : string(":") + k);
        v.push_back(key);
        v.push_back(to_string(value));
    }
    inline void assign(vector<string> &v, const vector<string> &keys, uint16_t value) const {
        if (keys.empty()) return;
        string key;
        for (auto &k : keys) key.append(key.empty() ? k : string(":") + k);
        v.push_back(key);
        v.push_back(to_string(value));
    }
    inline void assign(vector<string> &v, const vector<string> &keys, uint32_t value) const {
        if (keys.empty()) return;
        string key;
        for (auto &k : keys) key.append(key.empty() ? k : string(":") + k);
        v.push_back(key);
        v.push_back(to_string(value));
    }
    inline void assign(vector<string> &v, const vector<string> &keys, uint64_t value) const {
        if (keys.empty()) return;
        string key;
        for (auto &k : keys) key.append(key.empty() ? k : string(":") + k);
        v.push_back(key);
        v.push_back(to_string(value));
    }
    inline void assign(vector<string> &v, const vector<string> &keys, bool value) const {
        if (keys.empty()) return;
        string key;
        for (auto &k : keys) key.append(key.empty() ? k : string(":") + k);
        v.push_back(key);
        v.push_back(to_string(value));
    }
    inline void assign(vector<string> &v, const vector<string> &keys, const char *value) const {
        if (keys.empty()) return;
        string key;
        for (auto &k : keys) key.append(key.empty() ? k : string(":") + k);
        v.push_back(key);
        v.push_back(value);
    }
    inline void assign(vector<string> &v, const vector<string> &keys, const vector<unsigned> &values) const {
        if (keys.empty() || values.empty()) return;
        string key;
        for (auto &k : keys) key.append(key.empty() ? k : string(":") + k);
        v.push_back(key);
        string _values;
        for (auto &value : values) _values.append(_values.empty() ? to_string(value) : string(",") + to_string(value));
        v.push_back(_values);
    }
    inline void assign(vector<string> &v, const vector<string> &keys, const vector<nd_risk_id_t> &values) const {
        if (keys.empty() || values.empty()) return;
        string key;
        for (auto &k : keys) key.append(key.empty() ? k : string(":") + k);
        v.push_back(key);
        string _values;
        for (auto &value : values) _values.append(_values.empty() ? to_string(value) : string(",") + to_string(value));
        v.push_back(_values);
    }
    inline void assign(vector<string> &v, const vector<string> &keys, const vector<string> &values) const {
        if (keys.empty() || values.empty()) return;
        string key;
        for (auto &k : keys) key.append(key.empty() ? k : string(":") + k);
        v.push_back(key);
        v.push_back(values.empty() ? string() :
            accumulate(
                ++values.begin(), values.end(),
                *values.begin(), [](const string &a, const string &b) { return a + "," + b; }
            )
        );
    }
    inline void assign(vector<string> &v, const vector<string> &keys, const unordered_map<string, string> &values) const {
        if (keys.empty() || values.empty()) return;
        string key;
        for (auto &k : keys) key.append(key.empty() ? k : string(":") + k);
        v.push_back(key);

        vector<string> _values;
        for (auto &v : values) _values.push_back(v.first + ":" + v.second);
        v.push_back(_values.empty() ? string() :
            accumulate(
                ++_values.begin(), _values.end(),
                *_values.begin(), [](const string &a, const string &b) { return a + "," + b; }
            )
        );
    }

    inline bool operator==(const ndFlow &f) const {
        return (lower_addr == f.lower_addr && upper_addr == f.upper_addr);
    }

    inline ndFlow& operator+=(const ndFlow &f)
    {
        this->lower_bytes += f.lower_bytes;
        this->upper_bytes += f.upper_bytes;
        this->total_bytes += f.total_bytes;
        this->lower_packets += f.lower_packets;
        this->upper_packets += f.upper_packets;
        this->total_packets += f.total_packets;
        return *this;
    }
};

typedef unordered_map<string, ndFlow *> nd_flow_map;
typedef map<string, nd_flow_map *> nd_flows;
typedef pair<string, ndFlow *> nd_flow_pair;
typedef pair<nd_flow_map::iterator, bool> nd_flow_insert;

class ndFlowTicket
{
public:
    ndFlowTicket(ndFlow *flow = nullptr);

    virtual ~ndFlowTicket();

    void Take(ndFlow *flow = nullptr, bool increment = true);

protected:
    ndFlow *flow;
};

#endif // _ND_FLOW_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
