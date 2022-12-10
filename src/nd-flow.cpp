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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdexcept>
#include <cstring>
#include <map>
#include <list>
#include <vector>
#include <set>
#include <atomic>
#include <unordered_map>
#include <unordered_set>
#include <sstream>
#include <regex>
#include <mutex>
#include <bitset>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#define __FAVOR_BSD 1
#include <netinet/tcp.h>
#undef __FAVOR_BSD

#include <errno.h>

#include <arpa/inet.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>

#include <pcap/pcap.h>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#include <radix/radix_tree.hpp>

using namespace std;

#include "netifyd.h"

#include "nd-config.h"
#include "nd-ndpi.h"
#ifdef _ND_USE_NETLINK
#include "nd-netlink.h"
#endif
#include "nd-packet.h"
#include "nd-json.h"
#include "nd-util.h"
#include "nd-addr.h"
#include "nd-apps.h"
#include "nd-category.h"
#include "nd-protos.h"
#include "nd-risks.h"
#include "nd-flow.h"

// Enable flow hash cache debug logging
//#define _ND_DEBUG_FHC 1

extern ndGlobalConfig nd_config;

nd_device_ether nd_device_ethers;

ndFlow::ndFlow(const ndInterface &iface)
    : iface(iface), dpi_thread_id(-1),
    ip_version(0), ip_protocol(0), vlan_id(0), tcp_last_seq(0),
    ts_first_seen(0), ts_first_update(0), ts_last_seen(0),
    lower_map(LOWER_UNKNOWN), other_type(OTHER_UNKNOWN),
    tunnel_type(TUNNEL_NONE),
    lower_bytes(0), upper_bytes(0), total_bytes(0),
    lower_packets(0), upper_packets(0), total_packets(0),
    detection_packets(0),
    detected_protocol(ND_PROTO_UNKNOWN),
    detected_application(ND_APP_UNKNOWN),
    detected_protocol_name("Unknown"),
    detected_application_name(NULL),
    category { ND_CAT_UNKNOWN, ND_CAT_UNKNOWN, ND_CAT_UNKNOWN },
    ndpi_flow(NULL),
    digest_lower{}, digest_mdata{},
    dns_host_name{}, host_server_name{}, http{},
    privacy_mask(0), origin(0), direction(0),
    capture_filename{},
#if defined(_ND_USE_CONNTRACK) && defined(_ND_WITH_CONNTRACK_MDATA)
    ct_id(0), ct_mark(0),
#endif
#ifdef _ND_USE_NETLINK
    lower_type(ndNETLINK_ATYPE_UNKNOWN), upper_type(ndNETLINK_ATYPE_UNKNOWN),
#endif
    flags{}, tickets(0), gtp{},
    risks{}, ndpi_risk_score(0), ndpi_risk_score_client(0), ndpi_risk_score_server(0)
{
    gtp.version = 0xFF;
}

ndFlow::ndFlow(const ndFlow &flow)
    : iface(flow.iface), dpi_thread_id(-1),
    ip_version(flow.ip_version), ip_protocol(flow.ip_protocol),
    vlan_id(flow.vlan_id), tcp_last_seq(flow.tcp_last_seq),
    ts_first_seen(flow.ts_first_seen), ts_first_update(flow.ts_first_update),
    ts_last_seen(flow.ts_last_seen),
    lower_map(LOWER_UNKNOWN), other_type(OTHER_UNKNOWN),
    lower_mac(flow.lower_mac), upper_mac(flow.upper_mac),
    lower_addr(flow.lower_addr), upper_addr(flow.upper_addr),
    tunnel_type(flow.tunnel_type),
    lower_bytes(0), upper_bytes(0), total_bytes(0),
    lower_packets(0), upper_packets(0), total_packets(0),
    detection_packets(0),
    detected_protocol(ND_PROTO_UNKNOWN),
    detected_application(ND_APP_UNKNOWN),
    detected_protocol_name("Unknown"),
    detected_application_name(NULL),
    category { ND_CAT_UNKNOWN, ND_CAT_UNKNOWN, ND_CAT_UNKNOWN },
    ndpi_flow(NULL),
    dns_host_name{}, host_server_name{}, http{},
    privacy_mask(0), origin(0), direction(0),
    capture_filename{},
#if defined(_ND_USE_CONNTRACK) && defined(_ND_WITH_CONNTRACK_MDATA)
    ct_id(0), ct_mark(0),
#endif
#ifdef _ND_USE_NETLINK
    lower_type(ndNETLINK_ATYPE_UNKNOWN), upper_type(ndNETLINK_ATYPE_UNKNOWN),
#endif
    flags{}, tickets(0), gtp(flow.gtp),
    risks{}, ndpi_risk_score(0), ndpi_risk_score_client(0), ndpi_risk_score_server(0)
{
    memcpy(digest_lower, flow.digest_lower, SHA1_DIGEST_LENGTH);
    memset(digest_mdata, 0, SHA1_DIGEST_LENGTH);
}

ndFlow::~ndFlow()
{
    release();

    if (detected_application_name != NULL) {
        free(detected_application_name);
        detected_application_name = NULL;
    }

    if (has_ssl_issuer_dn()) {
        free(ssl.issuer_dn);
        ssl.issuer_dn = NULL;
    }

    if (has_ssl_subject_dn()) {
        free(ssl.subject_dn);
        ssl.subject_dn = NULL;
    }
}

void ndFlow::hash(const string &device,
    bool hash_mdata, const uint8_t *key, size_t key_length)
{
    sha1 ctx;

    sha1_init(&ctx);
    sha1_write(&ctx, (const char *)device.c_str(), device.size());

    sha1_write(&ctx, (const char *)&ip_version, sizeof(ip_version));
    sha1_write(&ctx, (const char *)&ip_protocol, sizeof(ip_protocol));
    sha1_write(&ctx, (const char *)&vlan_id, sizeof(vlan_id));

    switch (ip_version) {
    case 4:
        sha1_write(&ctx,
            (const char *)&lower_addr.addr.in.sin_addr, sizeof(struct in_addr));
        sha1_write(&ctx,
            (const char *)&upper_addr.addr.in.sin_addr, sizeof(struct in_addr));

        if (lower_addr.addr.in.sin_addr.s_addr == 0 &&
            upper_addr.addr.in.sin_addr.s_addr == 0xffffffff) {
            // XXX: Hash in lower MAC for ethernet broadcasts (DHCPv4).
            sha1_write(&ctx, (const char *)&lower_mac.addr.ll.sll_addr, ETH_ALEN);
        }

        break;
    case 6:
        sha1_write(&ctx,
            (const char *)&lower_addr.addr.in6.sin6_addr, sizeof(struct in6_addr));
        sha1_write(&ctx,
            (const char *)&upper_addr.addr.in6.sin6_addr, sizeof(struct in6_addr));
        break;
    default:
        break;
    }

    uint16_t port = lower_addr.GetPort(false);
    sha1_write(&ctx, (const char *)&port, sizeof(port));
    port = upper_addr.GetPort(false);
    sha1_write(&ctx, (const char *)&port, sizeof(port));

    if (hash_mdata) {
        sha1_write(&ctx,
            (const char *)&detected_protocol, sizeof(ndpi_protocol));

        if (host_server_name[0] != '\0') {
            sha1_write(&ctx,
                host_server_name, strnlen(host_server_name, ND_FLOW_HOSTNAME));
        }
        if (has_ssl_client_sni()) {
            sha1_write(&ctx,
                ssl.client_sni, strnlen(ssl.client_sni, ND_FLOW_HOSTNAME));
        }
        if (has_bt_info_hash()) {
            sha1_write(&ctx, bt.info_hash, ND_FLOW_BTIHASH_LEN);
        }
    }

    if (key != NULL && key_length > 0)
        sha1_write(&ctx, (const char *)key, key_length);

    if (! hash_mdata)
        sha1_result(&ctx, digest_lower);
    else
        sha1_result(&ctx, digest_mdata);
}

void ndFlow::push(const struct pcap_pkthdr *pkt_header, const uint8_t *pkt_data)
{
    struct pcap_pkthdr *header = new struct pcap_pkthdr;
    if (header == NULL)
        throw ndSystemException(__PRETTY_FUNCTION__, "new header", ENOMEM);
    uint8_t *data = new uint8_t[pkt_header->len];
    if (data == NULL)
        throw ndSystemException(__PRETTY_FUNCTION__, "new data", ENOMEM);

    memcpy(header, pkt_header, sizeof(struct pcap_pkthdr));
    memcpy(data, pkt_data, pkt_header->caplen);

    capture.push_back(make_pair(header, data));
}

int ndFlow::dump(pcap_t *pcap, const uint8_t *digest)
{
    char *p = capture_filename;
    memcpy(p, ND_FLOW_CAPTURE_TEMPLATE, sizeof(ND_FLOW_CAPTURE_TEMPLATE));

    p += ND_FLOW_CAPTURE_SUB_OFFSET;
    for (int i = 0; i < 4; i++, p += 2) sprintf(p, "%02hhx", digest[i]);
    strcat(p, ".cap");

    pcap_dumper_t *pcap_dumper = pcap_dump_open(pcap, capture_filename);

    if (pcap_dumper == NULL) {
        nd_dprintf("%s: pcap_dump_open: %s: %s\n",
            __PRETTY_FUNCTION__, capture_filename, "unknown");
        return -1;
    }

    for (nd_flow_capture::const_iterator i = capture.begin();
        i != capture.end(); i++) {
        pcap_dump((uint8_t *)pcap_dumper, i->first, i->second);
    }

    pcap_dump_close(pcap_dumper);

    return 0;
}

void ndFlow::reset(void)
{
    ts_first_update = 0;
    lower_bytes = upper_bytes = 0;
    lower_packets = upper_packets = 0;
}

void ndFlow::release(void)
{
    if (ndpi_flow != NULL) { ndpi_free_flow(ndpi_flow); ndpi_flow = NULL; }

    for (nd_flow_capture::const_iterator i = capture.begin();
        i != capture.end(); i++) {
        delete i->first;
        delete [] i->second;
    }

    capture.clear();
}

nd_proto_id_t ndFlow::master_protocol(void) const
{
    switch (detected_protocol) {
    case ND_PROTO_HTTPS:
    case ND_PROTO_TLS:
    case ND_PROTO_FTPS_CONTROL:
    case ND_PROTO_FTPS_DATA:
    case ND_PROTO_MAIL_IMAPS:
    case ND_PROTO_MAIL_POPS:
    case ND_PROTO_MAIL_SMTPS:
    case ND_PROTO_MQTTS:
    case ND_PROTO_NNTPS:
    case ND_PROTO_SIPS:
        return ND_PROTO_TLS;
    case ND_PROTO_HTTP:
    case ND_PROTO_HTTP_CONNECT:
    case ND_PROTO_HTTP_PROXY:
    case ND_PROTO_OOKLA:
    case ND_PROTO_PPSTREAM:
    case ND_PROTO_QQ:
    case ND_PROTO_RTSP:
    case ND_PROTO_STEAM:
    case ND_PROTO_TEAMVIEWER:
    case ND_PROTO_XBOX:
        return ND_PROTO_HTTP;
    default:
        break;
    }

    return detected_protocol;
}

bool ndFlow::has_dhcp_fingerprint(void) const
{
    return (
        detected_protocol == ND_PROTO_DHCP &&
        dhcp.fingerprint[0] != '\0'
    );
}

bool ndFlow::has_dhcp_class_ident(void) const
{
    return (
        detected_protocol == ND_PROTO_DHCP &&
        dhcp.class_ident[0] != '\0'
    );
}

bool ndFlow::has_http_user_agent(void) const
{
    return (
        master_protocol() == ND_PROTO_HTTP &&
        http.user_agent[0] != '\0'
    );
}

bool ndFlow::has_http_url(void) const
{
    return (
        http.url[0] != '\0'
    );
}

bool ndFlow::has_ssh_client_agent(void) const
{
    return (
        detected_protocol == ND_PROTO_SSH &&
        ssh.client_agent[0] != '\0'
    );
}

bool ndFlow::has_ssh_server_agent(void) const
{
    return (
        detected_protocol == ND_PROTO_SSH &&
        ssh.server_agent[0] != '\0'
    );
}

bool ndFlow::has_ssl_client_sni(void) const
{
    return (
        (master_protocol() == ND_PROTO_TLS || detected_protocol == ND_PROTO_QUIC) &&
        ssl.client_sni != NULL && ssl.client_sni[0] != '\0'
    );
}

bool ndFlow::has_ssl_server_cn(void) const
{
    return (
        (master_protocol() == ND_PROTO_TLS || detected_protocol == ND_PROTO_QUIC) &&
        ssl.server_cn[0] != '\0'
    );
}

bool ndFlow::has_ssl_issuer_dn(void) const
{
    return (
        (master_protocol() == ND_PROTO_TLS || detected_protocol == ND_PROTO_QUIC) &&
        ssl.issuer_dn != NULL
    );
}

bool ndFlow::has_ssl_subject_dn(void) const
{
    return (
        (master_protocol() == ND_PROTO_TLS || detected_protocol == ND_PROTO_QUIC) &&
        ssl.subject_dn != NULL
    );
}

bool ndFlow::has_ssl_client_ja3(void) const
{
    return (
        master_protocol() == ND_PROTO_TLS &&
        ssl.client_ja3[0] != '\0'
    );
}

bool ndFlow::has_ssl_server_ja3(void) const
{
    return (
        master_protocol() == ND_PROTO_TLS &&
        ssl.server_ja3[0] != '\0'
    );
}

bool ndFlow::has_bt_info_hash(void) const
{
    return (
        detected_protocol == ND_PROTO_BITTORRENT &&
        bt.info_hash_valid
    );
}

bool ndFlow::has_ssdp_headers(void) const
{
    return (
        detected_protocol == ND_PROTO_SSDP &&
        ssdp.headers.size()
    );
}
#if 0
bool ndFlow::has_mining_variant(void) const
{
    return (
        detected_protocol == ND_PROTO_MINING &&
        mining.variant[0] != '\0'
    );
}
#endif
bool ndFlow::has_mdns_domain_name(void) const
{
    return (
        detected_protocol == ND_PROTO_MDNS &&
        mdns.domain_name[0] != '\0'
    );
}

void ndFlow::print(void) const
{
    const char *lower_name = lower_addr.GetString().c_str(),
        *upper_name = upper_addr.GetString().c_str();

    if (ND_DEBUG_WITH_ETHERS) {
        string key;
        nd_device_ether::const_iterator i;

        key.assign((const char *)lower_mac.addr.ll.sll_addr, ETH_ALEN);

        i = nd_device_ethers.find(key);
        if (i != nd_device_ethers.end())
            lower_name = i->second.c_str();

        key.assign((const char *)upper_mac.addr.ll.sll_addr, ETH_ALEN);

        i = nd_device_ethers.find(key);
        if (i != nd_device_ethers.end())
            upper_name = i->second.c_str();
    }

    string iface_name;
    nd_iface_name(iface.ifname, iface_name);

    string digest;
    nd_sha1_to_string((const uint8_t *)bt.info_hash, digest);

    nd_flow_printf(
        "%s: [%c%c%c%c%c%c%c%c] %s%s%s %s:%hu %c%c%c %s:%hu%s%s%s%s%s%s%s\n",
        iface_name.c_str(),
        (iface.internal) ? 'i' : 'e',
        (ip_version == 4) ? '4' : (ip_version == 6) ? '6' : '-',
        flags.ip_nat.load() ? 'n' : '-',
        (flags.detection_updated.load()) ? 'u' : '-',
        (flags.detection_guessed.load()) ? 'g' : '-',
        (flags.dhc_hit.load()) ? 'd' : '-',
        (privacy_mask & PRIVATE_LOWER) ? 'p' :
            (privacy_mask & PRIVATE_UPPER) ? 'P' :
            (privacy_mask & (PRIVATE_LOWER | PRIVATE_UPPER)) ? 'X' :
            '-',
        (flags.soft_dissector.load()) ? 's' : '-',
        detected_protocol_name,
        (detected_application_name != NULL) ? "." : "",
        (detected_application_name != NULL) ? detected_application_name : "",
        lower_name, lower_addr.GetPort(),
        (origin == ORIGIN_LOWER || origin == ORIGIN_UNKNOWN) ? '-' : '<',
        (origin == ORIGIN_UNKNOWN) ? '?' : '-',
        (origin == ORIGIN_UPPER || origin == ORIGIN_UNKNOWN) ? '-' : '>',
        upper_name, upper_addr.GetPort(),
        (dns_host_name[0] != '\0' || host_server_name[0] != '\0') ? " H: " : "",
        (host_server_name[0] != '\0') ? host_server_name : (
            (dns_host_name[0] != '\0') ? dns_host_name : ""
        ),
        (has_ssl_client_sni()) ? " SSL" : "",
        (has_ssl_client_sni()) ? " C: " : "",
        (has_ssl_client_sni()) ? ssl.client_sni : "",
        (has_bt_info_hash()) ? " BT-IH: " : "",
        (has_bt_info_hash()) ? digest.c_str() : ""
    );
#if 0
    if (ND_DEBUG &&
        detected_protocol == ND_PROTO_TLS &&
        flags.detection_guessed.load() == false && ssl.version == 0x0000) {
        nd_dprintf("%s: SSL with no SSL/TLS verison.\n", iface.ifname.c_str());
    }
#endif
}

void ndFlow::update_lower_maps(void)
{
    if (lower_map == LOWER_UNKNOWN)
#ifdef _ND_USE_NETLINK
        get_lower_map(lower_type, upper_type, lower_map, other_type);
#else
        get_lower_map(lower_map, other_type);
#endif
    switch (tunnel_type) {
    case TUNNEL_GTP:
        if (gtp.lower_map == LOWER_UNKNOWN) {
            get_lower_map(
#ifdef _ND_USE_NETLINK
                gtp.lower_type, gtp.upper_type, gtp.lower_map, gtp.other_type
#else
                gtp.lower_map, gtp.other_type
#endif
            );
        }
    break;
    }
}

void ndFlow::get_lower_map(
#ifdef _ND_USE_NETLINK
    ndNetlinkAddressType lt,
    ndNetlinkAddressType ut,
#endif
    uint8_t &lm, uint8_t &ot)
{
#ifdef _ND_USE_NETLINK
    if (lt == ndNETLINK_ATYPE_ERROR ||
        ut == ndNETLINK_ATYPE_ERROR) {
        ot = OTHER_ERROR;
        return;
    }
    else if (lt == ndNETLINK_ATYPE_LOCALIP &&
        ut == ndNETLINK_ATYPE_LOCALNET) {
        lm = LOWER_OTHER;
        ot = OTHER_LOCAL;
    }
    else if (lt == ndNETLINK_ATYPE_LOCALNET &&
        ut == ndNETLINK_ATYPE_LOCALIP) {
        lm = LOWER_LOCAL;
        ot = OTHER_LOCAL;
    }
    else if (lt == ndNETLINK_ATYPE_MULTICAST) {
        lm = LOWER_OTHER;
        ot = OTHER_MULTICAST;
    }
    else if (ut == ndNETLINK_ATYPE_MULTICAST) {
        lm = LOWER_LOCAL;
        ot = OTHER_MULTICAST;
    }
    else if (lt == ndNETLINK_ATYPE_BROADCAST) {
        lm = LOWER_OTHER;
        ot = OTHER_BROADCAST;
    }
    else if (ut == ndNETLINK_ATYPE_BROADCAST) {
        lm = LOWER_LOCAL;
        ot = OTHER_BROADCAST;
    }
    else if (lt == ndNETLINK_ATYPE_PRIVATE &&
        ut == ndNETLINK_ATYPE_LOCALNET) {
        lm = LOWER_OTHER;
        ot = OTHER_LOCAL;
    }
    else if (lt == ndNETLINK_ATYPE_LOCALNET &&
        ut == ndNETLINK_ATYPE_PRIVATE) {
        lm = LOWER_LOCAL;
        ot = OTHER_LOCAL;
    }
#if 0
    // TODO: Further investigation required!
    // This appears to catch corrupted IPv6 headers.
    // Spend some time to figure out if there are any
    // possible over-matches for different methods of
    // deployment (gateway/port mirror modes).
#endif
    else if (ip_version != 6 &&
        lt == ndNETLINK_ATYPE_PRIVATE &&
        ut == ndNETLINK_ATYPE_PRIVATE) {
        lm = LOWER_LOCAL;
        ot = OTHER_LOCAL;
    }
    else if (lt == ndNETLINK_ATYPE_PRIVATE &&
        ut == ndNETLINK_ATYPE_LOCALIP) {
        lm = LOWER_OTHER;
        ot = OTHER_REMOTE;
    }
    else if (lt == ndNETLINK_ATYPE_LOCALIP &&
        ut == ndNETLINK_ATYPE_PRIVATE) {
        lm = LOWER_LOCAL;
        ot = OTHER_REMOTE;
    }
    else if (lt == ndNETLINK_ATYPE_LOCALNET &&
        ut == ndNETLINK_ATYPE_LOCALNET) {
        lm = LOWER_LOCAL;
        ot = OTHER_LOCAL;
    }
    else if (lt == ndNETLINK_ATYPE_UNKNOWN) {
        lm = LOWER_OTHER;
        ot = OTHER_REMOTE;
    }
    else if (ut == ndNETLINK_ATYPE_UNKNOWN) {
        lm = LOWER_LOCAL;
        ot = OTHER_REMOTE;
    }
#else
    lm = LOWER_UNKNOWN;
    ot = OTHER_UNSUPPORTED;
#endif
}

void ndFlow::json_encode(json &j, uint8_t encode_includes)
{
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
        j["digest"] = digest;
    } else {
        nd_sha1_to_string(digest_lower, digest);
        j["digest"] = digest;
    }

    j["last_seen_at"] = ts_last_seen;

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
        j["ip_nat"] = (bool)flags.ip_nat.load();
        j["dhc_hit"] = (bool)flags.dhc_hit.load();
        j["soft_dissector"] = (bool)flags.soft_dissector.load();
#if defined(_ND_USE_CONNTRACK) && defined(_ND_WITH_CONNTRACK_MDATA)
        j["ct_id"] = ct_id;
        j["ct_mark"] = ct_mark;
#endif
        j["ip_version"] = (unsigned)ip_version;
        j["ip_protocol"] = (unsigned)ip_protocol;
        j["vlan_id"] = (unsigned)vlan_id;
#if defined(_ND_USE_NETLINK) && ! defined(_ND_LEAN_AND_MEAN)
#if 0
        // 10.110.80.1: address is: PRIVATE
        // 67.204.229.236: address is: LOCALIP
        if (ND_DEBUG && _other_type == "unknown") {
            ndNetlink::PrintType(lower_ip, lower_type);
            ndNetlink::PrintType(upper_ip, upper_type);
            //exit(1);
        }
#endif
#endif
        j["other_type"] = _other_type;

        switch (origin) {
        case ORIGIN_UPPER:
            j["local_origin"] =
                (_lower_ip == "local_ip") ? false : true;
            break;
        case ORIGIN_LOWER:
        default:
            j["local_origin"] =
                (_lower_ip == "local_ip") ? true : false;
            break;
        }

        // 00-52-14 to 00-52-FF: Unassigned (small allocations)
        j[_lower_mac] = (privacy_mask & PRIVATE_LOWER) ?
            "00:52:14:00:00:00" : lower_mac.GetString();
        j[_upper_mac] = (privacy_mask & PRIVATE_UPPER) ?
            "00:52:ff:00:00:00" : upper_mac.GetString();

        if (privacy_mask & PRIVATE_LOWER) {
            if (ip_version == 4)
                j[_lower_ip] = ND_PRIVATE_IPV4 "253";
            else
                j[_lower_ip] = ND_PRIVATE_IPV6 "fd";
        }
        else
            j[_lower_ip] = lower_addr.GetString();

        if (privacy_mask & PRIVATE_UPPER) {
            if (ip_version == 4)
                j[_upper_ip] = ND_PRIVATE_IPV4 "254";
            else
                j[_upper_ip] = ND_PRIVATE_IPV6 "fe";
        }
        else
            j[_upper_ip] = upper_addr.GetString();

        j[_lower_port] = (unsigned)lower_addr.GetPort();
        j[_upper_port] = (unsigned)upper_addr.GetPort();

        j["detected_protocol"] = (unsigned)detected_protocol;
        j["detected_protocol_name"] =
            (detected_protocol_name != NULL) ? detected_protocol_name : "Unknown";

        j["detected_application"] = (unsigned)detected_application;
        j["detected_application_name"] =
            (detected_application_name != NULL) ? detected_application_name : "Unknown";

        j["detection_guessed"] = flags.detection_guessed.load();
        j["detection_updated"] = flags.detection_updated.load();

        j["category"]["application"] = category.application;
        j["category"]["protocol"] = category.protocol;
        j["category"]["domain"] = category.domain;

        if (dns_host_name[0] != '\0')
            j["dns_host_name"] = dns_host_name;

        if (host_server_name[0] != '\0')
            j["host_server_name"] = host_server_name;

        if (has_http_user_agent() || has_http_url()) {

            if (has_http_user_agent())
                j["http"]["user_agent"] = http.user_agent;
            if (has_http_url())
                j["http"]["url"] = http.url;
        }

        if (has_dhcp_fingerprint() || has_dhcp_class_ident()) {

            if (has_dhcp_fingerprint())
                j["dhcp"]["fingerprint"] = dhcp.fingerprint;

            if (has_dhcp_class_ident())
                j["dhcp"]["class_ident"] = dhcp.class_ident;
        }

        if (has_ssh_client_agent() || has_ssh_server_agent()) {

            if (has_ssh_client_agent())
                j["ssh"]["client"] = ssh.client_agent;

            if (has_ssh_server_agent())
                j["ssh"]["server"] = ssh.server_agent;
        }

        if (master_protocol() == ND_PROTO_TLS
            || detected_protocol == ND_PROTO_QUIC) {

            char tohex[7];

            sprintf(tohex, "0x%04hx", ssl.version);
            j["ssl"]["version"] = tohex;

            sprintf(tohex, "0x%04hx", ssl.cipher_suite);
            j["ssl"]["cipher_suite"] = tohex;

            if (has_ssl_client_sni())
                j["ssl"]["client_sni"] = ssl.client_sni;

            if (has_ssl_server_cn())
                j["ssl"]["server_cn"] = ssl.server_cn;

            if (has_ssl_issuer_dn())
                j["ssl"]["issuer_dn"] = ssl.issuer_dn;

            if (has_ssl_subject_dn())
                j["ssl"]["subject_dn"] = ssl.subject_dn;

            if (has_ssl_client_ja3())
                j["ssl"]["client_ja3"] = ssl.client_ja3;

            if (has_ssl_server_ja3())
                j["ssl"]["server_ja3"] = ssl.server_ja3;

            if (ssl.cert_fingerprint_found) {
                nd_sha1_to_string((const uint8_t *)ssl.cert_fingerprint, digest);
                j["ssl"]["fingerprint"] = digest;
            }

            j["ssl"]["alpn"] = tls_alpn;
            j["ssl"]["alpn_server"] = tls_alpn_server;
        }

        if (has_bt_info_hash()) {
            nd_sha1_to_string((const uint8_t *)bt.info_hash, digest);
            j["bt"]["info_hash"] = digest;
        }

        if (has_ssdp_headers())
            j["ssdp"] = ssdp.headers;
#if 0
        if (has_mining_variant())
            j["mining"]["variant"] = mining.variant;
#endif
        if (has_mdns_domain_name())
            j["mdns"]["answer"] = mdns.domain_name;

        j["first_seen_at"] = ts_first_seen;
        j["first_update_at"] = ts_first_update;

        j["risks"]["risks"] = risks;
        j["risks"]["ndpi_risk_score"] = ndpi_risk_score;
        j["risks"]["ndpi_risk_score_client"] = ndpi_risk_score_client;
        j["risks"]["ndpi_risk_score_server"] = ndpi_risk_score_server;
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

            j["gtp"]["version"] = gtp.version;
            j["gtp"]["ip_version"] = gtp.ip_version;
            j["gtp"][_lower_ip] = gtp.lower_addr.GetString();
            j["gtp"][_upper_ip] = gtp.upper_addr.GetString();
            j["gtp"][_lower_port] = (unsigned)gtp.lower_addr.GetPort();
            j["gtp"][_upper_port] = (unsigned)gtp.upper_addr.GetPort();
            j["gtp"][_lower_teid] = htonl(gtp.lower_teid);
            j["gtp"][_upper_teid] = htonl(gtp.upper_teid);
            j["gtp"]["other_type"] = _other_type;

            break;
        }
    }

    if (encode_includes & ENCODE_STATS) {
        j[_lower_bytes] = lower_bytes;
        j[_upper_bytes] = upper_bytes;
        j[_lower_packets] = lower_packets;
        j[_upper_packets] = upper_packets;
        j["total_packets"] = total_packets;
        j["total_bytes"] = total_bytes;
        j["detection_packets"] = detection_packets.load();
    }
}

ndFlowTicket::ndFlowTicket(ndFlow *flow)
    : flow(flow)
{
    if (flow != nullptr) flow->tickets++;
}

ndFlowTicket::~ndFlowTicket()
{
    if (flow != nullptr) flow->tickets--;
}

void ndFlowTicket::Take(ndFlow *flow, bool increment)
{
    if (flow != nullptr) {
        if (increment) flow->tickets++;
        if (this->flow != nullptr) this->flow->tickets--;
        this->flow = flow;
    }
    else if(this->flow != nullptr && increment)
        this->flow->tickets++;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
