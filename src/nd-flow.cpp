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
#include "nd-category.h"
#include "nd-protos.h"
#include "nd-flow.h"

// Enable flow hash cache debug logging
//#define _ND_DEBUG_FHC 1

ndFlow::ndFlow(ndInterface &iface)
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
    lower_type(ndAddr::atNONE), upper_type(ndAddr::atNONE),
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
    lower_type(ndAddr::atNONE), upper_type(ndAddr::atNONE),
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
#if 0
// TODO: Move to capture classes...
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
#endif
void ndFlow::reset(bool full_reset)
{
    ts_first_update = 0;
    lower_bytes = upper_bytes = 0;
    lower_packets = upper_packets = 0;

    if (full_reset) {
        detection_packets = 0;

        flags.detection_complete = false;
        flags.detection_guessed = false;
        flags.detection_init = false;
        flags.detection_updated = false;
        flags.dhc_hit = false;
        flags.expired = false;
        flags.expiring = false;
        flags.risk_checked = false;
        flags.soft_dissector = false;

        risks.clear();
    }
}

void ndFlow::release(void)
{
    if (ndpi_flow != NULL) {
        ndpi_free_flow(ndpi_flow);
        ndpi_flow = NULL;
    }

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
    case ND_PROTO_FTPS:
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
    case ND_PROTO_DNS:
    case ND_PROTO_MDNS:
    case ND_PROTO_LLMNR:
        return ND_PROTO_DNS;
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
    string iface_name;
    nd_iface_name(iface.ifname, iface_name);

    const char
        *lower_name = lower_addr.GetString().c_str(),
        *upper_name = upper_addr.GetString().c_str();

    string digest;
    nd_sha1_to_string((const uint8_t *)bt.info_hash, digest);

    nd_flow_printf(
        "%s: [%c%c%c%c%c%c%c%c] %s%s%s %s:%hu %c%c%c %s:%hu%s%s%s%s%s%s%s\n",
        iface_name.c_str(),
        (iface.role == ndIR_LAN) ? 'i' : 'e',
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
    if (ndGC_DEBUG &&
        detected_protocol == ND_PROTO_TLS &&
        flags.detection_guessed.load() == false && ssl.version == 0x0000) {
        nd_dprintf("%s: SSL with no SSL/TLS verison.\n", iface.ifname.c_str());
    }
#endif
}

void ndFlow::update_lower_maps(void)
{
    if (lower_map == LOWER_UNKNOWN)
        get_lower_map(lower_type, upper_type, lower_map, other_type);

    switch (tunnel_type) {
    case TUNNEL_GTP:
        if (gtp.lower_map == LOWER_UNKNOWN) {
            get_lower_map(
                gtp.lower_type, gtp.upper_type, gtp.lower_map, gtp.other_type
            );
        }
    break;
    }
}

void ndFlow::get_lower_map(
    ndAddr::Type lt,
    ndAddr::Type ut,
    uint8_t &lm, uint8_t &ot)
{
#if 0
    nd_dprintf("lower type: %s: %u, upper_type: %s: %u\n",
        lower_addr.GetString().c_str(), lt,
        upper_addr.GetString().c_str(), ut
    );
#endif
    if (lt == ndAddr::atERROR ||
        ut == ndAddr::atERROR) {
        ot = OTHER_ERROR;
    }
    else if (lt == ndAddr::atLOCAL &&
        ut == ndAddr::atLOCAL) {
        lm = LOWER_LOCAL;
        ot = OTHER_LOCAL;
    }
    else if (lt == ndAddr::atLOCAL &&
        ut == ndAddr::atLOCAL) {
        lm = LOWER_LOCAL;
        ot = OTHER_LOCAL;
    }
    else if (lt == ndAddr::atLOCAL &&
        ut == ndAddr::atLOCALNET) {
        lm = LOWER_LOCAL;
        ot = OTHER_LOCAL;
    }
    else if (lt == ndAddr::atLOCALNET &&
        ut == ndAddr::atLOCAL) {
        lm = LOWER_LOCAL;
        ot = OTHER_LOCAL;
    }
    else if (lt == ndAddr::atMULTICAST) {
        lm = LOWER_OTHER;
        ot = OTHER_MULTICAST;
    }
    else if (ut == ndAddr::atMULTICAST) {
        lm = LOWER_LOCAL;
        ot = OTHER_MULTICAST;
    }
    else if (lt == ndAddr::atBROADCAST) {
        lm = LOWER_OTHER;
        ot = OTHER_BROADCAST;
    }
    else if (ut == ndAddr::atBROADCAST) {
        lm = LOWER_LOCAL;
        ot = OTHER_BROADCAST;
    }
    else if (lt == ndAddr::atRESERVED &&
        ut == ndAddr::atLOCALNET) {
        lm = LOWER_OTHER;
        ot = OTHER_LOCAL;
    }
    else if (lt == ndAddr::atLOCALNET &&
        ut == ndAddr::atRESERVED) {
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
        lt == ndAddr::atRESERVED &&
        ut == ndAddr::atRESERVED) {
        lm = LOWER_LOCAL;
        ot = OTHER_LOCAL;
    }
    else if (lt == ndAddr::atRESERVED &&
        ut == ndAddr::atLOCAL) {
        lm = LOWER_OTHER;
        ot = OTHER_REMOTE;
    }
    else if (lt == ndAddr::atLOCAL &&
        ut == ndAddr::atRESERVED) {
        lm = LOWER_LOCAL;
        ot = OTHER_REMOTE;
    }
    else if (lt == ndAddr::atLOCALNET &&
        ut == ndAddr::atLOCALNET) {
        lm = LOWER_LOCAL;
        ot = OTHER_LOCAL;
    }
    else if (lt == ndAddr::atOTHER) {
        lm = LOWER_OTHER;
        ot = OTHER_REMOTE;
    }
    else if (ut == ndAddr::atOTHER) {
        lm = LOWER_LOCAL;
        ot = OTHER_REMOTE;
    }
#if 0
    nd_dprintf("lower map: %u, other type: %u\n", lm, ot);
#endif
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
