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

#include <cerrno>
#include <cstring>
#include <iostream>
#include <map>
#include <queue>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <list>
#include <vector>
#include <set>
#include <atomic>
#include <regex>
#include <algorithm>
#include <mutex>

#ifdef HAVE_ENDIAN_H
#include <endian.h>
#elif HAVE_SYS_ENDIAN_H
 #include <sys/endian.h>
 #if ! defined(__BYTE_ORDER__)
  #define __BYTE_ORDER__ _BYTE_ORDER
 #endif
 #if ! defined(__ORDER_LITTLE_ENDIAN__)
  #define __ORDER_LITTLE_ENDIAN__ _LITTLE_ENDIAN
 #endif
 #if ! defined(__ORDER_BIG_ENDIAN__)
  #define __ORDER_BIG_ENDIAN__ _BIG_ENDIAN
 #endif
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#if HAVE_NET_PPP_DEFS_H
#include <net/ppp_defs.h>
#elif HAVE_LINUX_PPP_DEFS_H
#include <linux/ppp_defs.h>
#else
#error Unable to find a usable ppp_defs include
#endif

#define __FAVOR_BSD 1
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#undef __FAVOR_BSD

#if !defined(ETHERTYPE_MPLS_UC)
 #if defined(ETHERTYPE_MPLS)
  #define ETHERTYPE_MPLS_UC ETHERTYPE_MPLS
 #elif defined(ETH_P_MPLS_UC)
  #define ETHERTYPE_MPLS_UC ETH_P_MPLS_UC
 #else
  #error Unable to find suitable define for ETHERTYPE_MPLS_UC
 #endif
#endif

#if !defined(ETHERTYPE_MPLS_MC)
 #if defined(ETHERTYPE_MPLS_MCAST)
  #define ETHERTYPE_MPLS_MC ETHERTYPE_MPLS_MCAST
 #elif defined(ETH_P_MPLS_MC)
  #define ETHERTYPE_MPLS_MC ETH_P_MPLS_MC
 #else
  #error Unable to find suitable define for ETHERTYPE_MPLS_MC
 #endif
#endif

#if !defined(ETHERTYPE_PPPOE)
 #if defined(ETH_P_PPP_SES)
  #define ETHERTYPE_PPPOE ETH_P_PPP_SES
 #else
  #error Unable to find suitable define for ETHERTYPE_PPPOE
 #endif
#endif

#if !defined(ETHERTYPE_PPPOEDISC)
 #if defined(ETH_P_PPP_DISC)
  #define ETHERTYPE_PPPOEDISC ETH_P_PPP_DISC
 #else
  #error Unable to find suitable define for ETHERTYPE_PPPOEDISC
 #endif
#endif

#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <netdb.h>
#include <resolv.h>
#include <ctype.h>

#include <pcap/pcap.h>
#ifdef HAVE_PCAP_SLL_H
#include <pcap/sll.h>
#else
#include "pcap-compat/sll.h"
#endif
#ifdef HAVE_PCAP_VLAN_H
#include <pcap/vlan.h>
#else
#include "pcap-compat/vlan.h"
#endif

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#ifdef _ND_USE_CONNTRACK
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#endif

#define _ND_PPP_PROTOCOL(p)	((((uint8_t *)(p))[0] << 8) + ((uint8_t *)(p))[1])

#define _ND_GTP_U_PORT    2152
#define _ND_GTP_G_PDU     0xff

using namespace std;

#include "netifyd.h"

#include "nd-config.h"
#include "nd-ndpi.h"
#ifdef _ND_USE_NETLINK
#include "nd-netlink.h"
#endif
#include "nd-packet.h"
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
#include "nd-socket.h"
#include "nd-util.h"
#include "nd-dhc.h"
#include "nd-fhc.h"
#include "nd-signal.h"
#include "nd-detection.h"
#include "nd-capture.h"

// Enable to log discarded packets
//#define _ND_LOG_PKT_DISCARD   1

// Enable to log discarded flows
//#define _ND_LOG_FLOW_DISCARD  1

// Enable DNS response debug logging
//#define _ND_LOG_DNS_RESPONSE  1

// Enable DNS hint cache debug logging
//#define _ND_LOG_DHC           1

// Enable flow hash cache debug logging
//#define _ND_LOG_FHC           1

// Enable GTP tunnel dissection
#define _ND_DISSECT_GTP         1

extern ndGlobalConfig nd_config;
extern ndFlowMap *nd_flow_buckets;

atomic_uint nd_flow_count;

nd_device nd_devices;
nd_interface_addr_map nd_interface_addrs;
nd_interface nd_interfaces;

struct __attribute__((packed)) nd_mpls_header_t
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint32_t ttl:8, s:1, exp:3, label:20;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    uint32_t label:20, exp:3, s:1, ttl:8;
#else
#error Endianess not defined (__BYTE_ORDER__).
#endif
};
#ifdef _ND_DISSECT_GTP
struct __attribute__((packed)) nd_gtpv1_header_t
{
    struct {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        uint8_t npdu_num:1;
        uint8_t seq_num:1;
        uint8_t ext_hdr:1;
        uint8_t reserved:1;
        uint8_t proto_type:1;
        uint8_t version:3;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        uint8_t version:3;
        uint8_t proto_type:1;
        uint8_t reserved:1;
        uint8_t ext_hdr:1;
        uint8_t seq_num:1;
        uint8_t npdu_num:1;
#else
#error Endianess not defined (__BYTE_ORDER__).
#endif
    } flags;

    uint8_t type;
    uint16_t length;
    uint32_t teid;
};

struct __attribute__((packed)) nd_gtpv2_header_t
{
    struct {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        uint8_t reserved:3;
        uint8_t teid:1;
        uint8_t piggyback:1;
        uint8_t version:3;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        uint8_t version:3;
        uint8_t piggyback:1;
        uint8_t teid:1;
        uint8_t reserved:3;
#else
#error Endianess not defined (__BYTE_ORDER__).
#endif
    } flags;

    uint8_t type;
    uint16_t length;
    uint32_t teid;
};
#endif // _ND_DISSECT_GTP

struct __attribute__((packed)) nd_dns_header_t {
    uint16_t tr_id;
    uint16_t flags;
    uint16_t num_queries;
    uint16_t num_answers;
    uint16_t authority_rrs;
    uint16_t additional_rrs;
};

ndCaptureThread::ndCaptureThread(
    nd_capture_type cs_type,
    int16_t cpu,
    nd_interface::iterator iface,
    const uint8_t *dev_mac,
    ndSocketThread *thread_socket,
    const nd_detection_threads &threads_dpi,
    ndDNSHintCache *dhc,
    uint8_t private_addr)
    : ndThread(iface->second, (long)cpu, /* IPC? */ false),
    dl_type(0), cs_type(cs_type),
    iface(iface), thread_socket(thread_socket),
/*    capture_unknown_flows(ND_CAPTURE_UNKNOWN_FLOWS), */
    ts_pkt_first(0), ts_pkt_last(0), dhc(dhc),
    threads_dpi(threads_dpi), dpi_thread_id(rand() % threads_dpi.size())
{
    nd_iface_name(iface->second, tag);

    private_addrs.first.ss_family = AF_INET;
    nd_private_ipaddr(private_addr, private_addrs.first);

    private_addrs.second.ss_family = AF_INET6;
    nd_private_ipaddr(private_addr, private_addrs.second);

    memcpy(this->dev_mac, dev_mac, ETH_ALEN);
    nd_dprintf(
        "%s: hwaddr: %02hhx:%02hhx:%02hhx:%02hhx:%02hx:%02hhx\n",
        tag.c_str(),
        dev_mac[0], dev_mac[1], dev_mac[2],
        dev_mac[3], dev_mac[4], dev_mac[5]
    );
}

const ndPacket *ndCaptureThread::ProcessPacket(const ndPacket *packet)
{
    ndFlow *nf, flow(iface);

    const struct ether_header *hdr_eth = NULL;
    const struct sll_header *hdr_sll = NULL;
    const struct ip *hdr_ip = NULL;
    const struct ip6_hdr *hdr_ip6 = NULL;
    const struct tcphdr *hdr_tcp = NULL;
    const struct udphdr *hdr_udp = NULL;
#ifdef _ND_DISSECT_GTP
    const struct nd_gtpv1_header_t *hdr_gtpv1 = NULL;
    const struct nd_gtpv2_header_t *hdr_gtpv2 = NULL;
#endif
    const uint8_t *l3 = NULL, *l4 = NULL, *pkt = NULL;
    uint16_t l2_len, l3_len, l4_len = 0, pkt_len = 0;
    uint16_t type = 0;
    uint16_t ppp_proto;
    uint16_t frag_off = 0;
    uint8_t vlan_packet = 0;
    int addr_cmp = 0;

    uint64_t ts_pkt = ((uint64_t)packet->tv_sec) *
            ND_DETECTION_TICKS +
            packet->tv_usec /
            (1000000 / ND_DETECTION_TICKS);
#if 0
    if (pcap_file.size()) {
        if (ts_pkt_first == 0)
            ts_pkt_first = ts_pkt;

        ts_pkt = (ts_pkt - ts_pkt_first) + (tv_epoch * 1000);

        if (ts_pkt_last > ts_pkt) ts_pkt = ts_pkt_last;

        if (ND_REPLAY_DELAY && ts_pkt_last) {
            useconds_t delay = useconds_t(ts_pkt - ts_pkt_last) * 1000;
            //nd_dprintf("%s: pkt delay: %lu\n", tag.c_str(), delay);
            if (delay) {
                pthread_mutex_unlock(&lock);
                usleep(delay);
                pthread_mutex_lock(&lock);
            }
        }
    }
    else
#endif
        if (ts_pkt_last > ts_pkt) ts_pkt = ts_pkt_last;

    ts_pkt_last = ts_pkt;

    stats.pkt.raw++;
    if (packet->length > stats.pkt.maxlen)
        stats.pkt.maxlen = packet->length;

    switch (dl_type) {
    case DLT_NULL:
        if (packet->caplen < sizeof(uint32_t)) {
            stats.pkt.discard++;
            stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
            nd_dprintf("%s: discard: Truncated packet.", tag.c_str());
#endif
            return packet;
        }

        switch (ntohl(*((uint32_t *)packet->data))) {
        case 2:
            type = ETHERTYPE_IP;
            break;
        case 24:
        case 28:
        case 30:
            type = ETHERTYPE_IPV6;
            break;
        default:
#ifdef _ND_LOG_PKT_DISCARD
        stats.pkt.discard++;
        stats.pkt.discard_bytes += packet->length;
        nd_dprintf("%s: discard: Unsupported BSD loopback encapsulation type: %lu\n",
            tag.c_str(), ntohl(*((uint32_t *)packet->data)));
#endif
            return packet;
        }

        l2_len = 4;
        break;

    case DLT_EN10MB:
        if (packet->caplen < sizeof(struct ether_header)) {
            stats.pkt.discard++;
            stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
            nd_dprintf("%s: discard: Truncated packet.", tag.c_str());
#endif
            return packet;
        }

        hdr_eth = reinterpret_cast<const struct ether_header *>(packet->data);
        type = ntohs(hdr_eth->ether_type);
        l2_len = sizeof(struct ether_header);
        stats.pkt.eth++;

        // STP?
        if ((hdr_eth->ether_shost[0] == 0x01 && hdr_eth->ether_shost[1] == 0x80 &&
            hdr_eth->ether_shost[2] == 0xC2) ||
            (hdr_eth->ether_dhost[0] == 0x01 && hdr_eth->ether_dhost[1] == 0x80 &&
            hdr_eth->ether_dhost[2] == 0xC2)) {
            stats.pkt.discard++;
            stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
            nd_dprintf("%s: discard: STP protocol.\n", tag.c_str());
#endif
            return packet;
        }

        break;

    case DLT_LINUX_SLL:
        if (packet->caplen < sizeof(struct sll_header)) {
            stats.pkt.discard++;
            stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
            nd_dprintf("%s: discard: Truncated packet.", tag.c_str());
#endif
            return packet;
        }

        hdr_sll = reinterpret_cast<const struct sll_header *>(packet->data);
        type = hdr_sll->sll_protocol;
        l2_len = SLL_HDR_LEN;
        break;

    case DLT_RAW:
    case DLT_IPV4:
    case DLT_IPV6:
        l2_len = 0;
        // type will be set to ETHERTYPE_IP/V6 below...
        break;

    default:
        stats.pkt.discard++;
        stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
        nd_dprintf("%s: discard: Unsupported datalink type: 0x%x\n",
            tag.c_str(), (unsigned)dl_type);
#endif
        return packet;
    }

    if (l2_len > packet->caplen) {
        stats.pkt.discard++;
        stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
        nd_dprintf("%s: discard: layer-2 length is beyond capture length.\n",
            tag.c_str());
#endif
    }

    while (true) {
        if (type == ETHERTYPE_VLAN) {
            if (l2_len + 4 > packet->caplen) {
                stats.pkt.discard++;
                stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
                nd_dprintf("%s: discard: layer-2 + VLAN length is beyond capture length.\n",
                    tag.c_str());
#endif
            }

            // TODO: Replace with struct vlan_tag from <pcap/vlan.h>
            // See: https://en.wikipedia.org/wiki/IEEE_802.1Q
            vlan_packet = 1;
            flow.vlan_id = ((packet->data[l2_len] << 8) + packet->data[l2_len + 1]) & 0xFFF;
            type = (packet->data[l2_len + 2] << 8) + packet->data[l2_len + 3];
            l2_len += VLAN_TAG_LEN;
        }
        else if (type == ETHERTYPE_MPLS_UC || type == ETHERTYPE_MPLS_MC) {
            stats.pkt.mpls++;
            union mpls {
                uint32_t u32;
                struct nd_mpls_header_t mpls;
            } mpls;
            mpls.u32 = ntohl(*((uint32_t *)&packet->data[l2_len]));
            type = ETHERTYPE_IP;
            l2_len += 4;

            if (l2_len > packet->caplen) {
                stats.pkt.discard++;
                stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
                nd_dprintf("%s: discard: layer-2 + MPLS length is beyond capture length.\n",
                    tag.c_str());
#endif
            }

            while (! mpls.mpls.s) {
                l2_len += 4;

                if (l2_len > packet->caplen) {
                    stats.pkt.discard++;
                    stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
                    nd_dprintf("%s: discard: layer-2 + MPLS length is beyond capture length.\n",
                        tag.c_str());
#endif
                }
                mpls.u32 = ntohl(*((uint32_t *)&packet->data[l2_len]));
            }
        }
        else if (type == ETHERTYPE_PPPOE) {
            stats.pkt.pppoe++;
            type = ETHERTYPE_IP;

            if (l2_len + 6 > packet->caplen) {
                stats.pkt.discard++;
                stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
                nd_dprintf("%s: discard: layer-2 + PPP length is beyond capture length.\n",
                    tag.c_str());
#endif
            }

            ppp_proto = (uint16_t)(
                _ND_PPP_PROTOCOL(packet->data + l2_len + 6)
            );
            if (ppp_proto != PPP_IP && ppp_proto != PPP_IPV6) {
                stats.pkt.discard++;
                stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
                nd_dprintf("%s: discard: unsupported PPP protocol: 0x%04hx\n",
                    tag.c_str(), ppp_proto);
#endif
                return packet;
            }

            l2_len += 8;

            if (l2_len > packet->caplen) {
                stats.pkt.discard++;
                stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
                nd_dprintf("%s: discard: layer-2 + PPP length is beyond capture length.\n",
                    tag.c_str());
#endif
            }
        }
        else if (type == ETHERTYPE_PPPOEDISC) {
            stats.pkt.pppoe++;
            stats.pkt.discard++;
            stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
            nd_dprintf("%s: discard: PPPoE discovery protocol.\n", tag.c_str());
#endif
            return packet;
        }
        else
            break;
    }

    stats.pkt.vlan += vlan_packet;

nd_process_ip:
    if (l2_len + sizeof(struct ip) > packet->caplen) {
        stats.pkt.discard++;
        stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
        nd_dprintf("%s: discard: layer-2 + IP length is beyond capture length.\n",
            tag.c_str());
#endif
    }

    hdr_ip = reinterpret_cast<const struct ip *>(&packet->data[l2_len]);

    flow.ip_version = hdr_ip->ip_v;

    if (flow.ip_version == 4) {

        if (type == 0) type = ETHERTYPE_IP;

        l3_len = ((uint16_t)hdr_ip->ip_hl * 4);
        l4_len = ntohs(hdr_ip->ip_len) - l3_len;
        flow.ip_protocol = hdr_ip->ip_p;
        flow.lower_addr.ss_family = AF_INET;
        flow.upper_addr.ss_family = AF_INET;
        l3 = reinterpret_cast<const uint8_t *>(hdr_ip);

        if (packet->caplen >= l2_len)
            frag_off = ntohs(hdr_ip->ip_off);

        if (packet->caplen - l2_len < sizeof(struct ip)) {
            // XXX: header too small
            stats.pkt.discard++;
            stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
            nd_dprintf("%s: discard: header too small\n", tag.c_str());
#endif
            return packet;
        }

        if ((frag_off & 0x3FFF) != 0) {
            // XXX: fragmented packets are not supported
            stats.pkt.frags++;
            stats.pkt.discard++;
            stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
            nd_dprintf("%s: discard: fragmented 0x3FFF\n", tag.c_str());
#endif
            return packet;
        }

        if ((frag_off & 0x1FFF) != 0) {
            // XXX: fragmented packets are not supported
            stats.pkt.frags++;
            stats.pkt.discard++;
            stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
            nd_dprintf("%s: discard: fragmented 0x1FFF\n", tag.c_str());
#endif
            return packet;
        }

        if (l3_len > (packet->caplen - l2_len)) {
            stats.pkt.discard++;
            stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
            nd_dprintf("%s: discard: l3_len[%hu] > (packet->caplen[%hu] - l2_len[%hu])(%hu)\n",
                tag.c_str(), l3_len, packet->caplen, l2_len, packet->caplen - l2_len);
#endif
            return packet;
        }

        addr_cmp = memcmp(&hdr_ip->ip_src, &hdr_ip->ip_dst, 4);

        if (addr_cmp < 0) {
            flow.lower_addr4->sin_addr.s_addr = hdr_ip->ip_src.s_addr;
            flow.upper_addr4->sin_addr.s_addr = hdr_ip->ip_dst.s_addr;
            if (dl_type == DLT_EN10MB) {
                memcpy(flow.lower_mac, hdr_eth->ether_shost, ETH_ALEN);
                memcpy(flow.upper_mac, hdr_eth->ether_dhost, ETH_ALEN);
            }
        }
        else {
            flow.lower_addr4->sin_addr.s_addr = hdr_ip->ip_dst.s_addr;
            flow.upper_addr4->sin_addr.s_addr = hdr_ip->ip_src.s_addr;
            if (dl_type == DLT_EN10MB) {
                memcpy(flow.lower_mac, hdr_eth->ether_dhost, ETH_ALEN);
                memcpy(flow.upper_mac, hdr_eth->ether_shost, ETH_ALEN);
            }
        }

        l4 = reinterpret_cast<const uint8_t *>(l3 + l3_len);
    }
    else if (flow.ip_version == 6) {

        if (type == 0) type = ETHERTYPE_IPV6;

        hdr_ip6 = reinterpret_cast<const struct ip6_hdr *>(&packet->data[l2_len]);

        l3 = reinterpret_cast<const uint8_t *>(hdr_ip6);
        l3_len = sizeof(struct ip6_hdr);
        l4 = reinterpret_cast<const uint8_t *>(l3 + l3_len);
        l4_len = ntohs(hdr_ip6->ip6_ctlun.ip6_un1.ip6_un1_plen);
        flow.ip_protocol = hdr_ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;

        if (ndpi_handle_ipv6_extension_headers(l3_len, &l4, &l4_len, &flow.ip_protocol)) {
            stats.pkt.discard++;
            stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
            nd_dprintf("%s: discard: Error walking IPv6 extensions.\n", tag.c_str());
#endif
            return packet;
        }

        flow.lower_addr.ss_family = AF_INET6;
        flow.upper_addr.ss_family = AF_INET6;

        int i = 0;
        if (memcmp(&hdr_ip6->ip6_src, &hdr_ip6->ip6_dst, sizeof(struct in6_addr))) {
            do {
                addr_cmp = memcmp(
                    &hdr_ip6->ip6_src.s6_addr32[i],
                    &hdr_ip6->ip6_dst.s6_addr32[i], 4);
                i++;
            }
            while (addr_cmp == 0);
        }

        if (addr_cmp < 0) {
            memcpy(&flow.lower_addr6->sin6_addr, &hdr_ip6->ip6_src, sizeof(struct in6_addr));
            memcpy(&flow.upper_addr6->sin6_addr, &hdr_ip6->ip6_dst, sizeof(struct in6_addr));
            if (dl_type == DLT_EN10MB) {
                memcpy(flow.lower_mac, hdr_eth->ether_shost, ETH_ALEN);
                memcpy(flow.upper_mac, hdr_eth->ether_dhost, ETH_ALEN);
            }
        }
        else {
            memcpy(&flow.lower_addr6->sin6_addr, &hdr_ip6->ip6_dst, sizeof(struct in6_addr));
            memcpy(&flow.upper_addr6->sin6_addr, &hdr_ip6->ip6_src, sizeof(struct in6_addr));
            if (dl_type == DLT_EN10MB) {
                memcpy(flow.lower_mac, hdr_eth->ether_dhost, ETH_ALEN);
                memcpy(flow.upper_mac, hdr_eth->ether_shost, ETH_ALEN);
            }
        }
    }
    else {
        // XXX: Warning: unsupported IP protocol version (IPv4/6 only)
        stats.pkt.discard++;
        stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
        nd_dprintf("%s: discard: invalid IP protocol version: %hhx\n",
            tag.c_str(), packet->data[l2_len]);
#endif
        return packet;
    }

    if (l2_len + l3_len + l4_len > packet->caplen) {
        stats.pkt.discard++;
        stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
        nd_dprintf("%s: discard: L2 + L3 + L4 length is beyond capture length.\n",
            tag.c_str());
#endif
        return packet;
    }

#if _ND_DISSECT_GTP
    if (l4_len > 8 && flow.ip_protocol == IPPROTO_UDP) {
        hdr_udp = reinterpret_cast<const struct udphdr *>(l4);

        if (ntohs(hdr_udp->uh_sport) == _ND_GTP_U_PORT ||
            ntohs(hdr_udp->uh_dport) == _ND_GTP_U_PORT) {

            hdr_gtpv1 = reinterpret_cast<const struct nd_gtpv1_header_t *>(
                l4 + sizeof(struct udphdr)
            );

            if (hdr_gtpv1->flags.version == 1) {

                if (flow.tunnel_type == ndFlow::TUNNEL_NONE) {
                    flow.tunnel_type = ndFlow::TUNNEL_GTP;

                    flow.gtp.version = hdr_gtpv1->flags.version;
                    memcpy(&flow.gtp.lower_addr,
                        &flow.lower_addr, sizeof(struct sockaddr_storage));
                    memcpy(&flow.gtp.upper_addr,
                        &flow.upper_addr, sizeof(struct sockaddr_storage));

                    struct sockaddr_in *laddr4 = flow.lower_addr4;
                    struct sockaddr_in6 *laddr6 = flow.lower_addr6;
                    struct sockaddr_in *uaddr4 = flow.upper_addr4;
                    struct sockaddr_in6 *uaddr6 = flow.upper_addr6;

                    flow.gtp.ip_version = flow.ip_version;

                    switch (flow.ip_version) {
                    case 4:
                        inet_ntop(AF_INET, &laddr4->sin_addr.s_addr,
                            flow.gtp.lower_ip, INET_ADDRSTRLEN);
                        inet_ntop(AF_INET, &uaddr4->sin_addr.s_addr,
                            flow.gtp.upper_ip, INET_ADDRSTRLEN);
                        break;

                    case 6:
                        inet_ntop(AF_INET6, &laddr6->sin6_addr.s6_addr,
                            flow.gtp.lower_ip, INET6_ADDRSTRLEN);
                        inet_ntop(AF_INET6, &uaddr6->sin6_addr.s6_addr,
                            flow.gtp.upper_ip, INET6_ADDRSTRLEN);
                        break;

                    default:
                        nd_printf("%s: ERROR: Unknown GTP IP version: %d\n",
                            tag.c_str(), flow.ip_version);
                        throw ndCaptureThreadException(strerror(EINVAL));
                    }

                    if (addr_cmp < 0) {
                        flow.gtp.lower_port = hdr_udp->uh_sport;
                        flow.gtp.upper_port = hdr_udp->uh_dport;
                    }
                    else if (addr_cmp > 0) {
                        flow.gtp.lower_port = hdr_udp->uh_dport;
                        flow.gtp.upper_port = hdr_udp->uh_sport;
                    }
                    else {
                        if (hdr_udp->uh_sport < hdr_udp->uh_dport) {
                            flow.gtp.lower_port = hdr_udp->uh_sport;
                            flow.gtp.upper_port = hdr_udp->uh_dport;
                        }
                        else {
                            flow.gtp.lower_port = hdr_udp->uh_dport;
                            flow.gtp.upper_port = hdr_udp->uh_sport;
                        }
                    }
                }

                if (hdr_gtpv1->type == _ND_GTP_G_PDU) {

                    l2_len = (l4 - packet->data) + sizeof(struct udphdr) + 8;

                    if (hdr_gtpv1->flags.ext_hdr) l2_len += 1;
                    if (hdr_gtpv1->flags.seq_num) l2_len += 4;
                    if (hdr_gtpv1->flags.npdu_num) l2_len += 1;

                    goto nd_process_ip;
                }
#if 0
                else {
                    nd_dprintf("%s: unsupported GTPv1 message type: 0x%hhx (%hhu)\n",
                        tag.c_str(), hdr_gtpv1->type, hdr_gtpv1->type);
                }
#endif
            }
            else if (hdr_gtpv1->flags.version == 2) {
                // TODO: GTPv2...
                hdr_gtpv2 = reinterpret_cast<const struct nd_gtpv2_header_t *>(
                    l4 + sizeof(struct udphdr)
                );
                nd_dprintf("%s: unimplemented GTP version (TODO): %u\n",
                    tag.c_str(), hdr_gtpv1->flags.version);
            }
            else {
                nd_dprintf("%s: unsupported GTP version: %u\n",
                    tag.c_str(), hdr_gtpv1->flags.version);
            }
        }
    }
#endif
    switch (flow.ip_protocol) {
    case IPPROTO_TCP:
        stats.pkt.tcp++;

        if (l4_len < 20) {
            stats.pkt.discard++;
            stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
            nd_dprintf("%s: discard: TCP header too small.\n",
                tag.c_str());
#endif
            return packet;
        }
        else {
            hdr_tcp = reinterpret_cast<const struct tcphdr *>(l4);

            uint16_t hdr_size = hdr_tcp->th_off * 4;

            if (hdr_size < 20 || hdr_size > l4_len) {
                stats.pkt.discard++;
                stats.pkt.discard_bytes += packet->length;
    #ifdef _ND_LOG_PKT_DISCARD
                nd_dprintf("%s: discard: unexpected TCP payload length.\n",
                    tag.c_str());
    #endif
                return packet;
            }

            if (addr_cmp < 0) {
                flow.lower_port = hdr_tcp->th_sport;
                flow.upper_port = hdr_tcp->th_dport;
            }
            else if (addr_cmp > 0) {
                flow.lower_port = hdr_tcp->th_dport;
                flow.upper_port = hdr_tcp->th_sport;
            }
            else {
                if (hdr_tcp->th_sport < hdr_tcp->th_dport) {
                    flow.lower_port = hdr_tcp->th_sport;
                    flow.upper_port = hdr_tcp->th_dport;
                }
                else {
                    flow.lower_port = hdr_tcp->th_dport;
                    flow.upper_port = hdr_tcp->th_sport;
                }
            }

            pkt = reinterpret_cast<const uint8_t *>(l4 + (hdr_tcp->th_off * 4));
            pkt_len = l4_len - hdr_size;
        }

        break;

    case IPPROTO_UDP:
        stats.pkt.udp++;

        if (l4_len < 8) {
            stats.pkt.discard++;
            stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
            nd_dprintf("%s: discard: UDP header too small.\n",
                tag.c_str());
#endif
            return packet;
        }

        hdr_udp = reinterpret_cast<const struct udphdr *>(l4);

        if (addr_cmp < 0) {
            flow.lower_port = hdr_udp->uh_sport;
            flow.upper_port = hdr_udp->uh_dport;
        }
        else if (addr_cmp > 0) {
            flow.lower_port = hdr_udp->uh_dport;
            flow.upper_port = hdr_udp->uh_sport;
        }
        else {
            if (hdr_udp->uh_sport < hdr_udp->uh_dport) {
                flow.lower_port = hdr_udp->uh_sport;
                flow.upper_port = hdr_udp->uh_dport;
            }
            else {
                flow.lower_port = hdr_udp->uh_dport;
                flow.upper_port = hdr_udp->uh_sport;
            }
        }

        if (ntohs(hdr_udp->uh_ulen) != l4_len) {
            stats.pkt.discard++;
            stats.pkt.discard_bytes += packet->length;
#ifdef _ND_LOG_PKT_DISCARD
            nd_dprintf("%s: discard: unexpected UDP data length.\n",
                tag.c_str());
#endif
            return packet;
        }

        pkt = reinterpret_cast<const uint8_t *>(l4 + sizeof(struct udphdr));
        pkt_len = ntohs(hdr_udp->uh_ulen) - sizeof(struct udphdr);

        break;

    case IPPROTO_ICMP:
    case IPPROTO_ICMPV6:
        stats.pkt.icmp++;
        break;

    case IPPROTO_IGMP:
        stats.pkt.igmp++;
        break;

    default:
        // Non-TCP/UDP protocols, ex: ICMP...
        //nd_dprintf("%s: non TCP/UDP protocol: %d\n", tag.c_str(), flow.ip_protocol);
        break;
    }

    flow.hash(tag);
    flow_digest.assign((const char *)flow.digest_lower, SHA1_DIGEST_LENGTH);

    nf = nd_flow_buckets->Lookup(flow_digest);

    if (nf != NULL) {
        // Flow exists in map.

        if (addr_cmp != nf->direction) {
#if _ND_DISSECT_GTP
            if (hdr_gtpv1 != NULL && hdr_gtpv1->flags.version == 1) {
                if (nf->tunnel_type == ndFlow::TUNNEL_GTP) {
                    switch (nf->origin) {
                    case ndFlow::ORIGIN_LOWER:
                        if (nf->gtp.upper_teid == 0)
                            nf->gtp.upper_teid = hdr_gtpv1->teid;
                        else if (hdr_gtpv1->teid != nf->gtp.upper_teid)
                            nf->gtp.upper_teid = hdr_gtpv1->teid;
                        break;
                    case ndFlow::ORIGIN_UPPER:
                        if (nf->gtp.lower_teid == 0)
                            nf->gtp.lower_teid = hdr_gtpv1->teid;
                        else if (hdr_gtpv1->teid != nf->gtp.lower_teid)
                            nf->gtp.lower_teid = hdr_gtpv1->teid;
                        break;
                    }
                }
            }
            else if (hdr_gtpv2 != NULL && hdr_gtpv2->flags.version == 2) {
                // TODO: Implemented GTPv2.
            }
#endif
        }
    }
    else {
        if (nd_config.max_flows > 0 && nd_flow_count + 1 > nd_config.max_flows) {
            stats.pkt.discard++;
            stats.pkt.discard_bytes += packet->length;
            stats.flow.dropped++;
#ifdef _ND_LOG_FLOW_DISCARD
            nd_dprintf("%s: discard: maximum flows exceeded: %u\n",
                tag.c_str(), nd_config.max_flows);
#endif
            return packet;
        }

        nf = new ndFlow(flow);
        if (nf == NULL) throw ndCaptureThreadException(strerror(ENOMEM));

        nf->direction = addr_cmp;

        if (nd_flow_buckets->Insert(flow_digest, nf) != NULL) {
            // Flow exists in map!  Impossible!
            throw ndCaptureThreadException(strerror(EINVAL));
        }

        nd_flow_count++;

        // New flow inserted, initialize...
        nf->ts_first_seen = ts_pkt;

        // Set initial flow origin:
        // XXX: A 50-50 guess based on which side we saw first.
        if (addr_cmp < 0)
            nf->origin = ndFlow::ORIGIN_LOWER;
        else
            nf->origin = ndFlow::ORIGIN_UPPER;

        // Refine according to the lowest port address
        // XXX: The lowest port is likely the destination.
        switch (nf->ip_protocol) {
        case IPPROTO_TCP:
        case IPPROTO_SCTP:
        case IPPROTO_UDP:
        case IPPROTO_UDPLITE:
            if (ntohs(nf->lower_port) < ntohs(nf->upper_port))
                nf->origin = ndFlow::ORIGIN_UPPER;
            else if (ntohs(nf->lower_port) > ntohs(nf->upper_port))
                nf->origin = ndFlow::ORIGIN_LOWER;
            break;
        }

        // Try to refine flow origin for TCP flows using SYN/ACK flags
        if (nf->ip_protocol == IPPROTO_TCP) {

            if ((hdr_tcp->th_flags & TH_SYN)) {

                if (! (hdr_tcp->th_flags & TH_ACK)) {
                    if (addr_cmp < 0)
                        nf->origin = ndFlow::ORIGIN_LOWER;
                    else
                        nf->origin = ndFlow::ORIGIN_UPPER;
                }
                else {
                    if (addr_cmp < 0)
                        nf->origin = ndFlow::ORIGIN_UPPER;
                    else
                        nf->origin = ndFlow::ORIGIN_LOWER;
                }
            }
        }

        if (nf->tunnel_type == ndFlow::TUNNEL_GTP) {
            switch (nf->origin) {
            case ndFlow::ORIGIN_LOWER:
                nf->gtp.lower_teid = hdr_gtpv1->teid;
                break;
            case ndFlow::ORIGIN_UPPER:
                nf->gtp.upper_teid = hdr_gtpv1->teid;
                break;
            }
        }
    }

    stats.pkt.wire_bytes += packet->length + 24;

    stats.pkt.ip++;
    stats.pkt.ip_bytes += packet->length;

    if (nf->ip_version == 4) {
        stats.pkt.ip4++;
        stats.pkt.ip4_bytes += packet->length;
    }
    else {
        stats.pkt.ip6++;
        stats.pkt.ip6_bytes += packet->length;
    }

    nf->total_packets++;
    nf->total_bytes += packet->length;

    if (addr_cmp < 0) {
        nf->lower_packets++;
        nf->lower_bytes += packet->length;
    }
    else {
        nf->upper_packets++;
        nf->upper_bytes += packet->length;
    }

    nf->ts_last_seen = ts_pkt;
    if (! nf->ts_first_update)
        nf->ts_first_update = ts_pkt;

    if (nf->ip_protocol == IPPROTO_TCP) {
        if (hdr_tcp->th_seq <= nf->tcp_last_seq) {
            stats.pkt.tcp_seq_error++;
            nf->tcp_last_seq = hdr_tcp->th_seq;
        }

        if (hdr_tcp->th_flags & TH_FIN) nf->flags.tcp_fin = true;
        if (hdr_tcp->th_flags & TH_RST) stats.pkt.tcp_resets++;
    }

    if (dhc != NULL && pkt != NULL && pkt_len > sizeof(struct nd_dns_header_t)) {
        uint16_t lport = ntohs(nf->lower_port), uport = ntohs(nf->upper_port);

        if (lport == 53 || uport == 53 || lport == 5355 || uport == 5355) {

            const char *host = NULL;
            bool is_query = ProcessDNSPacket(packet, &host);
#if 0
            if (is_query) {
                // Rehash M/DNS flows:
                // This is done to uniquely track queries that originate from
                // the same local port.  Some devices re-use their local port
                // which would cause additional queries to not be processed.
                // Rehashing using the host_server_name as an additional key
                // guarantees that we see all DNS queries/responses.

//                if (ndpi_proto == NDPI_PROTOCOL_DNS) {
                    nf->hash(tag, false,
                        (const uint8_t *)host,
                        strnlen(host, ND_MAX_HOSTNAME));
//                }
//                else {
//                    nf->hash(tag, false,
//                        (const uint8_t *)nf->mdns.answer,
//                        strnlen(nf->mdns.answer, ND_FLOW_MDNS_ANSLEN));
//                }

                if (memcmp(nf->digest_mdata, nf->digest_lower, SHA1_DIGEST_LENGTH)) {
                    flows->erase(fi.first);

                    memcpy(nf->digest_mdata, nf->digest_lower,
                        SHA1_DIGEST_LENGTH);
                    flow_digest.assign((const char *)nf->digest_lower,
                        SHA1_DIGEST_LENGTH);

                    fi = flows->insert(nd_flow_pair(flow_digest, nf));

                if (! fi.second) {
                    // Flow exists...  update stats and return.
                    *fi.first->second += *nf;

                    nd_dprintf("%s: delete rehashed DNS flow: %lu packets, detection complete: %s\n",
                        tag.c_str(), nf->total_packets, (nf->flags.detection_complete.load()) ? "yes" : "no");
                    delete nf;

                    return packet;
                }
            }
#else
            if (is_query && nf->flags.detection_complete.load()) {
                nf->flags.dhc_hit = false;
                nf->flags.detection_complete = false;
                nf->lower_bytes = flow.lower_bytes;
                nf->upper_bytes = flow.upper_bytes;
                nf->lower_packets = flow.lower_packets;
                nf->upper_packets = flow.upper_packets;
                nf->total_packets = flow.total_packets;
                nf->detection_packets = 0;
            }
#endif
        }
    }

    if (nf->flags.detection_complete.load() == false &&
        nf->flags.detection_expired.load() == false &&
        nf->detection_packets <= nd_config.max_detection_pkts &&
        nf->queued.load() <= nd_config.max_detection_pkts) {

        if (nf->dpi_thread_id < 0) {
            nf->dpi_thread_id = dpi_thread_id;
            if (++dpi_thread_id == (int16_t)threads_dpi.size()) dpi_thread_id = 0;
        }

        nd_detection_threads::const_iterator idpi = threads_dpi.find(nf->dpi_thread_id);

        if (idpi != threads_dpi.end()) {
            idpi->second->QueuePacket(nf, packet, addr_cmp,
                (nf->ip_version == 4) ?
                    (uint8_t *)hdr_ip : (uint8_t *)hdr_ip6,
                packet->caplen - l2_len
            );

            // Hand over ownership to the DPI packet queue
            packet = NULL;
        }
        else {
            nd_dprintf("ERROR: CPU thread ID not found: %hd\n", nf->dpi_thread_id);
            throw ndCaptureThreadException("CPU thread ID not found!");
        }
    }

//    if (capture_unknown_flows) nf->push(pkt_header, packet->data);

    return packet;
}

bool ndCaptureThread::ProcessDNSPacket(const ndPacket *packet, const char **host)
{
    ns_rr rr;
    int rc = ns_initparse(packet->data, packet->caplen, &ns_h);

    *host = NULL;

    if (rc < 0) {
#ifdef _ND_LOG_DHC
        nd_dprintf(
            "%s: dns initparse error: %s, length: %hu\n",
            tag.c_str(), strerror(errno), packet->caplen);
#endif
        return false;
    }

    if (ns_msg_getflag(ns_h, ns_f_rcode) != ns_r_noerror) {
#ifdef _ND_LOG_DHC
        nd_dprintf(
            "%s: dns response code: %hu\n", tag.c_str(),
            ns_msg_getflag(ns_h, ns_f_rcode));
#endif
        return false;
    }

#ifdef _ND_LOG_DHC
    nd_dprintf(
        "%s: type: %d, dns queries: %hu, answers: %hu\n",
        tag.c_str(), ns_msg_getflag(ns_h, ns_f_qr),
        ns_msg_count(ns_h, ns_s_qd), ns_msg_count(ns_h, ns_s_an));
#endif

    for (uint16_t i = 0; i < ns_msg_count(ns_h, ns_s_qd); i++) {
        if (ns_parserr(&ns_h, ns_s_qd, i, &rr)) {
#ifdef _ND_LOG_DHC
            nd_dprintf(
                "%s: dns error parsing QD RR %hu of %hu.\n", tag.c_str(),
                i + 1, ns_msg_count(ns_h, ns_s_qd));
#endif
            continue;
        }

#ifdef _ND_LOG_DHC
        if (ns_rr_type(rr) != ns_t_a && ns_rr_type(rr) != ns_t_aaaa) {
            nd_dprintf("%s: Skipping QD RR type: %d\n",
                tag.c_str(), ns_rr_type(rr));
            continue;
        }
#endif
#ifdef _ND_LOG_DHC
        nd_dprintf("%s: QD RR type: %d, name: %s\n",
            tag.c_str(), ns_rr_type(rr), ns_rr_name(rr));
#endif
        *host = ns_rr_name(rr);
        break;
    }

    // Is query?
    if (*host != NULL && ns_msg_getflag(ns_h, ns_f_qr) == 0)
        return true;

    // If host wasn't found or this isn't a response, return.
    if (*host == NULL || ns_msg_getflag(ns_h, ns_f_qr) != 1)
        return false;

    // Add responses to DHC...
    for (uint16_t i = 0; i < ns_msg_count(ns_h, ns_s_an); i++) {
        if (ns_parserr(&ns_h, ns_s_an, i, &rr)) {
#ifdef _ND_LOG_DHC
            nd_dprintf(
                "%s: dns error parsing AN RR %hu of %hu.\n", tag.c_str(),
                i + 1, ns_msg_count(ns_h, ns_s_an));
#endif
            continue;
        }
#ifdef _ND_LOG_DHC
        nd_dprintf("%s: AN RR type: %d\n", tag.c_str(), ns_rr_type(rr));
#endif
        if (ns_rr_type(rr) != ns_t_a && ns_rr_type(rr) != ns_t_aaaa)
            continue;

        dhc->insert(
            (ns_rr_type(rr) == ns_t_a) ? AF_INET : AF_INET6,
            ns_rr_rdata(rr), *host
        );
#ifdef _ND_LOG_DHC
        char addr[INET6_ADDRSTRLEN];
        struct in_addr addr4;
        struct in6_addr addr6;

        if (ns_rr_type(rr) == ns_t_a) {
            memcpy(&addr4, ns_rr_rdata(rr), sizeof(struct in_addr));
            inet_ntop(AF_INET, &addr4, addr, INET_ADDRSTRLEN);
        }
        else {
            memcpy(&addr6, ns_rr_rdata(rr), sizeof(struct in6_addr));
            inet_ntop(AF_INET6, &addr6, addr, INET6_ADDRSTRLEN);
        }

        nd_dprintf(
            "%s: dns RR %s address: %s, ttl: %u, rlen: %hu: %s\n",
            tag.c_str(), *host,
            (ns_rr_type(rr) == ns_t_a) ? "A" : "AAAA",
            ns_rr_ttl(rr), ns_rr_rdlen(rr), addr);
#endif // _ND_LOG_DHC
    }

    return false;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
