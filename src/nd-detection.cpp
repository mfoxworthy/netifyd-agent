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
#include <atomic>
#include <regex>
#include <algorithm>
#include <mutex>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#define __FAVOR_BSD 1
#include <netinet/in.h>
#include <netinet/tcp.h>
#undef __FAVOR_BSD

#include <arpa/inet.h>

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

using namespace std;

#include "netifyd.h"

#include "nd-ndpi.h"
#ifdef _ND_USE_NETLINK
#include "nd-netlink.h"
#endif
#include "nd-json.h"
#include "nd-apps.h"
#include "nd-protos.h"
#include "nd-flow.h"
#include "nd-flow-map.h"
#include "nd-thread.h"
#ifdef _ND_USE_CONNTRACK
#include "nd-conntrack.h"
#endif
#include "nd-socket.h"
#include "nd-util.h"
#include "nd-fhc.h"
#include "nd-dhc.h"
#include "nd-signal.h"
#include "nd-plugin.h"
#include "nd-detection.h"
#include "nd-tls-alpn.h"

// Enable flow hash cache debug logging
//#define _ND_LOG_FHC             1

extern nd_global_config nd_config;
extern ndApplications *nd_apps;

#define ndEF    entry->flow
#define ndEFNF  entry->flow->ndpi_flow
#define ndEFNFP entry->flow->ndpi_flow->protos

ndDetectionQueueEntry::ndDetectionQueueEntry(
    ndFlow *flow, uint8_t *pkt_data, uint32_t pkt_length, int addr_cmp
) : flow(flow), pkt_data(NULL), pkt_length(pkt_length), addr_cmp(addr_cmp)
{
    if (pkt_data != NULL && pkt_length > 0) {
        this->pkt_data = new uint8_t[pkt_length];
        if (this->pkt_data == NULL) throw ndDetectionThreadException(strerror(ENOMEM));
        memcpy(this->pkt_data, pkt_data, pkt_length);
    }
}

ndDetectionThread::ndDetectionThread(
    int16_t cpu,
    const string &tag,
#ifdef _ND_USE_NETLINK
    ndNetlink *netlink,
#endif
    ndSocketThread *thread_socket,
#ifdef _ND_USE_CONNTRACK
    ndConntrackThread *thread_conntrack,
#endif
#ifdef _ND_USE_PLUGINS
    nd_plugins *plugin_detections,
#endif
    nd_devices &devices,
    ndDNSHintCache *dhc,
    ndFlowHashCache *fhc,
    uint8_t private_addr)
    : ndThread(tag, (long)cpu, true),
    netlink(netlink),
    thread_socket(thread_socket),
#ifdef _ND_USE_CONNTRACK
    thread_conntrack(thread_conntrack),
#endif
#ifdef _ND_USE_PLUGINS
    plugins(plugin_detections),
#endif
    ndpi(NULL), custom_proto_base(0),
    devices(devices),
    dhc(dhc), fhc(fhc),
    flows(0)
{
    ndpi = nd_ndpi_init(tag);
    custom_proto_base = ndpi_get_custom_proto_base();

    private_addrs.first.ss_family = AF_INET;
    nd_private_ipaddr(private_addr, private_addrs.first);

    private_addrs.second.ss_family = AF_INET6;
    nd_private_ipaddr(private_addr, private_addrs.second);
#if 0
    memcpy(this->dev_mac, dev_mac, ETH_ALEN);
    nd_dprintf(
        "%s: hwaddr: %02hhx:%02hhx:%02hhx:%02hhx:%02hx:%02hhx\n",
        dev.c_str(),
        dev_mac[0], dev_mac[1], dev_mac[2],
        dev_mac[3], dev_mac[4], dev_mac[5]
    );
#endif
    int rc;

    pthread_condattr_t cond_attr;

    pthread_condattr_init(&cond_attr);
    pthread_condattr_setclock(&cond_attr, CLOCK_MONOTONIC);
    if ((rc = pthread_cond_init(&pkt_queue_cond, &cond_attr)) != 0)
        throw ndDetectionThreadException(strerror(rc));
    pthread_condattr_destroy(&cond_attr);

    if ((rc = pthread_mutex_init(&pkt_queue_cond_mutex, NULL)) != 0)
        throw ndDetectionThreadException(strerror(rc));

    nd_dprintf("%s: detection thread created on CPU: %hu, custom_proto_base: %u.\n",
        tag.c_str(), cpu, custom_proto_base);
}

ndDetectionThread::~ndDetectionThread()
{
    pthread_cond_broadcast(&pkt_queue_cond);

    Join();

    pthread_cond_destroy(&pkt_queue_cond);
    pthread_mutex_destroy(&pkt_queue_cond_mutex);

    while (pkt_queue.size()) {
        ndDetectionQueueEntry *entry = pkt_queue.front();
        pkt_queue.pop();

        ndEF->queued--;

        delete [] entry->pkt_data;
        delete entry;
    }

    if (ndpi != NULL) nd_ndpi_free(ndpi);

    nd_dprintf("%s: detection thread destroyed, %u flows processed.\n",
        tag.c_str(), flows);
}

void ndDetectionThread::Reload(void)
{
    if (ndpi != NULL) nd_ndpi_free(ndpi);
    ndpi = nd_ndpi_init(tag);
    custom_proto_base = ndpi_get_custom_proto_base();

    if (ndpi == NULL) throw ndDetectionThreadException(strerror(ENOMEM));
}

void ndDetectionThread::QueuePacket(ndFlow *flow, uint8_t *pkt_data, uint32_t pkt_length, int addr_cmp)
{
    int rc;

    ndDetectionQueueEntry *entry = new ndDetectionQueueEntry(
        flow, pkt_data, pkt_length, addr_cmp
    );

    if (entry == NULL) throw ndDetectionThreadException(strerror(ENOMEM));

    Lock();

    pkt_queue.push(entry);

    Unlock();

    if ((rc = pthread_cond_broadcast(&pkt_queue_cond)) != 0)
        throw ndDetectionThreadException(strerror(rc));

    flow->queued++;
}

void *ndDetectionThread::Entry(void)
{
    int rc;

    do {
        if ((rc = pthread_mutex_lock(&pkt_queue_cond_mutex)) != 0)
            throw ndDetectionThreadException(strerror(rc));

        struct timespec ts_cond;
        if (clock_gettime(CLOCK_MONOTONIC, &ts_cond) != 0)
            throw ndDetectionThreadException(strerror(rc));

        ts_cond.tv_sec += 1;

        if ((rc = pthread_cond_timedwait(
            &pkt_queue_cond, &pkt_queue_cond_mutex, &ts_cond)) != 0 &&
            rc != ETIMEDOUT) {
            throw ndDetectionThreadException(strerror(rc));
        }

        if ((rc = pthread_mutex_unlock(&pkt_queue_cond_mutex)) != 0)
            throw ndDetectionThreadException(strerror(rc));

        ProcessPacketQueue();
    }
    while (ShouldTerminate() == false);

    ProcessPacketQueue();

    nd_dprintf("%s: detection thread ended on CPU: %hu\n", tag.c_str(), cpu);

    return NULL;
}

void ndDetectionThread::ProcessPacketQueue(void)
{
    ndDetectionQueueEntry *entry;

    do {

        Lock();

        if (pkt_queue.size()) {
            entry = pkt_queue.front();
            pkt_queue.pop();
        }
        else
            entry = NULL;

        Unlock();

        if (entry != NULL) {
            if (! ndEF->flags.detection_complete.load() &&
                ! ndEF->flags.detection_expired.load())
                ProcessPacket(entry);

            ndEF->queued--;

            delete [] entry->pkt_data;
            delete entry;
        }
    } while (entry != NULL);
}

void ndDetectionThread::ProcessPacket(ndDetectionQueueEntry *entry)
{
    bool flow_update = false;
    struct ndpi_id_struct *id_src, *id_dst;

    if (ndEFNF != NULL) {
        if (entry->addr_cmp == ndEF->direction)
            id_src = ndEF->id_src, id_dst = ndEF->id_dst;
        else
            id_src = ndEF->id_dst, id_dst = ndEF->id_src;
    }
    else {
        flows++;

        ndEFNF = (ndpi_flow_struct *)ndpi_malloc(sizeof(ndpi_flow_struct));
        if (ndEFNF == NULL)
            throw ndDetectionThreadException(strerror(ENOMEM));

        memset(ndEFNF, 0, sizeof(ndpi_flow_struct));

        ndEF->id_src = new ndpi_id_struct;
        if (ndEF->id_src == NULL)
            throw ndDetectionThreadException(strerror(ENOMEM));
        ndEF->id_dst = new ndpi_id_struct;
        if (ndEF->id_dst == NULL)
            throw ndDetectionThreadException(strerror(ENOMEM));

        memset(ndEF->id_src, 0, sizeof(ndpi_id_struct));
        memset(ndEF->id_dst, 0, sizeof(ndpi_id_struct));

        id_src = ndEF->id_src;
        id_dst = ndEF->id_dst;
    }

    if (! ndEF->flags.detection_expiring.load()) {

        ndEF->detection_packets++;

        ndpi_protocol ndpi_rc = ndpi_detection_process_packet(
            ndpi,
            ndEFNF,
            (const uint8_t *)entry->pkt_data,
            entry->pkt_length,
            ndEF->ts_last_seen,
            id_src,
            id_dst
        );

        // XXX: Preserve app_protocol.
        ndEF->detected_protocol = nd_ndpi_proto_find(
            ndpi_rc.master_protocol,
            ndEF
        );
    }

    bool check_extra_packets = (
        ndEFNF->check_extra_packets
        && ndEF->detection_packets < nd_config.max_detection_pkts);

    if (! ndEF->flags.detection_init.load() && (
        ndEF->detected_protocol != ND_PROTO_UNKNOWN
        || ndEF->detection_packets == nd_config.max_detection_pkts
        || ndEF->flags.detection_expiring.load())) {

        if (! ndEF->flags.detection_guessed.load()
            && ndEF->detected_protocol == ND_PROTO_UNKNOWN) {

            ndEF->flags.detection_guessed = true;
            ndEF->detected_protocol = nd_ndpi_proto_find(
                ndpi_guess_undetected_protocol(
                    ndpi,
                    NULL,
                    ndEF->ip_protocol,
                    ntohs(ndEF->lower_port),
                    ntohs(ndEF->upper_port)
                ),
                ndEF
            );
        }

#ifdef _ND_USE_NETLINK
        if (ND_USE_NETLINK) {
            ndEF->lower_type = netlink->ClassifyAddress(&ndEF->lower_addr);
            ndEF->upper_type = netlink->ClassifyAddress(&ndEF->upper_addr);
        }
#endif
        if (dhc != NULL) {
            string hostname;
#ifdef _ND_USE_NETLINK
            if (ndEF->lower_type == ndNETLINK_ATYPE_UNKNOWN)
                ndEF->flags.dhc_hit = dhc->lookup(&ndEF->lower_addr, hostname);
            else if (ndEF->upper_type == ndNETLINK_ATYPE_UNKNOWN) {
                ndEF->flags.dhc_hit = dhc->lookup(&ndEF->upper_addr, hostname);
            }
#endif
            if (! ndEF->flags.dhc_hit.load()) {
                if (ndEF->origin == ndFlow::ORIGIN_LOWER)
                    ndEF->flags.dhc_hit = dhc->lookup(&ndEF->upper_addr, hostname);
                else if (ndEF->origin == ndFlow::ORIGIN_UPPER)
                    ndEF->flags.dhc_hit = dhc->lookup(&ndEF->lower_addr, hostname);
            }

            if (ndEF->flags.dhc_hit.load() &&
                (ndEFNF->host_server_name[0] == '\0' ||
                nd_is_ipaddr((const char *)ndEFNF->host_server_name))) {
                snprintf(
                    (char *)ndEFNF->host_server_name,
                    sizeof(ndEFNF->host_server_name) - 1,
                    "%s", hostname.c_str()
                );
            }
        }

        // Sanitize host server name; RFC 952 plus underscore for SSDP.
        for(unsigned i = 0;
            i < ND_MAX_HOSTNAME &&
            i < sizeof(ndEFNF->host_server_name); i++) {

            if (isalnum(ndEFNF->host_server_name[i]) ||
                ndEFNF->host_server_name[i] == '-' ||
                ndEFNF->host_server_name[i] == '_' ||
                ndEFNF->host_server_name[i] == '.') {
                ndEF->host_server_name[i] = tolower(ndEFNF->host_server_name[i]);
            }
            else {
                ndEF->host_server_name[i] = '\0';
                break;
            }
        }

        // Determine application based on master protocol metadata
        switch (ndEF->master_protocol()) {
        case ND_PROTO_TLS:
        case ND_PROTO_QUIC:
            if (ndEFNFP.tls_quic_stun.tls_quic.client_requested_server_name[0] != '\0') {
                ndEF->detected_application = nd_apps->Find(
                    (const char *)ndEFNFP.tls_quic_stun.tls_quic.client_requested_server_name
                );
            }
            break;

        case ND_PROTO_SPOTIFY:
            ndEF->detected_application = nd_apps->Lookup("netify.spotify");
            break;

        case ND_PROTO_SKYPE_CALL:
        case ND_PROTO_SKYPE_TEAMS:
            ndEF->detected_application = nd_apps->Lookup("netify.skype");
            break;

        case ND_PROTO_MDNS:
            if (ndEFNFP.mdns.answer[0] != '\0') {
                ndEF->detected_application = nd_apps->Find(
                    (const char *)ndEFNFP.mdns.answer
                );
            }
            break;
        default:
            break;
        }

        // Determine application by host_server_name if still unknown.
        if (ndEF->detected_application == ND_APP_UNKNOWN) {
            if (ndEF->host_server_name[0] != '\0') {
                ndEF->detected_application = nd_apps->Find(
                    (const char *)ndEF->host_server_name
                );
            }
        }

        if (ndEF->detected_application == ND_APP_UNKNOWN) {
            switch (ndEF->ip_version) {
            case 4:
                ndEF->detected_application = nd_apps->Find(
                    AF_INET,
                    static_cast<void *>(
                        &ndEF->lower_addr4->sin_addr
                    )
                );
                if (ndEF->detected_application) break;
                ndEF->detected_application = nd_apps->Find(
                    AF_INET,
                    static_cast<void *>(
                        &ndEF->upper_addr4->sin_addr
                    )
                );
                break;
            case 6:
                ndEF->detected_application = nd_apps->Find(
                    AF_INET6,
                    static_cast<void *>(
                        &ndEF->lower_addr6->sin6_addr
                    )
                );
                if (ndEF->detected_application) break;
                ndEF->detected_application = nd_apps->Find(
                    AF_INET6,
                    static_cast<void *>(
                        &ndEF->upper_addr6->sin6_addr
                    )
                );
                break;
            }
        }

        if (ndEF->detected_protocol == ND_PROTO_STUN) {
            // TODO
            //ndEF->detected_application == ND_PROTO_GOOGLE
            //    ndEF->detected_protocol.app_protocol = ND_PROTO_HANGOUT;
        }

        // Additional protocol-specific processing...
        nd_proto_id_t nd_proto = ndEF->master_protocol();

        switch (nd_proto) {

        case ND_PROTO_MDNS:
            for (size_t i = 0;
                i < strlen((const char *)ndEFNFP.mdns.answer); i++) {
                if (! isprint(ndEFNFP.mdns.answer[i])) {
                    // XXX: Sanitize mdns.answer of non-printable characters.
                    ndEFNFP.mdns.answer[i] = '_';
                }
            }

            snprintf(
                ndEF->mdns.answer, ND_FLOW_MDNS_ANSLEN,
                "%s", ndEFNFP.mdns.answer
            );
            break;

        case ND_PROTO_TLS:
        case ND_PROTO_QUIC:
            ndEF->ssl.version =
                ndEFNFP.tls_quic_stun.tls_quic.ssl_version;
            ndEF->ssl.cipher_suite =
                ndEFNFP.tls_quic_stun.tls_quic.server_cipher;

            snprintf(ndEF->ssl.client_sni, ND_FLOW_TLS_CNLEN,
                "%s", ndEFNFP.tls_quic_stun.tls_quic.client_requested_server_name);
            snprintf(ndEF->ssl.client_ja3, ND_FLOW_TLS_JA3LEN,
                "%s", ndEFNFP.tls_quic_stun.tls_quic.ja3_client);
            break;

        case ND_PROTO_HTTP:
            if (ndEFNF->http.user_agent != NULL) {
                for (size_t i = 0;
                    i < strlen((const char *)ndEFNF->http.user_agent); i++) {
                    if (! isprint(ndEFNF->http.user_agent[i])) {
                        // XXX: Sanitize user_agent of non-printable characters.
                        ndEFNF->http.user_agent[i] = '\0';
                        break;
                    }
                }

                snprintf(
                    ndEF->http.user_agent, ND_FLOW_UA_LEN,
                    "%s", ndEFNF->http.user_agent
                );
            }

            if (ndEFNF->http.url != NULL) {
                snprintf(
                    ndEF->http.url, ND_FLOW_URL_LEN,
                    "%s", ndEFNF->http.url
                );
            }

            break;
        case ND_PROTO_DHCP:
            snprintf(
                ndEF->dhcp.fingerprint, ND_FLOW_DHCPFP_LEN,
                "%s", ndEFNFP.dhcp.fingerprint
            );
            snprintf(
                ndEF->dhcp.class_ident, ND_FLOW_DHCPCI_LEN,
                "%s", ndEFNFP.dhcp.class_ident
            );
            break;
        case ND_PROTO_SSH:
            snprintf(ndEF->ssh.client_agent, ND_FLOW_SSH_UALEN,
                "%s", ndEFNFP.ssh.client_signature);
            snprintf(ndEF->ssh.server_agent, ND_FLOW_SSH_UALEN,
                "%s", ndEFNFP.ssh.server_signature);
            break;
        case ND_PROTO_SSDP:
            if (ndEFNF->packet.packet_lines_parsed_complete) {
                string buffer;
                for (unsigned i = 0;
                    i < ndEFNF->packet.parsed_lines; i++) {

                    buffer.assign(
                        (const char *)ndEFNF->packet.line[i].ptr,
                        ndEFNF->packet.line[i].len
                    );

                    size_t n = buffer.find_first_of(":");
                    if (n != string::npos && n > 0) {
                        string key = buffer.substr(0, n);
                        for_each(key.begin(), key.end(), [](char & c) {
                            c = ::tolower(c);
                        });

                        if (key != "user-agent" && key != "server" &&
                            ! (key.size() > 2 && key[0] == 'x' && key[1] == '-'))
                            continue;

                        string value = buffer.substr(n);
                        value.erase(value.begin(),
                            find_if(value.begin(), value.end(), [](int c) {
                                return !isspace(c) && c != ':';
                            })
                        );

                        ndEF->ssdp.headers[key] = value;
                    }
                }
            }
            break;
        case ND_PROTO_BITTORRENT:
            if (ndEFNFP.bittorrent.hash_valid) {
                ndEF->bt.info_hash_valid = true;
                memcpy(
                    ndEF->bt.info_hash,
                    ndEFNFP.bittorrent.hash,
                    ND_FLOW_BTIHASH_LEN
                );
            }
            break;
        default:
            break;
        }

        if (fhc != NULL &&
            ndEF->lower_port != 0 && ndEF->upper_port != 0) {

            flow_digest.assign(
                (const char *)ndEF->digest_lower, SHA1_DIGEST_LENGTH);

            if (! fhc->pop(flow_digest, flow_digest_mdata)) {

                ndEF->hash(tag, true);

                flow_digest_mdata.assign(
                    (const char *)ndEF->digest_mdata, SHA1_DIGEST_LENGTH
                );

                if (memcmp(ndEF->digest_lower, ndEF->digest_mdata,
                    SHA1_DIGEST_LENGTH))
                    fhc->push(flow_digest, flow_digest_mdata);
            }
            else {
                if (memcmp(ndEF->digest_mdata, flow_digest_mdata.c_str(),
                    SHA1_DIGEST_LENGTH)) {
#ifdef _ND_LOG_FHC
                    nd_dprintf("%s: Resurrected flow metadata hash from cache.\n",
                        tag.c_str());
#endif
                    memcpy(ndEF->digest_mdata, flow_digest_mdata.c_str(),
                        SHA1_DIGEST_LENGTH);
                }
            }
        }
        else ndEF->hash(tag, true);

        struct sockaddr_in *laddr4 = ndEF->lower_addr4;
        struct sockaddr_in6 *laddr6 = ndEF->lower_addr6;
        struct sockaddr_in *uaddr4 = ndEF->upper_addr4;
        struct sockaddr_in6 *uaddr6 = ndEF->upper_addr6;

        switch (ndEF->ip_version) {
        case 4:
            inet_ntop(AF_INET, &laddr4->sin_addr.s_addr,
                ndEF->lower_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &uaddr4->sin_addr.s_addr,
                ndEF->upper_ip, INET_ADDRSTRLEN);
            break;

        case 6:
            inet_ntop(AF_INET6, &laddr6->sin6_addr.s6_addr,
                ndEF->lower_ip, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &uaddr6->sin6_addr.s6_addr,
                ndEF->upper_ip, INET6_ADDRSTRLEN);
            break;

        default:
            nd_printf("%s: ERROR: Unknown IP version: %d\n",
                tag.c_str(), ndEF->ip_version);
            throw ndDetectionThreadException(strerror(EINVAL));
        }
#ifdef _ND_USE_NETLINK
        nd_device_addrs *device_addrs = devices[ndEF->iface->second].second;
        if (device_addrs != NULL) {

            pthread_mutex_lock(devices[ndEF->iface->second].first);

            for (int t = ndFlow::TYPE_LOWER; t < ndFlow::TYPE_MAX; t++) {
                string ip;
                const uint8_t *umac = NULL;

                if (t == ndFlow::TYPE_LOWER &&
                    (ndEF->lower_type == ndNETLINK_ATYPE_LOCALIP ||
                     ndEF->lower_type == ndNETLINK_ATYPE_LOCALNET ||
                     ndEF->lower_type == ndNETLINK_ATYPE_PRIVATE)) {

                    umac = ndEF->lower_mac;
                    ip = ndEF->lower_ip;
                }
                else if (t == ndFlow::TYPE_UPPER &&
                    (ndEF->upper_type == ndNETLINK_ATYPE_LOCALIP ||
                     ndEF->upper_type == ndNETLINK_ATYPE_LOCALNET ||
                     ndEF->upper_type == ndNETLINK_ATYPE_PRIVATE)) {

                    umac = ndEF->upper_mac;
                    ip = ndEF->upper_ip;
                }
                else continue;

                // Filter out reserved MAC prefixes...
                // ...IANA RFC7042, IPv4 uni/multicast:
                if (! ((umac[0] == 0x00 || umac[0] == 0x01) &&
                    umac[1] == 0x00 && umac[2] == 0x5e) &&
                    // IPv6 multicast:
                    ! (umac[0] == 0x33 && umac[1] == 0x33)) {

                    string mac;
                    mac.assign((const char *)umac, ETH_ALEN);

                    nd_device_addrs::iterator i;
                    if ((i = device_addrs->find(mac)) == device_addrs->end())
                        (*device_addrs)[mac].push_back(ip);
                    else {
                        bool duplicate = false;
                        vector<string>::iterator j;
                        for (j = (*device_addrs)[mac].begin();
                            j != (*device_addrs)[mac].end(); j++) {
                            if (ip != (*j)) continue;
                            duplicate = true;
                            break;
                        }

                        if (! duplicate)
                            (*device_addrs)[mac].push_back(ip);
                    }
                }
            }

            pthread_mutex_unlock(devices[ndEF->iface->second].first);
        }
#endif
#if defined(_ND_USE_CONNTRACK) && defined(_ND_USE_NETLINK)
        if (! ndEF->iface->first && thread_conntrack != NULL) {
            if ((ndEF->lower_type == ndNETLINK_ATYPE_LOCALIP &&
                ndEF->upper_type == ndNETLINK_ATYPE_UNKNOWN) ||
                (ndEF->lower_type == ndNETLINK_ATYPE_UNKNOWN &&
                ndEF->upper_type == ndNETLINK_ATYPE_LOCALIP)) {

                // Update flow with any collected information from the
                // connection tracker (CT ID, mark, NAT'd).
                thread_conntrack->UpdateFlow(ndEF);
            }
        }
#endif
        for (vector<uint8_t *>::const_iterator i =
            nd_config.privacy_filter_mac.begin();
            i != nd_config.privacy_filter_mac.end() &&
                ndEF->privacy_mask !=
                (ndFlow::PRIVATE_LOWER | ndFlow::PRIVATE_UPPER); i++) {
            if (! memcmp((*i), ndEF->lower_mac, ETH_ALEN))
                ndEF->privacy_mask |= ndFlow::PRIVATE_LOWER;
            if (! memcmp((*i), ndEF->upper_mac, ETH_ALEN))
                ndEF->privacy_mask |= ndFlow::PRIVATE_UPPER;
        }

        for (vector<struct sockaddr *>::const_iterator i =
            nd_config.privacy_filter_host.begin();
            i != nd_config.privacy_filter_host.end() &&
                ndEF->privacy_mask !=
                (ndFlow::PRIVATE_LOWER | ndFlow::PRIVATE_UPPER); i++) {

            struct sockaddr_in *sa_in;
            struct sockaddr_in6 *sa_in6;

            switch ((*i)->sa_family) {
            case AF_INET:
                sa_in = reinterpret_cast<struct sockaddr_in *>((*i));
                if (! memcmp(&ndEF->lower_addr4, &sa_in->sin_addr,
                    sizeof(struct in_addr)))
                    ndEF->privacy_mask |= ndFlow::PRIVATE_LOWER;
                if (! memcmp(&ndEF->upper_addr4, &sa_in->sin_addr,
                    sizeof(struct in_addr)))
                    ndEF->privacy_mask |= ndFlow::PRIVATE_UPPER;
                break;
            case AF_INET6:
                sa_in6 = reinterpret_cast<struct sockaddr_in6 *>((*i));
                if (! memcmp(&ndEF->lower_addr6, &sa_in6->sin6_addr,
                    sizeof(struct in6_addr)))
                    ndEF->privacy_mask |= ndFlow::PRIVATE_LOWER;
                if (! memcmp(&ndEF->upper_addr6, &sa_in6->sin6_addr,
                    sizeof(struct in6_addr)))
                    ndEF->privacy_mask |= ndFlow::PRIVATE_UPPER;
                break;
            }
        }

        ndEF->detected_protocol_name = nd_proto_get_name(
            ndEF->detected_protocol
        );

        if (ndEF->detected_application != ND_APP_UNKNOWN) {
            ndEF->detected_application_name = strdup(
                nd_apps->Lookup(ndEF->detected_application)
            );
        }

        ndEF->update_lower_maps();

        flow_update = true;
        ndEF->flags.detection_init = true;

        if (ndEF->flags.detection_expiring.load()) {
            ndEF->flags.detection_expired = true;
            check_extra_packets = false;
        }
    }
    else if (ndEF->flags.detection_init.load()) {
        // Flows with extra packet processing...
        ndEF->flags.detection_updated = false;

        switch (ndEF->master_protocol()) {

        case ND_PROTO_TLS:
        case ND_PROTO_QUIC:
            if (ndEF->ssl.cipher_suite == 0 &&
                ndEFNFP.tls_quic_stun.tls_quic.server_cipher != 0) {
                ndEF->ssl.cipher_suite =
                    ndEFNFP.tls_quic_stun.tls_quic.server_cipher;

                flow_update = true;
                ndEF->flags.detection_updated = true;
            }

            if (ndEF->ssl.server_cn[0] == '\0' &&
                ndEFNFP.tls_quic_stun.tls_quic.serverCN != NULL) {
                snprintf(ndEF->ssl.server_cn, ND_FLOW_TLS_CNLEN,
                    "%s", ndEFNFP.tls_quic_stun.tls_quic.serverCN);
                free(ndEFNFP.tls_quic_stun.tls_quic.serverCN);
                ndEFNFP.tls_quic_stun.tls_quic.serverCN = NULL;
                if (ndEF->detected_application == ND_APP_UNKNOWN) {
                    ndEF->detected_application = nd_apps->Find(
                        (const char *)ndEF->ssl.server_cn
                    );
                }

                flow_update = true;
                ndEF->flags.detection_updated = true;
            }
            if (ndEF->ssl.server_ja3[0] == '\0' &&
                ndEFNFP.tls_quic_stun.tls_quic.ja3_server[0] != '\0') {
                snprintf(ndEF->ssl.server_ja3, ND_FLOW_TLS_JA3LEN, "%s",
                    ndEFNFP.tls_quic_stun.tls_quic.ja3_server);
                flow_update = true;
                ndEF->flags.detection_updated = true;
            }

            if (! ndEF->ssl.cert_fingerprint_found &&
                ndEFNF->l4.tcp.tls.fingerprint_set) {
                memcpy(ndEF->ssl.cert_fingerprint,
                    ndEFNFP.tls_quic_stun.tls_quic.sha1_certificate_fingerprint,
                    ND_FLOW_TLS_HASH_LEN);
                flow_update = true;
                ndEF->ssl.cert_fingerprint_found = true;
                ndEF->flags.detection_updated = true;
            }

            if (ndEF->ssl.server_names_length <
                ndEFNFP.tls_quic_stun.tls_quic.server_names_len &&
                ndEFNFP.tls_quic_stun.tls_quic.server_names) {

                ndEF->ssl.server_names_length = ndEFNFP.tls_quic_stun.tls_quic.server_names_len;
                ndEF->ssl.server_names = (char *)realloc(
                    (void *)ndEF->ssl.server_names,
                    ndEF->ssl.server_names_length + 1
                );
                if (ndEF->ssl.server_names == NULL)
                    throw ndDetectionThreadException(strerror(ENOMEM));
                memcpy(
                    ndEF->ssl.server_names,
                    ndEFNFP.tls_quic_stun.tls_quic.server_names,
                    ndEF->ssl.server_names_length
                );
                ndEF->ssl.server_names[ndEF->ssl.server_names_length] = '\0';

                flow_update = true;
                ndEF->flags.detection_updated = true;
            }

            if (ndEFNFP.tls_quic_stun.tls_quic.alpn) {

                //nd_dprintf("%s: TLS ALPN: %s\n", tag.c_str(),
                //    ndEFNFP.tls_quic_stun.tls_quic.alpn);
                stringstream ss(
                    ndEFNFP.tls_quic_stun.tls_quic.alpn
                );

                while (ss.good()) {
                    string alpn;
                    getline(ss, alpn, ',');

                    //nd_dprintf("%s: TLS ALPN: search for: %s\n", tag.c_str(),
                    //    alpn.c_str());

                    for (int i = 0; ; i++) {
                        if (nd_alpn_proto_map[i].alpn[0] == '\0') break;
                        if (strncmp(alpn.c_str(),
                            nd_alpn_proto_map[i].alpn, ND_TLS_ALPN_MAX)) continue;
                        if (nd_alpn_proto_map[i].proto_id == ndEF->detected_protocol)
                            continue;

                        nd_dprintf("%s: TLS ALPN: refined: %s: %s -> %s\n",
                            tag.c_str(), alpn.c_str(),
                            ndEF->detected_protocol_name,
                            nd_proto_get_name(nd_alpn_proto_map[i].proto_id)
                        );

                        ndEF->detected_protocol = nd_alpn_proto_map[i].proto_id;
                        ndEF->detected_protocol_name = nd_proto_get_name(
                            nd_alpn_proto_map[i].proto_id
                        );

                        flow_update = true;
                        ndEF->flags.detection_updated = true;
                        break;
                    }
                }

                free(ndEFNFP.tls_quic_stun.tls_quic.alpn);
                ndEFNFP.tls_quic_stun.tls_quic.alpn = NULL;
            }
#if 0
/*
            snprintf(ndEF->ssl.server_cn, ND_FLOW_TLS_CNLEN,
                "%s", ndEFNFP.tls_quic_stun.tls_quic.server_certificate);
            snprintf(ndEF->ssl.server_organization, ND_FLOW_TLS_ORGLEN,
                "%s", ndEFNFP.tls_quic_stun.tls_quic.server_organization);
*/
        nd_dprintf("--> PROCESS EXTRA PACKETS: hello: %s\n",
            (ndEFNFP.tls_quic_stun.tls_quic.hello_processed) ?
            "yes" : "no");

        if (ndEF->ip_protocol != IPPROTO_TCP ||
            ! ndEFNF->l4.tcp.tls.certificate_processed) return;

            if (ndEF->detected_application == ND_APP_UNKNOWN &&
                ndEFNFP.tls_quic_stun.tls_quic.server_certificate[0] != '\0') {
                ndEF->detected_protocol.app_protocol = (uint16_t)ndpi_match_host_app_proto(
                    ndpi,
                    ndEFNF,
                    (char *)ndEFNFP.tls_quic_stun.tls_quic.server_certificate,
                    strlen((const char*)ndEFNFP.tls_quic_stun.tls_quic.server_certificate),
                    &npmr);
            }
#endif
        break;

        default:
            break;
        }
    }

    // Flow detection complete.
    if (ndEF->flags.detection_init.load() && ! check_extra_packets)
        ndEF->flags.detection_complete = true;

    if (flow_update) {

        if ((ND_DEBUG && ND_VERBOSE) || nd_config.h_flow != stderr)
            ndEF->print();

        for (nd_plugins::iterator i = plugins->begin();
            i != plugins->end(); i++) {
            ndPluginDetection *p = reinterpret_cast<ndPluginDetection *>(
                i->second->GetPlugin()
            );
            p->ProcessFlow(ndEF);
        }

        if (thread_socket && (ND_FLOW_DUMP_UNKNOWN ||
            ndEF->detected_protocol != ND_PROTO_UNKNOWN)) {
            json j;

            j["type"] = "flow";
            j["interface"] = ndEF->iface->second;
            j["internal"] = ndEF->iface->first;
            j["established"] = false;

            json jf;
            ndEF->json_encode(jf, ndFlow::ENCODE_METADATA);
            j["flow"] = jf;

            string json_string;
            nd_json_to_string(j, json_string, false);
            json_string.append("\n");

            thread_socket->QueueWrite(json_string);
        }
    }

    if (ndEF->flags.detection_complete.load())
        ndEF->release();
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
