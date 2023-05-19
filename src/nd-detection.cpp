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
#include <bitset>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#define __FAVOR_BSD 1
#include <netinet/in.h>
#include <netinet/tcp.h>
#undef __FAVOR_BSD

#include <arpa/inet.h>

#include <net/if.h>
#include <net/if_arp.h>
#if defined(__linux__)
#include <linux/if_packet.h>
#elif defined(__FreeBSD__)
#include <net/if_dl.h>
#endif

#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <netdb.h>
#include <resolv.h>
#include <ctype.h>

#include <curl/curl.h>
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

#include <radix/radix_tree.hpp>

#ifdef _ND_USE_CONNTRACK
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#endif

using namespace std;

#include "netifyd.h"

#include "nd-config.h"
#include "nd-signal.h"
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
#include "nd-fhc.h"
#include "nd-dhc.h"
#include "nd-thread.h"
class ndInstanceStatus;
#include "nd-plugin.h"
#include "nd-instance.h"
#include "nd-flow-parser.h"
#ifdef _ND_USE_CONNTRACK
#include "nd-conntrack.h"
#endif
#include "nd-detection.h"
#include "nd-capture.h"
#include "nd-tls-alpn.h"
#include "nd-napi.h"

// Enable flow hash cache debug logging
//#define _ND_LOG_FHC             1

// Enable to log unknown protocol debug
//#define _ND_LOG_PROTO_UNKNOWN   1

// Enable to log custom domain category lookups
//#define _ND_LOG_DOMAIN_LOOKUPS  1

#define ndEF    entry->flow
#define ndEFNF  entry->flow->ndpi_flow
#define ndEFNFP entry->flow->ndpi_flow->protos

ndDetectionThread::ndDetectionThread(
    int16_t cpu,
    const string &tag,
#ifdef _ND_USE_NETLINK
    ndNetlink *netlink,
#endif
#ifdef _ND_USE_CONNTRACK
    ndConntrackThread *thread_conntrack,
#endif
    ndDNSHintCache *dhc,
    ndFlowHashCache *fhc,
    uint8_t private_addr)
    : ndThread(tag, (long)cpu, true),
    ndInstanceClient(),
#ifdef _ND_USE_NETLINK
    netlink(netlink),
#endif
#ifdef _ND_USE_CONNTRACK
    thread_conntrack(thread_conntrack),
#endif
    ndpi(NULL),
    dhc(dhc), fhc(fhc),
    flows(0)
{
    Reload();

    private_addrs.first.ss_family = AF_INET;
    nd_private_ipaddr(private_addr, private_addrs.first);

    private_addrs.second.ss_family = AF_INET6;
    nd_private_ipaddr(private_addr, private_addrs.second);

    int rc;

    pthread_condattr_t cond_attr;

    pthread_condattr_init(&cond_attr);
    pthread_condattr_setclock(&cond_attr, CLOCK_MONOTONIC);
    if ((rc = pthread_cond_init(&pkt_queue_cond, &cond_attr)) != 0)
        throw ndDetectionThreadException(strerror(rc));
    pthread_condattr_destroy(&cond_attr);

    if ((rc = pthread_mutex_init(&pkt_queue_cond_mutex, NULL)) != 0)
        throw ndDetectionThreadException(strerror(rc));

    nd_dprintf("%s: detection thread created on CPU: %hu\n",
        tag.c_str(), cpu);
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

        delete entry;
    }

    if (ndpi != NULL) nd_ndpi_free(ndpi);

    nd_dprintf("%s: detection thread destroyed, %u flows processed.\n",
        tag.c_str(), flows);
}

void ndDetectionThread::Reload(void)
{
    if (ndpi != NULL) nd_ndpi_free(ndpi);
    ndpi = nd_ndpi_init();
}

void ndDetectionThread::QueuePacket(
    nd_flow_ptr& flow, const ndPacket *packet,
    const uint8_t *data, uint16_t length)
{
    ndDetectionQueueEntry *entry = new ndDetectionQueueEntry(
        flow, packet, data, length
    );

    if (entry == NULL)
        throw ndDetectionThreadException(strerror(ENOMEM));

    Lock();

    pkt_queue.push(entry);

    Unlock();

    int rc;
    if ((rc = pthread_cond_broadcast(&pkt_queue_cond)) != 0)
        throw ndDetectionThreadException(strerror(rc));
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

            if (ndEF->stats.detection_packets.load() == 0 || (
                ndEF->flags.detection_complete.load() == false &&
                ndEF->flags.expiring.load() == false &&
                ndEF->stats.detection_packets.load() < ndGC.max_detection_pkts
            )) {

                ndEF->stats.detection_packets++;

                ProcessPacket(entry);
            }

            if (ndEF->stats.detection_packets.load() == ndGC.max_detection_pkts ||
                (ndEF->flags.expiring.load() &&
                    ndEF->flags.expired.load() == false)) {

                if (ndEF->flags.detection_complete.load() == false &&
                    ndEF->flags.detection_guessed.load() == false &&
                    ndEF->detected_protocol == ND_PROTO_UNKNOWN) {

                    if (entry->packet != nullptr)
                        ProcessPacket(entry);

                    if (ndEF->detected_protocol == ND_PROTO_UNKNOWN)
                        SetGuessedProtocol(entry);

                    ProcessFlow(entry);

                    FlowUpdate(entry);
                }

                if (ndEF->flags.expiring.load())
                    ndEF->flags.expired = true;
            }

            if (ndEF->flags.detection_complete.load())
                ndEF->Release();

            delete entry;
        }
    } while (entry != NULL);
}

void ndDetectionThread::ProcessPacket(ndDetectionQueueEntry *entry)
{
    bool flow_update = false;

    if (ndEFNF == NULL) {

        flows++;

        ndEFNF = (ndpi_flow_struct *)ndpi_malloc(sizeof(ndpi_flow_struct));
        if (ndEFNF == NULL)
            throw ndDetectionThreadException(strerror(ENOMEM));

        memset(ndEFNF, 0, sizeof(ndpi_flow_struct));
    }

    ndpi_protocol ndpi_rc = ndpi_detection_process_packet(
        ndpi,
        ndEFNF,
        entry->data,
        entry->length,
        ndEF->ts_last_seen.load(),
        NULL
    );

    if (ndEF->detected_protocol == ND_PROTO_UNKNOWN &&
        ndpi_rc.master_protocol != NDPI_PROTOCOL_UNKNOWN) {
        ndEF->detected_protocol = nd_ndpi_proto_find(
            ndpi_rc.master_protocol,
            ndEF
        );
    }

    if (ndEF->detected_protocol == ND_PROTO_UNKNOWN &&
        ndpi_rc.app_protocol != NDPI_PROTOCOL_UNKNOWN) {
        ndEF->detected_protocol = nd_ndpi_proto_find(
            ndpi_rc.app_protocol,
            ndEF
        );
#if _ND_LOG_PROTO_UNKNOWN
        if (ndEF->detected_protocol != ND_PROTO_UNKNOWN) {
            char proto_name[64];
            ndpi_protocol2name(
                ndpi, ndpi_rc, proto_name, sizeof(proto_name)
            );
            nd_dprintf(
                "%s: Set detected protocol from application hint: %s\n",
                tag.c_str(), proto_name
            );
        }
#endif
    }

    if (ndEF->detected_protocol == ND_PROTO_TODO) {
        char proto_name[64];
        ndpi_protocol2name(
            ndpi, ndpi_rc, proto_name, sizeof(proto_name)
        );
        nd_dprintf(
            "%s: Unmapped detected protocol: ID #%hu/%hu (%s)\n",
                tag.c_str(), ndpi_rc.master_protocol,
                ndpi_rc.app_protocol, proto_name
        );
    }

    bool check_extra_packets = (ndEFNF->extra_packets_func != NULL);

    if (! ndEF->flags.risk_checked.load()) {
        if (ndEFNF->risk_checked) {
            if (ndEFNF->risk != NDPI_NO_RISK) {
                for (unsigned i = 0; i < NDPI_MAX_RISK; i++) {
                    if (NDPI_ISSET_BIT(ndEFNF->risk, i) != 0) {
                        ndEF->risks.push_back(nd_ndpi_risk_find(i));
                    }
                }

                ndEF->ndpi_risk_score = ndpi_risk2score(
                    ndEFNF->risk,
                    &ndEF->ndpi_risk_score_client,
                    &ndEF->ndpi_risk_score_server
                );
            }

            ndEF->flags.risk_checked = true;
        }
    }

    if (ndEF->flags.detection_init.load() == false
        && ndEF->detected_protocol != ND_PROTO_UNKNOWN) {

        ProcessFlow(entry);
        flow_update = true;
    }
    else if (ndEF->flags.detection_init.load()) {

        // Flows with extra packet processing...
        ndEF->flags.detection_updated = false;

        switch (ndEF->GetMasterProtocol()) {

        case ND_PROTO_TLS:
        case ND_PROTO_QUIC:
            if (ndEF->ssl.cipher_suite == 0 &&
                ndEFNFP.tls_quic.server_cipher != 0) {
                ndEF->ssl.cipher_suite =
                    ndEFNFP.tls_quic.server_cipher;

                flow_update = true;
                ndEF->flags.detection_updated = true;
            }

            if (ndEF->ssl.server_cn[0] == '\0' &&
                ndEFNFP.tls_quic.serverCN != NULL) {
                nd_set_hostname(
                    ndEF->ssl.server_cn,
                    ndEFNFP.tls_quic.serverCN,
                    ND_FLOW_TLS_CNLEN
                );
                free(ndEFNFP.tls_quic.serverCN);
                ndEFNFP.tls_quic.serverCN = NULL;

                // Detect application by server CN if still unknown.
                SetDetectedApplication(entry,
                    ndi.apps.Find(ndEF->ssl.server_cn)
                );

                flow_update = true;
                ndEF->flags.detection_updated = true;
            }

            if (ndEF->ssl.issuer_dn == NULL &&
                ndEFNFP.tls_quic.issuerDN != NULL) {
                ndEF->ssl.issuer_dn = strdup(ndEFNFP.tls_quic.issuerDN);
                free(ndEFNFP.tls_quic.issuerDN);
                ndEFNFP.tls_quic.issuerDN = NULL;
                flow_update = true;
                ndEF->flags.detection_updated = true;
            }

            if (ndEF->ssl.subject_dn == NULL &&
                ndEFNFP.tls_quic.subjectDN != NULL) {
                ndEF->ssl.subject_dn = strdup(ndEFNFP.tls_quic.subjectDN);
                free(ndEFNFP.tls_quic.subjectDN);
                ndEFNFP.tls_quic.subjectDN = NULL;
                flow_update = true;
                ndEF->flags.detection_updated = true;
            }

            if (ndEF->ssl.server_ja3[0] == '\0' &&
                ndEFNFP.tls_quic.ja3_server[0] != '\0') {
                snprintf(ndEF->ssl.server_ja3, ND_FLOW_TLS_JA3LEN, "%s",
                    ndEFNFP.tls_quic.ja3_server);
                flow_update = true;
                ndEF->flags.detection_updated = true;
            }

            if (! ndEF->ssl.cert_fingerprint_found &&
                ndEFNFP.tls_quic.fingerprint_set) {
                memcpy(ndEF->ssl.cert_fingerprint,
                    ndEFNFP.tls_quic.sha1_certificate_fingerprint,
                    ND_FLOW_TLS_HASH_LEN);
                flow_update = true;
                ndEF->ssl.cert_fingerprint_found = true;
                ndEF->flags.detection_updated = true;
            }

            if (ndEFNFP.tls_quic.advertised_alpns) {

                ProcessALPN(entry, true);

                free(ndEFNFP.tls_quic.advertised_alpns);
                ndEFNFP.tls_quic.advertised_alpns = NULL;
            }

            if (ndEFNFP.tls_quic.negotiated_alpn) {

                flow_update = ProcessALPN(entry, false);

                free(ndEFNFP.tls_quic.negotiated_alpn);
                ndEFNFP.tls_quic.negotiated_alpn = NULL;
            }
        break;
        case ND_PROTO_DNS:
            //nd_dprintf("DNS flow updated.\n");
            break;
        case ND_PROTO_MDNS:
            if (ndEF->HasMDNSDomainName()) {
                flow_update = true;
                ndEF->flags.detection_updated = true;
            }
            //nd_dprintf("mDNS flow updated: %s, %s, %s\n",
            //    ndEF->host_server_name, ndEFNF->host_server_name, ndEF->mdns.domain_name);
            break;
        case ND_PROTO_LLMNR:
            //nd_dprintf("LLMNR flow updated.\n");
            break;
        default:
            break;
        }
    }
#if 0
    if (ndEF->detected_protocol == ND_PROTO_MDNS) {
        nd_dprintf("mDNS flow updated: packets: %lu, check extra packets: %s.\n",
            ndEF->stats.detection_packets.load(), (check_extra_packets) ? "yes" : "no");
    }
#endif
    // Flow detection complete.
    if (ndEF->flags.detection_init.load() && ! check_extra_packets)
        ndEF->flags.detection_complete = true;

    // Last updates, write to socket(s)...
    if (flow_update) FlowUpdate(entry);
}

bool ndDetectionThread::ProcessALPN(ndDetectionQueueEntry *entry, bool client)
{
    bool flow_update = false;
    const char *detected_alpn = (client) ?
        ndEFNFP.tls_quic.advertised_alpns : ndEFNFP.tls_quic.negotiated_alpn;
//    nd_dprintf("%s: TLS %s ALPN: %s\n",
//        tag.c_str(), (client) ? "client" : "server", detected_alpn);

    if (client) {
        stringstream ss(detected_alpn);

        while (ss.good()) {
            string alpn;
            getline(ss, alpn, ',');

            ndEF->tls_alpn.push_back(alpn);
        }

        flow_update = (ndEF->tls_alpn.size() > 0);
    }
    else {
        ndEF->tls_alpn_server.push_back(detected_alpn);

        //nd_dprintf("%s: TLS ALPN: search for: %s\n", tag.c_str(),
        //    detected_alpn);

        for (unsigned i = 0; ; i++) {
            if (nd_alpn_proto_map[i].alpn[0] == '\0') break;
            if (strncmp(detected_alpn,
                nd_alpn_proto_map[i].alpn, ND_TLS_ALPN_MAX)) continue;
            if (nd_alpn_proto_map[i].proto_id == ndEF->detected_protocol)
                continue;

            if ((ndGC_DEBUG && ndGC_VERBOSE)) {
                nd_dprintf("%s: TLS ALPN: refined: %s: %s -> %s\n",
                    tag.c_str(), detected_alpn,
                    ndEF->detected_protocol_name,
                    nd_proto_get_name(nd_alpn_proto_map[i].proto_id)
                );
            }

            ndEF->detected_protocol = nd_alpn_proto_map[i].proto_id;
            ndEF->detected_protocol_name = nd_proto_get_name(
                nd_alpn_proto_map[i].proto_id
            );

            flow_update = true;
            ndEF->flags.detection_updated = true;
            break;
        }
    }

    return flow_update;
}

void ndDetectionThread::ProcessFlow(ndDetectionQueueEntry *entry)
{
    ndi.addr_types.Classify(ndEF->lower_type, ndEF->lower_addr);
    ndi.addr_types.Classify(ndEF->upper_type, ndEF->upper_addr);

    if (dhc != NULL && ndEF->GetMasterProtocol() != ND_PROTO_DNS) {
        string hostname;

        if (ndEF->lower_type == ndAddr::atOTHER)
            ndEF->flags.dhc_hit = dhc->Lookup(ndEF->lower_addr, hostname);

        if (! ndEF->flags.dhc_hit.load() &&
            ndEF->upper_type == ndAddr::atOTHER) {
            ndEF->flags.dhc_hit = dhc->Lookup(ndEF->upper_addr, hostname);
        }

        if (ndEF->flags.dhc_hit.load()) {
            snprintf(
                ndEF->dns_host_name,
                sizeof(ndEF->dns_host_name) - 1,
                "%s", hostname.c_str()
            );
            if (ndEFNF->host_server_name[0] == '\0' ||
                nd_is_ipaddr((const char *)ndEFNF->host_server_name)) {
                snprintf(
                    (char *)ndEFNF->host_server_name,
                    sizeof(ndEFNF->host_server_name) - 1,
                    "%s", hostname.c_str()
                );
            }
        }
    }

    nd_set_hostname(
        ndEF->host_server_name, ndEFNF->host_server_name,
        min((size_t)ND_FLOW_HOSTNAME, (size_t)sizeof(ndEFNF->host_server_name))
    );

    // Determine application based on master protocol metadata for
    // Protocol / Application "Twins"
    switch (ndEF->detected_protocol) {

    case ND_PROTO_APPLE_PUSH:
        SetDetectedApplication(entry, ndi.apps.Lookup("netify.apple-push"));
        break;

    case ND_PROTO_AVAST:
        SetDetectedApplication(entry, ndi.apps.Lookup("netify.avast"));
        break;

    case ND_PROTO_LINE_CALL:
        SetDetectedApplication(entry, ndi.apps.Lookup("netify.line"));
        break;

    case ND_PROTO_NEST_LOG_SINK:
        SetDetectedApplication(entry, ndi.apps.Lookup("netify.nest"));
        break;

    case ND_PROTO_SPOTIFY:
        SetDetectedApplication(entry, ndi.apps.Lookup("netify.spotify"));
        break;

    case ND_PROTO_STEAM:
        SetDetectedApplication(entry, ndi.apps.Lookup("netify.steam"));
        break;

    case ND_PROTO_SYNCTHING:
        SetDetectedApplication(entry, ndi.apps.Lookup("netify.syncthing"));
        break;

    case ND_PROTO_TEAMVIEWER:
        SetDetectedApplication(entry, ndi.apps.Lookup("netify.teamviewer"));
        break;

    case ND_PROTO_TIVOCONNECT:
        SetDetectedApplication(entry, ndi.apps.Lookup("netify.tivo"));
        break;

    case ND_PROTO_TPLINK_SHP:
        SetDetectedApplication(entry, ndi.apps.Lookup("netify.tp-link"));
        break;

    case ND_PROTO_TUYA_LP:
        SetDetectedApplication(entry, ndi.apps.Lookup("netify.tuya-smart"));
        break;

    case ND_PROTO_UBNTAC2:
        SetDetectedApplication(entry, ndi.apps.Lookup("netify.ubiquiti"));
        break;

    case ND_PROTO_ZOOM:
        SetDetectedApplication(entry, ndi.apps.Lookup("netify.zoom"));
        break;

    default:
        break;
    }

    // Determine application by host_server_name if still unknown.
    if (ndEF->detected_application == ND_APP_UNKNOWN) {
        if (ndEF->host_server_name[0] != '\0')
            SetDetectedApplication(entry, ndi.apps.Find(ndEF->host_server_name));
    }

    // Determine application by dns_host_name if still unknown.
    if (ndEF->detected_application == ND_APP_UNKNOWN) {
        if (ndEF->dns_host_name[0] != '\0')
            SetDetectedApplication(entry, ndi.apps.Find(ndEF->dns_host_name));
    }

    // Determine application by network CIDR if still unknown.
    // DNS flows excluded...
    if (ndEF->GetMasterProtocol() != ND_PROTO_DNS &&
        ndEF->detected_application == ND_APP_UNKNOWN) {

        if (ndEF->lower_type == ndAddr::atOTHER) {
            SetDetectedApplication(entry, ndi.apps.Find(ndEF->lower_addr));

            if (ndEF->detected_application == ND_APP_UNKNOWN)
                SetDetectedApplication(entry, ndi.apps.Find(ndEF->upper_addr));
        }
        else {
            SetDetectedApplication(entry, ndi.apps.Find(ndEF->upper_addr));

            if (ndEF->detected_application == ND_APP_UNKNOWN)
                SetDetectedApplication(entry, ndi.apps.Find(ndEF->lower_addr));
        }
    }

    // Additional protocol-specific processing...
    switch (ndEF->GetMasterProtocol()) {

    case ND_PROTO_TLS:
    case ND_PROTO_QUIC:
        ndEF->ssl.version =
            ndEFNFP.tls_quic.ssl_version;
        ndEF->ssl.cipher_suite =
            ndEFNFP.tls_quic.server_cipher;

        ndEF->ssl.client_sni = ndEF->host_server_name;

        if (ndEF->ssl.server_cn[0] == '\0' &&
            ndEFNFP.tls_quic.serverCN != NULL) {
            nd_set_hostname(
                ndEF->ssl.server_cn,
                ndEFNFP.tls_quic.serverCN,
                ND_FLOW_TLS_CNLEN
            );
            free(ndEFNFP.tls_quic.serverCN);
            ndEFNFP.tls_quic.serverCN = NULL;

            // Detect application by server CN if still unknown.
            if (ndEF->detected_application == ND_APP_UNKNOWN)
                SetDetectedApplication(entry, ndi.apps.Find(ndEF->ssl.server_cn));
        }

        if (ndEF->ssl.issuer_dn == NULL &&
            ndEFNFP.tls_quic.issuerDN != NULL) {
            ndEF->ssl.issuer_dn = strdup(ndEFNFP.tls_quic.issuerDN);
            free(ndEFNFP.tls_quic.issuerDN);
            ndEFNFP.tls_quic.issuerDN = NULL;
        }

        if (ndEF->ssl.subject_dn == NULL &&
            ndEFNFP.tls_quic.subjectDN != NULL) {
            ndEF->ssl.subject_dn = strdup(ndEFNFP.tls_quic.subjectDN);
            free(ndEFNFP.tls_quic.subjectDN);
            ndEFNFP.tls_quic.subjectDN = NULL;
        }

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
        if (ndEFNF->http.user_agent != NULL &&
            strnlen(ndEFNF->http.user_agent, ND_FLOW_UA_LEN) != 0) {
            ndEF->ssdp.headers["user-agent"].assign(
                ndEFNF->http.user_agent,
                strnlen(ndEFNF->http.user_agent, ND_FLOW_UA_LEN)
            );
        }
        break;
    case ND_PROTO_BITTORRENT:
#if 0
        if (ndEFNFP.bittorrent.hash_valid) {
            ndEF->bt.info_hash_valid = true;
            memcpy(
                ndEF->bt.info_hash,
                ndEFNFP.bittorrent.hash,
                ND_FLOW_BTIHASH_LEN
            );
        }
#endif
        break;
    default:
        break;
    }

    if (fhc != NULL &&
        ndEF->lower_addr.GetPort(false) != 0 && ndEF->upper_addr.GetPort(false) != 0) {

        flow_digest.assign(
            (const char *)ndEF->digest_lower, SHA1_DIGEST_LENGTH);

        if (! fhc->Pop(flow_digest, flow_digest_mdata)) {

            ndEF->Hash(tag, true);

            flow_digest_mdata.assign(
                (const char *)ndEF->digest_mdata, SHA1_DIGEST_LENGTH
            );

            if (memcmp(ndEF->digest_lower, ndEF->digest_mdata,
                SHA1_DIGEST_LENGTH))
                fhc->Push(flow_digest, flow_digest_mdata);
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
    else ndEF->Hash(tag, true);

    for (int t = ndFlow::TYPE_LOWER; t < ndFlow::TYPE_MAX; t++) {
        const ndAddr *mac, *ip;
        ndAddr::Type type = ndAddr::atNONE;

        if (t == ndFlow::TYPE_LOWER && (
            ndEF->lower_type == ndAddr::atLOCAL ||
            ndEF->lower_type == ndAddr::atLOCALNET ||
            ndEF->lower_type == ndAddr::atRESERVED)) {

            ndi.addr_types.Classify(type, ndEF->lower_mac);

            mac = &ndEF->lower_mac;
            ip = &ndEF->lower_addr;
        }
        else if (t == ndFlow::TYPE_UPPER && (
            ndEF->upper_type == ndAddr::atLOCAL ||
            ndEF->upper_type == ndAddr::atLOCALNET ||
            ndEF->upper_type == ndAddr::atRESERVED)) {

            ndi.addr_types.Classify(type, ndEF->upper_mac);

            mac = &ndEF->upper_mac;
            ip = &ndEF->upper_addr;
        }
        else continue;

        if (type != ndAddr::atOTHER ||
            mac == nullptr || ip == nullptr) continue;

        ndEF->iface.PushEndpoint(*mac, *ip);
    }

#ifdef _ND_USE_CONNTRACK
    if (thread_conntrack != NULL &&
        ndEF->iface.role != ndIR_LAN) {

        if ((ndEF->lower_type == ndAddr::atLOCAL &&
            ndEF->upper_type == ndAddr::atOTHER ) ||
            (ndEF->lower_type == ndAddr::atOTHER &&
            ndEF->upper_type == ndAddr::atLOCAL)) {

            // Update flow with any collected information from the
            // connection tracker (CT ID, mark, NAT'd).
            thread_conntrack->UpdateFlow(ndEF);
        }
    }
#endif
    ndEF->detected_protocol_name = nd_proto_get_name(
        ndEF->detected_protocol
    );

    if (ndEF->detected_protocol != ND_PROTO_UNKNOWN) {
        ndEF->category.protocol = ndi.categories.Lookup(
            ndCAT_TYPE_PROTO,
            (unsigned)ndEF->detected_protocol
        );
    }

    if (ndEFNF->host_server_name[0] != '\0') {
        ndEF->category.domain = ndi.domains.Lookup(
            ndEFNF->host_server_name
        );
#ifdef _ND_LOG_DOMAIN_LOOKUPS
        nd_dprintf("%s: category.domain: %hu\n",
            tag.c_str(), ndEF->category.domain);
#endif
    }

    ndEF->UpdateLowerMaps();

    for (vector<uint8_t *>::const_iterator i =
        ndGC.privacy_filter_mac.begin();
        i != ndGC.privacy_filter_mac.end() &&
            ndEF->privacy_mask !=
            (ndFlow::PRIVATE_LOWER | ndFlow::PRIVATE_UPPER); i++) {
#if defined(__linux__)
        if (! memcmp((*i), ndEF->lower_mac.addr.ll.sll_addr, ETH_ALEN))
            ndEF->privacy_mask |= ndFlow::PRIVATE_LOWER;
        if (! memcmp((*i), ndEF->upper_mac.addr.ll.sll_addr, ETH_ALEN))
            ndEF->privacy_mask |= ndFlow::PRIVATE_UPPER;
#elif defined(__FreeBSD__)
        if (! memcmp((*i), LLADDR(&ndEF->lower_mac.addr.dl), ETH_ALEN))
            ndEF->privacy_mask |= ndFlow::PRIVATE_LOWER;
        if (! memcmp((*i), LLADDR(&ndEF->upper_mac.addr.dl), ETH_ALEN))
            ndEF->privacy_mask |= ndFlow::PRIVATE_UPPER;
#endif
    }

    for (vector<struct sockaddr *>::const_iterator i =
        ndGC.privacy_filter_host.begin();
        i != ndGC.privacy_filter_host.end() &&
            ndEF->privacy_mask !=
            (ndFlow::PRIVATE_LOWER | ndFlow::PRIVATE_UPPER); i++) {

        struct sockaddr_in *sa_in;
        struct sockaddr_in6 *sa_in6;

        switch ((*i)->sa_family) {
        case AF_INET:
            sa_in = reinterpret_cast<struct sockaddr_in *>((*i));
            if (! memcmp(&ndEF->lower_addr.addr.in.sin_addr, &sa_in->sin_addr,
                sizeof(struct in_addr)))
                ndEF->privacy_mask |= ndFlow::PRIVATE_LOWER;
            if (! memcmp(&ndEF->upper_addr.addr.in.sin_addr, &sa_in->sin_addr,
                sizeof(struct in_addr)))
                ndEF->privacy_mask |= ndFlow::PRIVATE_UPPER;
            break;
        case AF_INET6:
            sa_in6 = reinterpret_cast<struct sockaddr_in6 *>((*i));
            if (! memcmp(&ndEF->lower_addr.addr.in6.sin6_addr, &sa_in6->sin6_addr,
                sizeof(struct in6_addr)))
                ndEF->privacy_mask |= ndFlow::PRIVATE_LOWER;
            if (! memcmp(&ndEF->upper_addr.addr.in6.sin6_addr, &sa_in6->sin6_addr,
                sizeof(struct in6_addr)))
                ndEF->privacy_mask |= ndFlow::PRIVATE_UPPER;
            break;
        }

        // TODO: Update the text IP addresses that were set above...
    }

    ndEF->flags.detection_init = true;
}

void ndDetectionThread::SetDetectedApplication(ndDetectionQueueEntry *entry, nd_app_id_t app_id)
{
    if (app_id == ND_APP_UNKNOWN) return;
    ndEF->detected_application = app_id;
    const char *name = ndi.apps.Lookup(app_id);

    if (ndEF->detected_application_name != NULL) {
        ndEF->detected_application_name = (char *)realloc(
            ndEF->detected_application_name,
            strlen(name) + 1
        );

        strcpy(ndEF->detected_application_name, name);
    }
    else
        ndEF->detected_application_name = strdup(name);

    ndEF->category.application = ndi.categories.Lookup(
        ndCAT_TYPE_APP, app_id
    );
}

void ndDetectionThread::FlowUpdate(ndDetectionQueueEntry *entry)
{
    if (ndEF->category.application == ND_CAT_UNKNOWN &&
        ndEF->detected_application != ND_APP_UNKNOWN) {

        ndEF->category.application = ndi.categories.Lookup(
            ndCAT_TYPE_APP,
            (unsigned)ndEF->detected_application
        );
    }

    if (ndEF->category.protocol == ND_CAT_UNKNOWN &&
        ndEF->detected_protocol != ND_PROTO_UNKNOWN) {

        ndEF->category.protocol = ndi.categories.Lookup(
            ndCAT_TYPE_PROTO,
            (unsigned)ndEF->detected_protocol
        );
    }

    if (ndEF->category.domain == ND_DOMAIN_UNKNOWN &&
        ndEFNF->host_server_name[0] != '\0') {

        ndEF->category.domain = ndi.domains.Lookup(
            ndEFNF->host_server_name
        );
    }

    if (ndGC_SOFT_DISSECTORS) {

        ndSoftDissector nsd;

        if (ndi.apps.SoftDissectorMatch(ndEF, &parser, nsd)) {

            ndEF->flags.soft_dissector = true;
            ndEF->flags.detection_complete = true;

            if (nsd.aid > -1) {
                if (nsd.aid == ND_APP_UNKNOWN) {
                    ndEF->detected_application = 0;
                    if (ndEF->detected_application_name != NULL) {
                        free(ndEF->detected_application_name);
                        ndEF->detected_application_name = NULL;
                    }
                    ndEF->category.application = ND_CAT_UNKNOWN;
                }
                else
                    SetDetectedApplication(entry, (nd_app_id_t)nsd.aid);
            }

            if (nsd.pid > -1) {
                ndEF->detected_protocol = (nd_proto_id_t)nsd.pid;

                ndEF->category.protocol = ndi.categories.Lookup(
                    ndCAT_TYPE_PROTO,
                    (unsigned)ndEF->detected_protocol
                );
                ndEF->detected_protocol_name = nd_proto_get_name(
                    ndEF->detected_protocol
                );
            }
        }
    }

    if ((ndGC_DEBUG && ndGC_VERBOSE) || ndGC.h_flow != stderr)
        ndEF->Print();

    ndi.plugins.BroadcastProcessorEvent(
        (ndEF->flags.detection_updated.load()) ?
            ndPluginProcessor::EVENT_FLOW_UPDATED :
            ndPluginProcessor::EVENT_FLOW_NEW,
        ndEF
    );
}

void ndDetectionThread::SetGuessedProtocol(ndDetectionQueueEntry *entry)
{
    uint8_t guessed = 0;
    ndpi_protocol ndpi_rc = ndpi_detection_giveup(
        ndpi,
        ndEFNF,
        1, &guessed
    );

    if (guessed) {
        ndEF->detected_protocol = nd_ndpi_proto_find(
            ndpi_rc.master_protocol,
            ndEF
        );

        if (ndEF->detected_protocol == ND_PROTO_UNKNOWN) {
            ndEF->detected_protocol = nd_ndpi_proto_find(
                ndpi_rc.app_protocol,
                ndEF
            );
        }
    }

    ndEF->flags.detection_init = true;
    ndEF->flags.detection_guessed = true;
    ndEF->flags.detection_complete = true;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
