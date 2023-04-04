// Netify Agent
// Copyright (C) 2015-2023 eGloo Incorporated <http://www.egloo.ca>
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
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>

#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <netdb.h>
#include <resolv.h>
#include <ctype.h>

#define __FAVOR_BSD 1
#include <netinet/tcp.h>
#undef __FAVOR_BSD

#include <errno.h>

#include <arpa/inet.h>

#ifdef _ND_USE_CONNTRACK
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#endif

#include <libmnl/libmnl.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#ifndef NF_ACCEPT
#define NF_ACCEPT   1
#endif

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
#include "nd-protos.h"
#include "nd-category.h"
#include "nd-flow.h"
#include "nd-flow-map.h"
#include "nd-flow-parser.h"
#include "nd-thread.h"
#ifdef _ND_USE_CONNTRACK
#include "nd-conntrack.h"
#endif
#include "nd-socket.h"
#include "nd-dhc.h"
#include "nd-fhc.h"
#include "nd-signal.h"
#include "nd-detection.h"
#include "nd-capture.h"
#include "nd-capture-nfq.h"

static int ndCaptureNFQueue_Callback(
    const struct nlmsghdr *nlh, void *user)
{
    ndCaptureNFQueue *nfq = static_cast<ndCaptureNFQueue *>(user);
    const char *tag = nfq->GetTag().c_str();

    struct nlattr *attr[NFQA_MAX + 1] = { };
    if (nfq_nlmsg_parse(nlh, attr) < 0) {
        nd_printf("%s: Error parsing attributes: %s\n", tag,
            strerror(errno)
        );
        return MNL_CB_ERROR;
    }
#if 0
    for (unsigned i = 0; i < NFQA_MAX; i++)
        nd_dprintf("NFQA_%i: %p\n", i, attr[i]);
#endif
    if (attr[NFQA_PACKET_HDR] == nullptr) {
        nd_printf("%s: No packet header metadata set.\n", tag);
        return MNL_CB_ERROR;
    }

    struct nfqnl_msg_packet_hdr *pkt_hdr = nullptr;
    pkt_hdr = static_cast<struct nfqnl_msg_packet_hdr *>(
        mnl_attr_get_payload(attr[NFQA_PACKET_HDR])
    );
#if 0
    nd_dprintf("%s: pkt protocol: 0x%04x\n", tag,
        ntohs(pkt_hdr->hw_protocol));
#endif
    struct nfqnl_msg_packet_timestamp *pkt_ts = nullptr;
    if (attr[NFQA_TIMESTAMP] != nullptr) {
        pkt_ts = static_cast<struct nfqnl_msg_packet_timestamp *>(
            mnl_attr_get_payload(attr[NFQA_TIMESTAMP])
        );
    }

    struct nfqnl_msg_packet_hw *pkt_hwaddr = nullptr;
    if (attr[NFQA_HWADDR] != nullptr) {
        pkt_hwaddr = static_cast<struct nfqnl_msg_packet_hw *>(
            mnl_attr_get_payload(attr[NFQA_HWADDR])
        );
        if (pkt_hwaddr != nullptr) {
            nd_dprintf("%s: hwaddr[%hu]: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n",
                tag,
                pkt_hwaddr->hw_addrlen,
                pkt_hwaddr->hw_addr[0],
                pkt_hwaddr->hw_addr[1],
                pkt_hwaddr->hw_addr[2],
                pkt_hwaddr->hw_addr[3],
                pkt_hwaddr->hw_addr[4],
                pkt_hwaddr->hw_addr[5]
            );
        }
    }
#ifdef _ND_LOG_WARNINGS
    else
        nd_dprintf("%s: WARNING: no hardware address.\n", tag);
#endif
    uint16_t pkt_len = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
    void *payload = mnl_attr_get_payload(attr[NFQA_PAYLOAD]);
#ifdef _ND_LOG_PACKETS
    uint16_t x = 0;
    for (uint16_t i = 0; i < pkt_len; i++) {
        fprintf(stderr, " %02x", ((uint8_t *)payload)[i]);
        if (++x == 16) {
            x = 0;
            fprintf(stderr, "\n");
        }
    }
    fprintf(stderr, "\n");
#endif
    uint32_t skbinfo = attr[NFQA_SKB_INFO] ?
        ntohl(mnl_attr_get_u32(attr[NFQA_SKB_INFO])) : 0;

    uint32_t pkt_caplen = pkt_len;

    if (attr[NFQA_CAP_LEN])
        pkt_caplen = ntohl(mnl_attr_get_u32(attr[NFQA_CAP_LEN]));

    ndPacket *pkt = nullptr;
    // One-and-only packet copy...
    uint8_t *pkt_data = new uint8_t[
        sizeof(struct ether_header) + pkt_len
    ];
    if (pkt_data == nullptr) {
        throw ndSystemException(
            __PRETTY_FUNCTION__, "new pkt_data", errno
        );
    }

    struct ether_header *hdr_eth = (struct ether_header *)pkt_data;
    memset(hdr_eth, 0, sizeof(struct ether_addr));
    hdr_eth->ether_type = pkt_hdr->hw_protocol;
    if (pkt_hwaddr != nullptr) {
        memcpy(
            &hdr_eth->ether_shost[0], &pkt_hwaddr->hw_addr[0],
            ETH_ALEN
        );
    }

    struct timeval tv;

    if (pkt_ts == nullptr) {
#ifdef _ND_LOG_WARNINGS
        nd_dprintf("%s: WARNING: no packet timestamp.\n", tag);
#endif
        gettimeofday(&tv, NULL);
    }
    else {
        tv.tv_sec = (time_t)pkt_ts->sec;
        tv.tv_usec = (time_t)pkt_ts->usec;
    };

    uint8_t *pkt_offset = pkt_data + sizeof(struct ether_header);
    memcpy(pkt_offset, payload, pkt_len);

    pkt = new ndPacket(ndPacket::STATUS_OK,
        pkt_caplen, sizeof(struct ether_header) + pkt_len,
        pkt_data, tv
    );

    if (pkt != nullptr)
        nfq->PushPacket(pkt);
    else {
        throw ndSystemException(
            __PRETTY_FUNCTION__, "new ndPacket", errno
        );
    }

    if (skbinfo & NFQA_SKB_GSO)
        nd_dprintf("%s: GSO packet.\n", tag);

    struct nfgenmsg *nfg = static_cast<struct nfgenmsg *>(
        mnl_nlmsg_get_payload(nlh)
    );

    uint8_t buffer[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh_verdict = nfq_nlmsg_put((char *)buffer,
        NFQNL_MSG_VERDICT, ntohs(nfg->res_id)
    );

    nfq_nlmsg_verdict_put(
        nlh_verdict, ntohl(pkt_hdr->packet_id), NF_ACCEPT
    );

    if (mnl_socket_sendto(nfq->GetSocket(),
        nlh_verdict, nlh_verdict->nlmsg_len) < 0) {
            nd_printf("%s: Error setting verdict: %s\n",
                tag, strerror(errno));
        return MNL_CB_ERROR;
    }

    return MNL_CB_OK;
}

ndCaptureNFQueue::ndCaptureNFQueue(
    int16_t cpu,
    ndInterface& iface,
    ndSocketThread *thread_socket,
    const nd_detection_threads &threads_dpi,
    unsigned instance_id,
    ndDNSHintCache *dhc,
    uint8_t private_addr)
    :
    ndCaptureThread(ndCT_NFQ,
        (long)cpu, iface, thread_socket,
        threads_dpi, dhc, private_addr),
    nl(nullptr), port_id(0),
    buffer_size(0xffff + (MNL_SOCKET_BUFFER_SIZE / 2)),
    buffer(nullptr), dropped(0)
{
    dl_type = DLT_EN10MB;

    tag.append("#" + to_string(instance_id));

    queue_id = iface.config.nfq->queue_id + instance_id;

    nl = mnl_socket_open(NETLINK_NETFILTER);

    if (nl == nullptr) {
        throw ndSystemException(
            __PRETTY_FUNCTION__, "mnl_socket_open", errno
        );
    }

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        throw ndSystemException(
            __PRETTY_FUNCTION__, "mnl_socket_bind", errno
        );
    }

    port_id = mnl_socket_get_portid(nl);

    buffer = new uint8_t[buffer_size];

    if (buffer == nullptr) {
        throw ndSystemException(
            __PRETTY_FUNCTION__, "new buffer", errno
        );
    }

    struct nlmsghdr *nlh;

    nlh = nfq_nlmsg_put((char *)buffer, NFQNL_MSG_CONFIG, queue_id);
    nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);
    nfq_nlmsg_cfg_put_cmd(nlh, AF_INET6, NFQNL_CFG_CMD_BIND);

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        throw ndSystemException(
            __PRETTY_FUNCTION__, "mnl_socket_sendto", errno
        );
    }

    nlh = nfq_nlmsg_put((char *)buffer, NFQNL_MSG_CONFIG, queue_id);
    nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);

    long flags = NFQA_CFG_F_FAIL_OPEN | NFQA_CFG_F_GSO;
//    long flags = NFQA_CFG_F_FAIL_OPEN |
//        NFQA_CFG_F_CONNTRACK | NFQA_CFG_F_GSO;
    mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(flags));
    mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(flags));

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        throw ndSystemException(
            __PRETTY_FUNCTION__, "mnl_socket_sendto", errno
        );
    }

    //int enable = 1;
    //mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, &enable, sizeof(int));

    nd_dprintf("%s: NFQ capture thread created.\n", tag.c_str());
}

ndCaptureNFQueue::~ndCaptureNFQueue()
{
    Join();

    if (nl != nullptr) mnl_socket_close(nl);
    if (buffer != nullptr) delete [] buffer;

    nd_dprintf("%s: NFQ capture thread destroyed.\n", tag.c_str());
}

void *ndCaptureNFQueue::Entry(void)
{
    int rc = 0;
    struct timeval tv;
    int fd = mnl_socket_get_fd(nl);
    fd_set fds_read;

    capture_state = STATE_ONLINE;

    nd_dprintf("%s: NFQ capture started on CPU: %lu\n",
        tag.c_str(), cpu >= 0 ? cpu : 0);

    while (! ShouldTerminate()) {

        FD_ZERO(&fds_read);
        FD_SET(fd, &fds_read);

        memset(&tv, 0, sizeof(struct timeval));
        tv.tv_sec = 1;

        rc = select(fd + 1, &fds_read, NULL, NULL, &tv);

        if (rc == -1) {
            throw ndSystemException(
                __PRETTY_FUNCTION__, "select", errno);
        }

        if (rc == 0 || ! FD_ISSET(fd, &fds_read)) continue;

        rc = mnl_socket_recvfrom(nl, (char *)buffer, buffer_size);

        if (rc == -1) {
            if (errno == ENOBUFS) {
                dropped++;
                continue;
            }
            else {
                nd_printf("%s: Error receiving NFQUEUE data: %s\n",
                    tag.c_str(), strerror(errno)
                );
                break;
            }
        }

        rc = mnl_cb_run(
            (char *)buffer, rc, 0, port_id,
            ndCaptureNFQueue_Callback, static_cast<void *>(this)
        );

        if (rc < 0) {
            nd_printf("%s: Error processing NFQUEUE data: %s\n",
                tag.c_str(), strerror(errno)
            );
            break;
        }

        if (pkt_queue.size()) {

            Lock();

            try {
                for (auto &pkt : pkt_queue) {
                    if (ProcessPacket(pkt) != nullptr)
                        delete pkt;
                }
            }
            catch (...) {
                Unlock();
                capture_state = STATE_OFFLINE;
                throw;
            }

            Unlock();

            pkt_queue.clear();
        }
    }

    capture_state = STATE_OFFLINE;

    nd_dprintf("%s: NFQ capture ended on CPU: %lu\n",
        tag.c_str(), cpu >= 0 ? cpu : 0);

    return NULL;
}

void ndCaptureNFQueue::GetCaptureStats(ndPacketStats &stats)
{
    stats.pkt.capture_dropped = dropped;

    dropped = 0;

    ndCaptureThread::GetCaptureStats(stats);
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
