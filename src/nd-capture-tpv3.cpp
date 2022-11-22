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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include <net/if.h>
#include <net/ethernet.h>

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

#include <linux/if_packet.h>

#ifdef _ND_USE_CONNTRACK
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#endif

#include <pcap/pcap.h>
#ifdef HAVE_PCAP_VLAN_H
#include <pcap/vlan.h>
#else
#include "pcap-compat/vlan.h"
#endif

#include <nlohmann/json.hpp>
using json = nlohmann::json;

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
#include "nd-capture-tpv3.h"

#define _ND_VLAN_OFFSET         (2 * ETH_ALEN)

extern ndGlobalConfig nd_config;

class ndPacketRing;
class ndPacketRingBlock
{
public:
    ndPacketRingBlock(void *entry);

    inline uint32_t GetStatus(void) {
        return hdr.bdh->hdr.bh1.block_status;
    }

    inline void SetStatus(uint32_t status = TP_STATUS_KERNEL) {
        hdr.bdh->hdr.bh1.block_status = status;
    }

    inline void Release(void) {
        hdr.bdh->hdr.bh1.block_status = TP_STATUS_KERNEL;
    }

    size_t ProcessPackets(ndPacketRing *ring,
        vector<ndPacket *> &pkt_queue);

protected:
    friend class ndPacket;
    friend class ndPacketRing;

    union {
        uint8_t *raw;
        struct tpacket_block_desc *bdh;
    } hdr;
};

typedef vector<ndPacketRingBlock *> ndPacketRingBlocks;

class ndPacketRing
{
public:
    ndPacketRing(const string &ifname, ndPacketStats *stats);

    virtual ~ndPacketRing();

    inline int GetDescriptor(void) { return sd; }

    bool SetFilter(const string &expr);
    bool ApplyFilter(const uint8_t *pkt, size_t snaplen, size_t length) const;

    ndPacketRingBlock *Next(void);

    ndPacket *CopyPacket(void *entry,
        ndPacket::status_flags &status);

    bool GetStats(void);

protected:
    friend class ndPacket;
    friend class ndPacketRingBlock;

    string ifname;
    int sd;
    void *buffer;
    ndPacketRingBlocks blocks;
    ndPacketRingBlocks::iterator it_block;

    size_t tp_hdr_len;
    size_t tp_reserved;
    size_t tp_frame_size;
    size_t tp_ring_size;

    struct tpacket_req3 tp_req;

    struct bpf_program filter;

    ndPacketStats *stats;
};

ndPacketRingBlock::ndPacketRingBlock(void *entry)
{
    hdr.raw = static_cast<uint8_t *>(entry);
    hdr.bdh = static_cast<struct tpacket_block_desc *>(entry);
}

size_t ndPacketRingBlock::ProcessPackets(ndPacketRing *ring,
    vector<ndPacket *> &pkt_queue)
{
    struct tpacket3_hdr *entry;
    entry = (struct tpacket3_hdr *)(hdr.raw + hdr.bdh->hdr.bh1.offset_to_first_pkt);

    size_t packets = (size_t)hdr.bdh->hdr.bh1.num_pkts;

    for (size_t i = 0; i < packets; i++) {

        ndPacket::status_flags status;
        ndPacket *pkt = ring->CopyPacket(entry, status);

        if (status & ndPacket::STATUS_FILTERED)
            ring->stats->pkt.capture_filtered++;

        if (! (status & ndPacket::STATUS_OK)) {
            ring->stats->pkt.discard++;
            // TODO: ring->stats->pkt.discard_bytes +=
        }

        if (pkt != nullptr) pkt_queue.push_back(pkt);

        entry = (struct tpacket3_hdr *)((uint8_t *)entry + entry->tp_next_offset);
    }

    return packets;
}

ndPacketRing::ndPacketRing(
    const string &ifname, ndPacketStats *stats)
    : ifname(ifname), sd(-1), buffer(nullptr),
    tp_hdr_len(0), tp_reserved(0),
    tp_frame_size(0), tp_ring_size(0),
    tp_req{0}, filter{0}, stats(stats)
{
    unsigned so_uintval;

    struct ifreq ifr;
    if (nd_ifreq(ifname.c_str(), SIOCGIFINDEX, &ifr) < 0)
        throw ndCaptureThreadException("error getting interface index");

    sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (sd < 0) {
        nd_dprintf("%s: socket: %s\n", ifname.c_str(), strerror(errno));
        throw ndCaptureThreadException("error creating socket");
    }

    nd_dprintf("%s: AF_PACKET socket created: %d\n", ifname.c_str(), sd);

    so_uintval = TPACKET_V3;
    socklen_t so_vallen = sizeof(so_uintval);
    if (getsockopt(sd, SOL_PACKET, PACKET_HDRLEN,
        (void *)&so_uintval, &so_vallen) < 0) {
        nd_dprintf("%s: getsockopt(PACKET_HDRLEN): %s\n",
            ifname.c_str(), strerror(errno));
        throw ndCaptureThreadException("TPACKET_V3 not supported");
    }

    tp_hdr_len = (size_t)so_uintval;
    nd_dprintf("%s: TPACKET_V3 header length: %ld\n",
        ifname.c_str(), tp_hdr_len);

    so_uintval = TPACKET_V3;
    if (setsockopt(sd, SOL_PACKET, PACKET_VERSION,
        (const void *)&so_uintval, sizeof(so_uintval)) < 0) {
        nd_dprintf("%s: setsockopt(PACKET_VERSION): TPACKET_V3: %s\n",
            ifname.c_str(), strerror(errno));
        throw ndCaptureThreadException("error selecting TPACKET_V3");
    }

    struct sockaddr_ll sa_ll_bind;
    memset(&sa_ll_bind, 0, sizeof(struct sockaddr_ll));
    sa_ll_bind.sll_family = AF_PACKET;
    sa_ll_bind.sll_protocol = htons(ETH_P_ALL);
    sa_ll_bind.sll_ifindex = ifr.ifr_ifindex;

    if (bind(sd,
        (const struct sockaddr *)&sa_ll_bind,
        sizeof(struct sockaddr_ll)) < 0) {
        nd_dprintf("%s: bind: %s\n", ifname.c_str(), strerror(errno));
        throw ndCaptureThreadException("unable to bind socket to interface");
    }

    nd_dprintf("%s: AF_PACKET socket bound to: %s [%d]\n",
        ifname.c_str(), ifname.c_str(), ifr.ifr_ifindex);

    struct packet_mreq pmreq;
    memset(&pmreq, 0, sizeof(struct packet_mreq));
    pmreq.mr_ifindex = ifr.ifr_ifindex;

    const vector<short> pmreq_types = {
        PACKET_MR_PROMISC,
        PACKET_MR_ALLMULTI
    };

    for (unsigned i = 0; i < pmreq_types.size(); i++) {
        pmreq.mr_type = pmreq_types[i];

        if (setsockopt(sd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
            (const void *)&pmreq, sizeof(struct packet_mreq)) < 0) {
            nd_dprintf("%s: setsockopt(PACKET_ADD_MEMBERSHIP:%hu): %s\n",
                ifname.c_str(), pmreq.mr_type, strerror(errno));
            throw ndCaptureThreadException("error while adding membership(s)");
        }
    }
#ifdef PACKET_FANOUT
    if (ND_TPV3_FANOUT) {
        so_uintval = (PACKET_FANOUT_HASH |
            PACKET_FANOUT_FLAG_DEFRAG | PACKET_FANOUT_FLAG_ROLLOVER) << 16 |
            (uint16_t)ifr.ifr_ifindex;

        nd_dprintf("%s: fanout options and flags: 0x%08x\n", ifname.c_str(), so_uintval);

        if (setsockopt(sd, SOL_PACKET, PACKET_FANOUT,
            (const void *)&so_uintval, sizeof(so_uintval)) < 0) {
            nd_dprintf("%s: setsockopt(PACKET_FANOUT): %s\n", ifname.c_str(), strerror(errno));
            throw ndCaptureThreadException("error enabling fanout");
        }
    }
#else
#warning "PACKET_FANOUT not supported."
#endif
    so_uintval = sizeof(struct vlan_tag);
    if (setsockopt(sd, SOL_PACKET, PACKET_RESERVE,
        (const void *)&so_uintval, sizeof(so_uintval)) < 0) {
        nd_dprintf("%s: setsockopt(PACKET_RESERVE): %s\n", ifname.c_str(), strerror(errno));
        throw ndCaptureThreadException("error reserving VLAN TAG space");
    }

    so_uintval = 0;
    so_vallen = sizeof(so_uintval);
    if (getsockopt(sd, SOL_PACKET, PACKET_RESERVE,
        (void *)&so_uintval, &so_vallen) < 0) {
        nd_dprintf("%s: getsockopt(PACKET_RESERVE): %s\n", ifname.c_str(), strerror(errno));
        throw ndCaptureThreadException("error getting reserved VLAN TAG size");
    }

    tp_reserved = (size_t)so_uintval;
    if (tp_reserved != sizeof(struct vlan_tag)) {
        nd_dprintf("%s: PACKET_RESERVE: unexpected size: %lu != %u\n", ifname.c_str(),
            tp_reserved, sizeof(struct vlan_tag)
        );
        throw ndCaptureThreadException("unexpected reserved VLAN TAG size");
    }

    tp_req.tp_block_size = nd_config.tpv3_rb_block_size;
    tp_req.tp_frame_size = nd_config.tpv3_rb_frame_size;
    tp_req.tp_block_nr = nd_config.tpv3_rb_blocks;
    tp_req.tp_frame_nr =
        (tp_req.tp_block_size * tp_req.tp_block_nr) /
            tp_req.tp_frame_size;
    tp_req.tp_retire_blk_tov = ND_TPV3_READ_TIMEOUT;
    //tp_req.tp_feature_req_word = // TODO: Features?

    nd_dprintf("%s: block size: %u\n", ifname.c_str(), tp_req.tp_block_size);
    nd_dprintf("%s: frame size: %u\n", ifname.c_str(), tp_req.tp_frame_size);
    nd_dprintf("%s: blocks: %u\n", ifname.c_str(), tp_req.tp_block_nr);
    nd_dprintf("%s: frames: %u\n", ifname.c_str(), tp_req.tp_frame_nr);

    if (setsockopt(sd, SOL_PACKET, PACKET_RX_RING,
        (const void *)&tp_req, sizeof(struct tpacket_req3)) < 0) {
        nd_dprintf("%s: setsockopt(PACKET_RX_RING): %s\n",
            ifname.c_str(), strerror(errno));
        throw ndCaptureThreadException("error requesting RX ring");
    }

    buffer = mmap(0, tp_req.tp_block_size * tp_req.tp_block_nr,
        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, sd, 0);
    if (buffer == MAP_FAILED) {
        nd_dprintf("%s: mmap(%u): %s\n", ifname.c_str(),
            tp_req.tp_block_size * tp_req.tp_block_nr, strerror(errno)
        );
        throw ndCaptureThreadException("error mapping RX ring");
    }

    for (unsigned b = 0; b < tp_req.tp_block_nr; b++) {
        ndPacketRingBlock *entry = new ndPacketRingBlock(
            (void *)(((size_t)buffer) + (b * tp_req.tp_block_size))
        );
        blocks.push_back(entry);
    }

    it_block = blocks.begin();

    nd_dprintf("%s: created %lu packet ring blocks.\n",
        ifname.c_str(), blocks.size()
    );
}

ndPacketRing::~ndPacketRing()
{
    if (buffer) munmap(buffer, tp_ring_size);
    if (sd != -1) close(sd);
    for (auto &i : blocks) delete i;
}

bool ndPacketRing::SetFilter(const string &expr)
{
    if (pcap_compile_nopcap(
        ND_PCAP_SNAPLEN, DLT_EN10MB, &filter,
        expr.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
        nd_dprintf("pcap_compile_nopcap: %s: failed.\n",
            expr.c_str());
        return false;
    }

    return true;
}

bool ndPacketRing::ApplyFilter(const uint8_t *pkt,
    size_t length, size_t snaplen) const
{
    return (filter.bf_insns &&
        bpf_filter(filter.bf_insns, pkt, length, snaplen) == 0);
}

bool ndPacketRing::GetStats(void)
{
    struct tpacket_stats_v3 tp_stats;
    socklen_t so_vallen = sizeof(struct tpacket_stats_v3);

    memset(&tp_stats, 0, so_vallen);

    if (getsockopt(sd, SOL_PACKET, PACKET_STATISTICS,
        &tp_stats, &so_vallen) < 0) {
        nd_dprintf("%s: error getting packet statistics: %s\n",
            ifname.c_str(), strerror(errno));
        return false;
    }

    stats->pkt.capture_dropped = tp_stats.tp_drops;
    // TODO: tp_freeze_q_cnt?

    return true;
}

ndPacketRingBlock *ndPacketRing::Next(void)
{
    ndPacketRingBlock *block = nullptr;

    if ((*it_block)->hdr.bdh->hdr.bh1.block_status & TP_STATUS_USER) {
        block = (*it_block);

        if (++it_block == blocks.end())
            it_block = blocks.begin();
    }

    return block;
}

ndPacket *ndPacketRing::CopyPacket(void *entry,
    ndPacket::status_flags &status)
{
    struct tpacket3_hdr *hdr = (struct tpacket3_hdr *)entry;

    unsigned int tp_len, tp_mac, tp_snaplen;
    tp_len = hdr->tp_len;
    tp_mac = hdr->tp_mac;
    tp_snaplen = hdr->tp_snaplen;

    struct timeval tv = { hdr->tp_sec, hdr->tp_nsec / 1000 };

    status = ndPacket::STATUS_INIT;

    if (tp_len != tp_snaplen)
        nd_dprintf("tp_len: %u, tp_snaplen: %u\n", tp_len, tp_snaplen);

#if 0
    if (tp_mac + tp_snaplen > tp_req.tp_frame_size) {
        nd_dprintf("%s: Corrupted kernel ring frame: MAC offset: %u + snaplen: %u > frame_size: %u\n",
            ifname.c_str(), tp_mac, tp_snaplen,
            tp_req.tp_frame_size
        );

        status = ndPacket::STATUS_CORRUPTED;
        return nullptr;
    }
#endif
    uint8_t *data = (uint8_t *)entry + tp_mac;

    if ((hdr->hv1.tp_vlan_tci ||
        (hdr->tp_status & TP_STATUS_VLAN_VALID)) &&
            tp_snaplen >= (unsigned int)_ND_VLAN_OFFSET) {

        struct nd_vlan_tag {
            uint16_t vlan_tpid;
            uint16_t vlan_tci;
        };

        struct nd_vlan_tag *tag;

        data -= sizeof(struct vlan_tag);
        memmove((void *)data,
            data + sizeof(struct vlan_tag), _ND_VLAN_OFFSET);

        tag = (struct nd_vlan_tag *)(data + _ND_VLAN_OFFSET);

        if (hdr->hv1.tp_vlan_tpid &&
            (hdr->tp_status & TP_STATUS_VLAN_TPID_VALID))
            tag->vlan_tpid = htons(hdr->hv1.tp_vlan_tpid);
        else
            tag->vlan_tpid = htons(ETH_P_8021Q);

        tag->vlan_tci = htons(hdr->hv1.tp_vlan_tci);

        tp_snaplen += sizeof(struct vlan_tag);
        tp_len += sizeof(struct vlan_tag);

        status |= ndPacket::STATUS_VLAN_TAG_RESTORED;
    }

    if (ApplyFilter(data, tp_len, tp_snaplen)) {
        status = ndPacket::STATUS_FILTERED;
        return nullptr;
    }

    ndPacket *pkt = nullptr;
    // One-and-only packet copy...
    uint8_t *pkt_data = new uint8_t[tp_snaplen];

    if (pkt_data) {
        memcpy(pkt_data, data, tp_snaplen);
        pkt = new ndPacket(status,
            tp_len, tp_snaplen, pkt_data, tv);
    }

    if (pkt) status |= ndPacket::STATUS_OK;
    else status = ndPacket::STATUS_ENOMEM;

    return pkt;
}

ndCaptureTPv3::ndCaptureTPv3(
    int16_t cpu,
    const ndInterface &iface,
    const uint8_t *dev_mac,
    ndSocketThread *thread_socket,
    const nd_detection_threads &threads_dpi,
    ndDNSHintCache *dhc,
    uint8_t private_addr)
    :
    ring(nullptr),
    ndCaptureThread(ndCT_TPV3,
        (long)cpu, iface, dev_mac, thread_socket,
        threads_dpi, dhc, private_addr)
{
    dl_type = DLT_EN10MB;

    nd_dprintf("%s: TPv3 capture thread created.\n", tag.c_str());
}

ndCaptureTPv3::~ndCaptureTPv3()
{
    Join();

    ndPacketRing *_ring = static_cast<ndPacketRing *>(ring);
    if (_ring != nullptr) delete _ring;

    nd_dprintf("%s: TPv3 capture thread destroyed.\n", tag.c_str());
}

void *ndCaptureTPv3::Entry(void)
{
    fd_set fds_read;

    ndPacketRing *_ring = new ndPacketRing(iface.ifname, &stats);

    if (_ring == nullptr)
        throw runtime_error(strerror(ENOMEM));

    ring = static_cast<void *>(_ring);

    nd_device_filter::const_iterator it_filter;
    it_filter = nd_config.device_filters.find(tag);

    if (it_filter != nd_config.device_filters.end())
        _ring->SetFilter(it_filter->second);

    int sd_max = _ring->GetDescriptor();
//    int sd_max = max(fd_ipc[0], _ring->GetDescriptor());

    int rc = 0;
    struct timeval tv;
#if 0
    size_t max_queued = 0;
    size_t packets = 0, total_packets = 0;
#endif
    vector<ndPacket *> pkt_queue;
    pkt_queue.reserve(nd_config.tpv3_rb_blocks);

    while (! ShouldTerminate() && rc >= 0) {

        ndPacketRingBlock *entry = _ring->Next();

        if (entry == nullptr) {

            FD_ZERO(&fds_read);
//            FD_SET(fd_ipc[0], &fds_read);
            FD_SET(_ring->GetDescriptor(), &fds_read);

            tv.tv_sec = 1; tv.tv_usec = 0;
            rc = select(sd_max + 1, &fds_read, NULL, NULL, &tv);

            if (rc == -1)
                printf("select: %s\n", strerror(errno));
#if 0
            if (rc > 0 && FD_ISSET(fd_ipc[0], &fds_read)) {
                // TODO: Not used.
                uint32_t ipc_id = RecvIPC();
            }
#endif
            continue;
        }

        entry->ProcessPackets(_ring, pkt_queue);
        entry->Release();

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
                throw;
            }

            Unlock();

            pkt_queue.clear();
        }
    }

    nd_dprintf("%s: TPv3 capture ended on CPU: %lu\n",
        tag.c_str(), cpu >= 0 ? cpu : 0);

    return NULL;
}

void ndCaptureTPv3::GetCaptureStats(ndPacketStats &stats)
{
    ndCaptureThread::GetCaptureStats(stats);
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
