#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include <arpa/inet.h>

#include <linux/if_packet.h>

//#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>

#include <pcap/pcap.h>

#define IF_NAME                 "eth0"
#define IF_FILTER               "not port 22"
#define IF_SNAPLEN              2048 // XXX: Only used by bpf_filter

// Default ring buffer size in MB
#define _ND_RING_BUFFER_SIZE    4
//#define _ND_RING_BUFFER_SIZE    128

#define VLAN_TAG_LEN            4
#define VLAN_OFFSET             (2 * ETH_ALEN)

#ifndef likely
#define likely(x)               __builtin_expect(!!(x), 1)
#endif

static sig_atomic_t sigint = 0;

static void sighandler(int num)
{
    sigint = 1;
}

static int nd_ifreq(const char *name, unsigned long request, struct ifreq *ifr)
{
    int fd, rc = -1;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        printf("%s: error creating ifreq socket: %s\n",
            name, strerror(errno));
            return rc;
    }

    memset(ifr, '\0', sizeof(struct ifreq));
    strncpy(ifr->ifr_name, name, IFNAMSIZ - 1);

    if (ioctl(fd, request, (char *)ifr) == -1) {
        printf("%s: error sending interface request: %s\n",
            name, strerror(errno));
    }
    else rc = 0;

    close(fd);
    return rc;
}

#include <string>
#include <stdexcept>
#include <vector>

using namespace std;

typedef struct {
    size_t packets;
    size_t dropped;
    size_t filtered;
    size_t discarded;
} ndPacketCaptureStats;

class ndPacket;
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

    size_t ProcessPackets(ndPacketRing *ring);

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
    ndPacketRing(const string &ifname,
        size_t ring_buffer_size = _ND_RING_BUFFER_SIZE);

    virtual ~ndPacketRing();

    inline int GetDescriptor(void) { return sd; }

    bool SetFilter(const string &expr);
    bool ApplyFilter(const uint8_t *pkt, size_t snaplen, size_t length) const;

    bool GetStats(ndPacketCaptureStats &stats);

    ndPacketRingBlock *Next(void);

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
    size_t tp_snaplen;
    size_t tp_frame_size;
    size_t tp_ring_size;

    struct tpacket_req3 tp_req;

    struct bpf_program filter;

    ndPacketCaptureStats pkt_stats;
};

class ndPacket
{
public:
    enum {
        STATUS_INIT = 0,

        STATUS_OK = 0x01,
        STATUS_CORRUPTED = 0x02,
        STATUS_FILTERED = 0x04,
        STATUS_VLAN_TAG_RESTORED = 0x08,

        STATUS_ENOMEM = 0x40,
        STATUS_LOCKED = 0x80
    };

    typedef uint8_t status_flags;

    ndPacket(
        const status_flags &status,
        const uint16_t &length, const uint16_t &captured,
        uint8_t *data)
        : status(status), length(length), captured(captured),
        data(data) { }

    virtual ~ndPacket() {
        if (data != nullptr) delete [] data;
        status = STATUS_INIT;
    }

    static ndPacket *Create(
        const ndPacketRing *ring,
        void *entry,
        status_flags &status
    );

protected:
    status_flags status;
    uint16_t length;
    uint16_t captured;
    uint8_t *data;
};

ndPacketRingBlock::ndPacketRingBlock(void *entry)
{
    hdr.raw = static_cast<uint8_t *>(entry);
    hdr.bdh = static_cast<struct tpacket_block_desc *>(entry);
}

size_t ndPacketRingBlock::ProcessPackets(ndPacketRing *ring)
{
    struct tpacket3_hdr *entry;
    entry = (struct tpacket3_hdr *)(hdr.raw + hdr.bdh->hdr.bh1.offset_to_first_pkt);
    
    size_t packets = (size_t)hdr.bdh->hdr.bh1.num_pkts;
    ring->pkt_stats.packets += packets;

    for (size_t i = 0; i < packets; i++) {

        ndPacket::status_flags status;
        ndPacket *pkt = ndPacket::Create(ring, entry, status);

        if (status & ndPacket::STATUS_FILTERED)
            ring->pkt_stats.filtered++;

        if (! (status & ndPacket::STATUS_OK))
            ring->pkt_stats.discarded++;

        if (pkt != nullptr) delete pkt;

        entry = (struct tpacket3_hdr *)((uint8_t *)entry + entry->tp_next_offset);
    }

    return packets;
}

ndPacketRing::ndPacketRing(
    const string &ifname, size_t ring_buffer_size)
    : ifname(ifname), sd(-1), buffer(nullptr),
    tp_hdr_len(0), tp_reserved(0), tp_snaplen(IF_SNAPLEN),
    tp_frame_size(0), tp_ring_size(0),
    tp_req{0}, filter{0}, pkt_stats{0}
{
    unsigned so_uintval;

    struct ifreq ifr;
    if (nd_ifreq(ifname.c_str(), SIOCGIFINDEX, &ifr) < 0)
        throw runtime_error("error getting interface index");

    sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (sd < 0) {
        printf("%s: socket: %s\n", ifname.c_str(), strerror(errno));
        throw runtime_error("error creating socket");
    }

    printf("%s: AF_PACKET socket created: %d\n", ifname.c_str(), sd);

    so_uintval = TPACKET_V3;
    socklen_t so_vallen = sizeof(so_uintval);
    if (getsockopt(sd, SOL_PACKET, PACKET_HDRLEN,
        (void *)&so_uintval, &so_vallen) < 0) {
        printf("%s: getsockopt(PACKET_HDRLEN): %s\n",
            ifname.c_str(), strerror(errno));
        throw runtime_error("TPACKET_V3 not supported");
    }

    tp_hdr_len = (size_t)so_uintval;
    printf("%s: TPACKET_V3 header length: %ld\n",
        ifname.c_str(), tp_hdr_len);

    so_uintval = TPACKET_V3;
    if (setsockopt(sd, SOL_PACKET, PACKET_VERSION,
        (const void *)&so_uintval, sizeof(so_uintval)) < 0) {
        printf("%s: setsockopt(PACKET_VERSION): TPACKET_V3: %s\n",
            ifname.c_str(), strerror(errno));
        throw runtime_error("error selecting TPACKET_V3");
    }

    struct sockaddr_ll sa_ll_bind;
    memset(&sa_ll_bind, 0, sizeof(struct sockaddr_ll));
    sa_ll_bind.sll_family = AF_PACKET;
    sa_ll_bind.sll_protocol = htons(ETH_P_ALL);
    sa_ll_bind.sll_ifindex = ifr.ifr_ifindex;

    if (bind(sd,
        (const struct sockaddr *)&sa_ll_bind,
        sizeof(struct sockaddr_ll)) < 0) {
        printf("%s: bind: %s\n", ifname.c_str(), strerror(errno));
        throw runtime_error("unable to bind socket to interface");
    }

    printf("%s: AF_PACKET socket bound to: %s [%d]\n",
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
            printf("%s: setsockopt(PACKET_ADD_MEMBERSHIP:%hu): %s\n",
                ifname.c_str(), pmreq.mr_type, strerror(errno));
            throw runtime_error("error while adding membership(s)");
        }
    }
#ifdef PACKET_FANOUT
    so_uintval = (PACKET_FANOUT_HASH |
        PACKET_FANOUT_FLAG_DEFRAG | PACKET_FANOUT_FLAG_ROLLOVER) << 16 | 1;

    printf("%s: fanout options and flags: 0x%08x\n", ifname.c_str(), so_uintval);

    if (setsockopt(sd, SOL_PACKET, PACKET_FANOUT,
        (const void *)&so_uintval, sizeof(so_uintval)) < 0) {
        printf("%s: setsockopt(PACKET_FANOUT): %s\n", ifname.c_str(), strerror(errno));
        throw runtime_error("error enabling fanout");
    }
#else
#warning "PACKET_FANOUT not supported."
#endif
    so_uintval = VLAN_TAG_LEN;
    if (setsockopt(sd, SOL_PACKET, PACKET_RESERVE,
        (const void *)&so_uintval, sizeof(so_uintval)) < 0) {
        printf("%s: setsockopt(PACKET_RESERVE): %s\n", ifname.c_str(), strerror(errno));
        throw runtime_error("error reserving VLAN TAG space");
    }

    so_uintval = 0;
    so_vallen = sizeof(so_uintval);
    if (getsockopt(sd, SOL_PACKET, PACKET_RESERVE,
        (void *)&so_uintval, &so_vallen) < 0) {
        printf("%s: getsockopt(PACKET_RESERVE): %s\n", ifname.c_str(), strerror(errno));
        throw runtime_error("error getting reserved VLAN TAG size");
    }

    tp_reserved = (size_t)so_uintval;
    if (tp_reserved != VLAN_TAG_LEN) {
        printf("%s: PACKET_RESERVE: unexpected size: %lu != %u\n", ifname.c_str(),
            tp_reserved, VLAN_TAG_LEN
        );
        throw runtime_error("unexpected reserved VLAN TAG size");
    }

    size_t block_size = 1 << 22, frame_size = 1 << 11, block_count = 64;

    tp_req.tp_block_size = (unsigned)block_size;
    tp_req.tp_frame_size = (unsigned)frame_size;
    tp_req.tp_block_nr = (unsigned)block_count;
    tp_req.tp_frame_nr = (unsigned)(block_size * block_count) / frame_size;
    tp_req.tp_retire_blk_tov = 60; // TODO: Read about this.
    //tp_req.tp_feature_req_word = // TODO: Features?

    printf("%s: block size: %u\n", ifname.c_str(), tp_req.tp_block_size);
    printf("%s: frame size: %u\n", ifname.c_str(), tp_req.tp_frame_size);
    printf("%s: blocks: %u\n", ifname.c_str(), tp_req.tp_block_nr);
    printf("%s: frames: %u\n", ifname.c_str(), tp_req.tp_frame_nr);

    if (setsockopt(sd, SOL_PACKET, PACKET_RX_RING,
        (const void *)&tp_req, sizeof(struct tpacket_req3)) < 0) {
        printf("%s: setsockopt(PACKET_RX_RING): %s\n",
            ifname.c_str(), strerror(errno));
        throw runtime_error("error requesting RX ring");
    }

    buffer = mmap(0, tp_req.tp_block_size * tp_req.tp_block_nr,
        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, sd, 0);
    if (buffer == MAP_FAILED) {
        printf("%s: mmap(%u): %s\n", ifname.c_str(),
            tp_req.tp_block_size * tp_req.tp_block_nr, strerror(errno)
        );
        throw runtime_error("error mapping RX ring");
    }

    for (size_t b = 0; b < block_count; b++) {
        ndPacketRingBlock *entry = new ndPacketRingBlock(
            (void *)(((size_t)buffer) + (b * tp_req.tp_block_size))
        );
        blocks.push_back(entry);
    }

    it_block = blocks.begin();

    printf("%s: created %lu packet ring blocks.\n",
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
        IF_SNAPLEN, DLT_EN10MB, &filter,
        IF_FILTER, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        printf("pcap_compile_nopcap: %s: failed.\n", IF_FILTER);
        return false;
    }

    return true;
}

bool ndPacketRing::ApplyFilter(const uint8_t *pkt, size_t length, size_t snaplen) const
{
    return (filter.bf_insns &&
        bpf_filter(filter.bf_insns, pkt, length, snaplen) == 0);
}

bool ndPacketRing::GetStats(ndPacketCaptureStats &stats)
{
    struct tpacket_stats_v3 tp_stats;
    socklen_t so_vallen = sizeof(struct tpacket_stats_v3);

    memset(&tp_stats, 0, so_vallen);

    if (getsockopt(sd, SOL_PACKET, PACKET_STATISTICS,
        &tp_stats, &so_vallen) < 0) {
        printf("%s: error getting packet statistics: %s\n",
            ifname.c_str(), strerror(errno));
        return false;
    }

    pkt_stats.packets = tp_stats.tp_packets;
    pkt_stats.dropped = tp_stats.tp_drops;
    // v3: tp_freeze_q_cnt

    memcpy(&stats, &pkt_stats, sizeof(ndPacketCaptureStats));
    memset(&pkt_stats, 0, sizeof(ndPacketCaptureStats));

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

ndPacket *ndPacket::Create(const ndPacketRing *ring,
    void *entry, status_flags &status)
{
    struct tpacket3_hdr *hdr = (struct tpacket3_hdr *)entry;

    unsigned int tp_len, tp_mac, tp_snaplen;
    tp_len = hdr->tp_len;
    tp_mac = hdr->tp_mac;
    tp_snaplen = hdr->tp_snaplen;
#if 0
    // TODO: time
    unsigned int tp_sec, tp_usec;
    tp_sec = hdr->tp_sec;
    tp_usec = hdr->tp_nsec / 1000;
#endif
    status = STATUS_INIT;

    if (tp_len != tp_snaplen)
        printf("tp_len: %u, tp_snaplen: %u\n", tp_len, tp_snaplen);

#if 0
    if (tp_mac + tp_snaplen > ring->tp_req.tp_frame_size) {
        printf("%s: Corrupted kernel ring frame: MAC offset: %u + snaplen: %u > frame_size: %u\n",
            ring->ifname.c_str(), tp_mac, tp_snaplen,
            ring->tp_req.tp_frame_size
        );

        status = STATUS_CORRUPTED;
        return nullptr;
    }
#endif
    uint8_t *data = (uint8_t *)entry + tp_mac;

    if ((hdr->hv1.tp_vlan_tci ||
        (hdr->tp_status & TP_STATUS_VLAN_VALID)) &&
            tp_snaplen >= (unsigned int)VLAN_OFFSET) {

        struct nd_vlan_tag {
            uint16_t vlan_tpid;
            uint16_t vlan_tci;
        };

        struct nd_vlan_tag *tag;

        data -= VLAN_TAG_LEN;
        memmove((void *)data, data + VLAN_TAG_LEN, VLAN_OFFSET);

        tag = (struct nd_vlan_tag *)(data + VLAN_OFFSET);

        if (hdr->hv1.tp_vlan_tpid &&
            (hdr->tp_status & TP_STATUS_VLAN_TPID_VALID))
            tag->vlan_tpid = htons(hdr->hv1.tp_vlan_tpid);
        else
            tag->vlan_tpid = htons(ETH_P_8021Q);

        tag->vlan_tci = htons(hdr->hv1.tp_vlan_tci);

        tp_snaplen += VLAN_TAG_LEN;
        tp_len += VLAN_TAG_LEN;

        status |= STATUS_VLAN_TAG_RESTORED;
    }

    if (ring->ApplyFilter(data, tp_len, tp_snaplen)) {
        status = STATUS_FILTERED;
        return nullptr;
    }

    ndPacket *pkt = nullptr;
    uint8_t *pkt_data = new uint8_t[tp_snaplen];

    if (pkt_data) {
        memcpy(pkt_data, data, tp_snaplen);
        pkt = new ndPacket(status, tp_len, tp_snaplen, pkt_data);
    }

    if (pkt) status |= STATUS_OK;
    else status = STATUS_ENOMEM;

    return pkt;
}

int main(int argc, char *argv[])
{
    fd_set fds_read;

    ndPacketRing *ring = new ndPacketRing(
        (argc > 1) ? argv[1] : IF_NAME
    );

    if (ring == nullptr)
        throw runtime_error(strerror(ENOMEM));

    ring->SetFilter(IF_FILTER);

    int sd_max = ring->GetDescriptor();

    int rc = 0;
    struct timeval tv;

    size_t max_queued = 0;
    size_t packets = 0, total_packets = 0;

    signal(SIGINT, sighandler);

    while (likely(!sigint) && rc >= 0) {

        ndPacketRingBlock *entry = ring->Next();

        if (entry == nullptr) {

            FD_ZERO(&fds_read);
            FD_SET(ring->GetDescriptor(), &fds_read);

            tv.tv_sec = 1; tv.tv_usec = 0;
            rc = select(sd_max + 1, &fds_read, NULL, NULL, &tv);

            if (rc == -1)
                printf("select: %s\n", strerror(errno));

            continue;
        }

        size_t queued = entry->ProcessPackets(ring);

        entry->Release();

        packets += queued;

        if (queued > max_queued)
            max_queued = queued;

        if (packets > 1000) {
            total_packets += packets;
            packets = 0;

            ndPacketCaptureStats stats;
            memset(&stats, 0, sizeof(ndPacketCaptureStats));

            ring->GetStats(stats);

            if (stats.dropped) {
                printf("packets: %lu / %lu\n", stats.packets, total_packets);
                printf("dropped: %lu\n", stats.dropped);
                printf("filtered: %lu\n", stats.filtered);
                printf("queued / max: %lu / %lu\n", queued, max_queued);
            }
        }
    }

    delete ring;

    printf("total packets: %lu\n", packets + total_packets);

    return 0;
}
