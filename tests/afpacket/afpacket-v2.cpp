#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

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

#define PKT_DELAY_MS            10
//#define PKT_DELAY_MS            500

//#define IF_THREADS            4
#define IF_THREADS              1
#define IF_NAME                 "eth0"
#define IF_SNAPLEN              (24 * 1024)
//#define IF_SNAPLEN              (64 * 1024)
#define IF_FILTER               "not port 22"

// Default ring buffer size in MB
#define _ND_RING_BUFFER_SIZE    4
//#define _ND_RING_BUFFER_SIZE    128

#define VLAN_TAG_LEN            4
#define VLAN_OFFSET             (2 * ETH_ALEN)

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
    uint32_t packets;
    uint32_t dropped;
} ndPacketCaptureStats;

class ndPacket;
class ndPacketRing;
class ndPacketRingEntry
{
public:
    ndPacketRingEntry(void *entry);

    inline uint32_t GetStatus(void) {
        return hdr.tp_hdr->tp_status;
    }

    inline void SetStatus(uint32_t status = TP_STATUS_KERNEL) {
        hdr.tp_hdr->tp_status = status;
    }

    inline void Release(void) {
        hdr.tp_hdr->tp_status = TP_STATUS_KERNEL;
    }

protected:
    friend class ndPacket;
    friend class ndPacketRing;

    union {
        uint8_t *raw;
        struct tpacket2_hdr *tp_hdr;
    } hdr;
};

ndPacketRingEntry::ndPacketRingEntry(void *entry)
{
    hdr.raw = static_cast<uint8_t *>(entry);
    hdr.tp_hdr = static_cast<struct tpacket2_hdr *>(entry);
}

typedef vector<ndPacketRingEntry *> ndPacketRingEntries;

class ndPacketRing
{
public:
    ndPacketRing(const string &ifname,
        size_t ring_buffer_size = _ND_RING_BUFFER_SIZE);

    virtual ~ndPacketRing();

    inline int GetDescriptor(void) { return sd; }

    bool GetStats(ndPacketCaptureStats &stats);

    ndPacketRingEntry *NextPacket(void);

protected:
    friend class ndPacket;

    string ifname;
    int sd;
    void *buffer;
    ndPacketRingEntries ring;
    ndPacketRingEntries::iterator it_ring;

    size_t tp_hdrlen;
    size_t tp_reserved;
    size_t tp_snaplen;
    size_t tp_frame_size;
    size_t tp_ring_size;
    struct tpacket_req tp_req;
};

typedef vector<ndPacketRing *> ndPacketRings;

ndPacketRing::ndPacketRing(
    const string &ifname, size_t ring_buffer_size)
    : ifname(ifname), sd(-1), buffer(nullptr),
    tp_hdrlen(0), tp_reserved(0), tp_snaplen(IF_SNAPLEN),
    tp_frame_size(0), tp_ring_size(0),
    tp_req{0}
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

    so_uintval = TPACKET_V2;
    socklen_t so_vallen = sizeof(so_uintval);
    if (getsockopt(sd, SOL_PACKET, PACKET_HDRLEN,
        (void *)&so_uintval, &so_vallen) < 0) {
        printf("%s: getsockopt(PACKET_HDRLEN): %s\n",
            ifname.c_str(), strerror(errno));
        throw runtime_error("TPACKET_V2 not supported");
    }

    tp_hdrlen = (size_t)so_uintval;
    printf("%s: TPACKET_V2 header length: %ld\n",
        ifname.c_str(), tp_hdrlen);

    so_uintval = TPACKET_V2;
    if (setsockopt(sd, SOL_PACKET, PACKET_VERSION,
        (const void *)&so_uintval, sizeof(so_uintval)) < 0) {
        printf("%s: setsockopt(PACKET_VERSION): TPACKET_V2: %s\n",
            ifname.c_str(), strerror(errno));
        throw runtime_error("error selecting TPACKET_V2");
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
        /* PACKET_MR_ALLMULTI */
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
        printf("%s: PACKET_RESERVE: unexpected size: %u != %u\n", ifname.c_str(),
            tp_reserved, VLAN_TAG_LEN
        );
        throw runtime_error("unexpected reserved VLAN TAG size");
    }

    size_t tp_hdrlen_sll = TPACKET_ALIGN(tp_hdrlen) + sizeof(struct sockaddr_ll);
    size_t offset_net = TPACKET_ALIGN(
        tp_hdrlen_sll + (ETH_HLEN < 16 ? 16 : ETH_HLEN)) + tp_reserved;
    size_t offset_mac = offset_net - ETH_HLEN;

    tp_frame_size = TPACKET_ALIGN(offset_mac + IF_SNAPLEN);
    tp_snaplen = tp_frame_size - offset_mac;

    printf("%s: calculated frame size: %u\n",
        ifname.c_str(), tp_frame_size);
    printf("%s: snaplen + padding: %u\n",
        ifname.c_str(), tp_snaplen);

    tp_req.tp_frame_size = tp_frame_size;

#define RX_RING_BUFFER_ORDER 10
    tp_req.tp_block_size = getpagesize() << RX_RING_BUFFER_ORDER;
    printf("%s: tp_block_size: %u\n",
        ifname.c_str(), tp_req.tp_block_size);
    while (tp_req.tp_block_size < tp_req.tp_frame_size) {
        printf("%s: tp_block_size: %u < tp_frame_size: %u\n",
            ifname.c_str(),
            tp_req.tp_block_size, tp_req.tp_frame_size);
        tp_req.tp_block_size <<= 1;
        printf("%s: <<1 tp_block_size: %u\n",
            ifname.c_str(), tp_req.tp_block_size);
    }

    unsigned tp_frames_per_block;
    tp_frames_per_block = tp_req.tp_block_size / tp_req.tp_frame_size;

    if (tp_frames_per_block == 0) {
        printf("%s: invalid frames per block (%u/%u).\n",
            ifname.c_str(),
            tp_req.tp_block_size, tp_req.tp_frame_size
        );
        throw runtime_error("invalid frames-per-block");
    }

    unsigned tp_max_size = ring_buffer_size * 1024 * 1024;

    tp_req.tp_frame_nr = tp_max_size / tp_frame_size;
    tp_req.tp_block_nr = tp_req.tp_frame_nr / tp_frames_per_block;
    tp_req.tp_frame_nr = tp_req.tp_block_nr * tp_frames_per_block;

    printf("%s: frame size: %u\n", ifname.c_str(), tp_frame_size);
    printf("%s: frames: %u\n", ifname.c_str(), tp_req.tp_frame_nr);
    printf("%s: block size: %u\n", ifname.c_str(), tp_req.tp_block_size);
    printf("%s: blocks: %u\n", ifname.c_str(), tp_req.tp_block_nr);
    printf("%s: wasted: %u\n", ifname.c_str(),
        tp_req.tp_block_nr * (
            tp_req.tp_block_size % tp_req.tp_frame_size)
    );

    if (setsockopt(sd, SOL_PACKET, PACKET_RX_RING,
        (const void *)&tp_req, sizeof(struct tpacket_req)) < 0) {
        printf("%s: setsockopt(PACKET_RX_RING): %s\n",
            ifname.c_str(), strerror(errno));
        throw runtime_error("error requesting RX ring");
    }

    tp_ring_size = tp_req.tp_block_size * tp_req.tp_block_nr;

    buffer = mmap(0, tp_ring_size,
        PROT_READ | PROT_WRITE, MAP_SHARED, sd, 0);
    if (buffer == MAP_FAILED) {
        printf("%s: mmap(%u): %s\n",
            ifname.c_str(), tp_ring_size, strerror(errno));
        throw runtime_error("error mapping RX ring");
    }

    size_t i = 0;
    for (size_t b = 0; b < tp_req.tp_block_nr; b++) {
        size_t bo = b * tp_req.tp_block_size;
        for (size_t f = 0;
            f < (tp_req.tp_block_size / tp_req.tp_frame_size) &&
            i < tp_req.tp_frame_nr; f++) {
            size_t fo = f * tp_req.tp_frame_size;
            ndPacketRingEntry *entry = new ndPacketRingEntry(
                (void *)(((size_t)buffer) + bo + fo)
            );
            ring.push_back(entry);
            i++;
        }
    }

    it_ring = ring.begin();

    printf("%s: created %u packet ring entries.\n", ifname.c_str(),
        ring.size()
    );
}

ndPacketRing::~ndPacketRing()
{
    if (buffer) munmap(buffer, tp_ring_size);
    if (sd != -1) close(sd);
    for (auto &i : ring) delete i;
}

bool ndPacketRing::GetStats(ndPacketCaptureStats &stats)
{
    struct tpacket_stats tp_stats;
    socklen_t so_vallen = sizeof(struct tpacket_stats);

    memset(&tp_stats, 0, so_vallen);

    if (getsockopt(sd, SOL_PACKET, PACKET_STATISTICS,
        &tp_stats, &so_vallen) < 0) {
        printf("%s: error getting packet statistics: %s\n",
            ifname.c_str(), strerror(errno));
        return false;
    }

    stats.packets = tp_stats.tp_packets;
    stats.dropped = tp_stats.tp_drops;

    return true;
}

ndPacketRingEntry *ndPacketRing::NextPacket(void)
{
    size_t entries = ring.size();
    ndPacketRingEntry *entry = nullptr;

    do {
        if (it_ring == ring.end())
            it_ring = ring.begin();

        if ((*it_ring)->hdr.tp_hdr->tp_status & TP_STATUS_USER)
            entry = (*it_ring);

        it_ring++;
    }
    while (entry == nullptr && --entries > 0);

    return entry;
}

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

    enum {
        FILTER_NONE,
        FILTER_PCAP,

        FILTER_MAX
    };

    typedef uint8_t filter_type;

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
        ndPacketRingEntry *entry,
        status_flags &status,
        const filter_type &ftype = FILTER_NONE,
        const void *fprogram = nullptr
    );

protected:
    status_flags status;
    uint16_t length;
    uint16_t captured;
    uint8_t *data;
};

ndPacket *ndPacket::Create(
    const ndPacketRing *ring,
    ndPacketRingEntry *entry, status_flags &status,
    const filter_type &ftype, const void *fprogram)
{
    status = STATUS_INIT;

    unsigned int tp_len, tp_mac, tp_snaplen, tp_sec, tp_usec;
    tp_len = entry->hdr.tp_hdr->tp_len;
    tp_mac = entry->hdr.tp_hdr->tp_mac;
    tp_snaplen = entry->hdr.tp_hdr->tp_snaplen;
    tp_sec = entry->hdr.tp_hdr->tp_sec;
    tp_usec = entry->hdr.tp_hdr->tp_nsec / 1000;

    if (tp_mac + tp_snaplen > ring->tp_req.tp_frame_size) {
        printf("%s: Corrupted kernel ring frame: MAC offset: %u + snaplen: %u > frame_size: %u\n",
            ring->ifname.c_str(), tp_mac, tp_snaplen,
            ring->tp_req.tp_frame_size
        );

        status = STATUS_CORRUPTED;
        return nullptr;
    }

    uint8_t *data = entry->hdr.raw + tp_mac;

    if ((entry->hdr.tp_hdr->tp_vlan_tci ||
        (entry->hdr.tp_hdr->tp_status & TP_STATUS_VLAN_VALID)) &&
            tp_snaplen >= (unsigned int)VLAN_OFFSET) {

        struct nd_vlan_tag {
            uint16_t vlan_tpid;
            uint16_t vlan_tci;
        };

        struct nd_vlan_tag *tag;

        data -= VLAN_TAG_LEN;
        memmove((void *)data, data + VLAN_TAG_LEN, VLAN_OFFSET);

        tag = (struct nd_vlan_tag *)(data + VLAN_OFFSET);

        if (entry->hdr.tp_hdr->tp_vlan_tpid &&
            (entry->hdr.tp_hdr->tp_status & TP_STATUS_VLAN_TPID_VALID))
            tag->vlan_tpid = htons(entry->hdr.tp_hdr->tp_vlan_tpid);
        else
            tag->vlan_tpid = htons(ETH_P_8021Q);

        tag->vlan_tci = htons(entry->hdr.tp_hdr->tp_vlan_tci);

        tp_snaplen += VLAN_TAG_LEN;
        tp_len += VLAN_TAG_LEN;

        status |= STATUS_VLAN_TAG_RESTORED;
    }

    const struct bpf_program *filter = nullptr;

    if (ftype == FILTER_PCAP && fprogram != nullptr) {
        filter = static_cast<const struct bpf_program *>(fprogram);

        if (bpf_filter(
            filter->bf_insns, data, tp_len, tp_snaplen) == 0) {
            status = STATUS_FILTERED;
            return nullptr;
        }
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
    struct bpf_program filter;
    if (pcap_compile_nopcap(
        IF_SNAPLEN, DLT_EN10MB, &filter,
        IF_FILTER, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        printf("pcap_compile_nopcap: %s: failed.\n", IF_FILTER);
        return 1;
    }

    fd_set fds_read;

    int sd_max = -1;
    ndPacketRings rings;

    for (unsigned id = 0; id < IF_THREADS; id++) {
        ndPacketRing *ring = new ndPacketRing(
            (argc > 1) ? argv[1] : IF_NAME
        );
        int sd = ring->GetDescriptor();
        if (sd > sd_max) sd_max = sd;
        rings.push_back(ring);
    }

    int rc;
    struct timeval tv;

    size_t packets = 0;
    size_t max_queued = 0;
    size_t filtered = 0;
    size_t discarded = 0;

    do {
        FD_ZERO(&fds_read);
        for (unsigned id = 0; id < IF_THREADS; id++) {
            FD_SET(rings[id]->GetDescriptor(), &fds_read);
        }

        usleep(PKT_DELAY_MS * 1000);

        tv.tv_sec = 1; tv.tv_usec = 0;
        rc = select(sd_max + 1, &fds_read, NULL, NULL, &tv);

        if (rc == 0)
            continue;
        else if (rc == -1) {
            printf("select: %s\n", strerror(errno));
            return 1;
        }

        for (unsigned id = 0; id < IF_THREADS; id++) {

            if (! FD_ISSET(rings[id]->GetDescriptor(), &fds_read))
                continue;

            size_t queued = 0;
            ndPacketRingEntry *entry = rings[id]->NextPacket();

            bool get_stats = false;

            while (entry != nullptr) {
                queued++;

                if (! get_stats)
                    get_stats = ((packets + queued) % 1000 == 0);

                ndPacket::status_flags status;
                ndPacket *pkt = ndPacket::Create(
                    rings[id],
                    entry, status/*,
                    ndPacket::FILTER_PCAP, (void *)&filter*/
                );

                if (status & ndPacket::STATUS_FILTERED)
                    filtered++;

                if (! (status & ndPacket::STATUS_OK))
                    discarded++;

                if (pkt != nullptr) delete pkt;

                entry->Release();
                entry = rings[id]->NextPacket();
            }

            packets += queued;

            if (queued > max_queued)
                max_queued = queued;

            if (get_stats) {
                ndPacketCaptureStats stats;
                memset(&stats, 0, sizeof(ndPacketCaptureStats));

                rings[id]->GetStats(stats);

                if (stats.dropped) {
                    printf("packets: %u (%u)\n", packets, stats.packets);
                    printf("dropped: %u\n", stats.dropped);
                    printf("filtered: %u\n", filtered);
                    printf("queued / max: %u / %u\n", queued, max_queued);
                }
            }
        }
    } while (rc > -1);

    return 0;
}
