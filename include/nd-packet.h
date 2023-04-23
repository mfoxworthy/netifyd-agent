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

#ifndef _ND_PACKET_H
#define _ND_PACKET_H

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
        const uint16_t &length, const uint16_t &caplen,
        uint8_t *data, const struct timeval &tv)
        : status(status), length(length), caplen(caplen),
        data(data), tv_sec(tv.tv_sec), tv_usec(tv.tv_usec) { }

    virtual ~ndPacket() {
        if (data != nullptr) delete [] data;
        status = STATUS_INIT;
    }

    inline status_flags GetStatus(void) { return status; }
    inline uint16_t GetWireLength(void) { return length; }
    inline uint16_t GetCaptureLength(void) { return caplen; }
    inline const uint8_t *GetData(void) { return data; }
    inline void GetTime(struct timeval &tv) {
        tv.tv_sec = tv_sec;
        tv.tv_usec = tv_usec;
    }

protected:
    friend class ndCaptureThread;

    status_flags status;
    uint16_t length;
    uint16_t caplen;
    const uint8_t *data;
    time_t tv_sec;
    time_t tv_usec;
};

class ndPacketStats : public ndSerializer
{
public:
    typedef pair<string, ndPacketStats> Interface;

    struct pkt_t {
        uint64_t raw;
        uint64_t eth;
        uint64_t mpls;
        uint64_t pppoe;
        uint64_t vlan;
        uint64_t frags;
        uint64_t discard;
        uint32_t maxlen;
        uint64_t ip;
        uint64_t ip4;
        uint64_t ip6;
        uint64_t icmp;
        uint64_t igmp;
        uint64_t tcp;
        uint64_t tcp_seq_error;
        uint64_t tcp_resets;
        uint64_t udp;
        uint64_t ip_bytes;
        uint64_t ip4_bytes;
        uint64_t ip6_bytes;
        uint64_t wire_bytes;
        uint64_t discard_bytes;
        uint64_t queue_dropped;
        uint64_t capture_dropped;
        uint64_t capture_filtered;
    } pkt;

    struct flow_t {
        uint64_t dropped;
    } flow;

    ndPacketStats() { Reset(); }

    inline ndPacketStats& operator+=(const ndPacketStats &rhs) {
        pkt.raw += rhs.pkt.raw;
        pkt.eth += rhs.pkt.eth;
        pkt.mpls += rhs.pkt.mpls;
        pkt.pppoe += rhs.pkt.pppoe;
        pkt.vlan += rhs.pkt.vlan;
        pkt.frags += rhs.pkt.frags;
        pkt.discard += rhs.pkt.discard;
        if (rhs.pkt.maxlen > pkt.maxlen)
            pkt.maxlen = rhs.pkt.maxlen;
        pkt.ip += rhs.pkt.ip;
        pkt.ip4 += rhs.pkt.ip4;
        pkt.ip6 += rhs.pkt.ip6;
        pkt.icmp += rhs.pkt.icmp;
        pkt.igmp += rhs.pkt.igmp;
        pkt.tcp += rhs.pkt.tcp;
        pkt.tcp_seq_error += rhs.pkt.tcp_seq_error;
        pkt.tcp_resets += rhs.pkt.tcp_resets;
        pkt.udp += rhs.pkt.udp;
        pkt.ip_bytes += rhs.pkt.ip_bytes;
        pkt.ip4_bytes += rhs.pkt.ip4_bytes;
        pkt.ip6_bytes += rhs.pkt.ip6_bytes;
        pkt.wire_bytes += rhs.pkt.wire_bytes;
        pkt.discard_bytes += rhs.pkt.discard_bytes;
        pkt.queue_dropped += rhs.pkt.queue_dropped;
        pkt.capture_dropped += rhs.pkt.capture_dropped;
        pkt.capture_filtered += rhs.pkt.capture_filtered;

        return *this;
    }

    inline void Reset(void) {
        memset(&pkt, 0, sizeof(struct pkt_t));
        memset(&flow, 0, sizeof(struct flow_t));
    }

    inline void AddAndReset(ndPacketStats &stats) {
        stats += (*this);
        Reset();
    }
};

#endif // _ND_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
