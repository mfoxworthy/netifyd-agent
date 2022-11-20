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

#ifndef _ND_CAPTURE_H
#define _ND_CAPTURE_H

typedef struct {
    size_t packets;
    size_t dropped;
    size_t filtered;
    size_t discarded;
} ndPacketCaptureStats;

class ndPacket;
class ndSocketThread;
class ndCaptureThread;

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
        uint8_t *data)
        : status(status), length(length), caplen(caplen),
        data(data), tv_sec(0), tv_usec(0) { }

    virtual ~ndPacket() {
        if (data != nullptr) delete [] data;
        status = STATUS_INIT;
    }

    inline status_flags GetStatus(void) { return status; }
    inline uint16_t GetWireLength(void) { return length; }
    inline uint16_t GetCaptureLength(void) { return caplen; }
    inline uint8_t *GetPayload(void) { return data; }
    inline void GetTime(struct timeval &tv) {
        tv.tv_sec = tv_sec;
        tv.tv_usec = tv_usec;
    }

protected:
    friend class ndCaptureThread;

    status_flags status;
    uint16_t length;
    uint16_t caplen;
    uint8_t *data;
    time_t tv_sec;
    time_t tv_usec;
};

class ndCaptureThreadException : public runtime_error
{
public:
    explicit ndCaptureThreadException(const string &what_arg)
        : runtime_error(what_arg) { }
};

typedef queue<ndPacket *> nd_pkt_queue;

class ndPacketQueue
{
public:
    ndPacketQueue(const string &tag);
    virtual ~ndPacketQueue();

    bool empty(void) { return pkt_queue.empty(); }
    size_t size(void) { return pkt_queue.size(); }

    size_t push(ndPacket *pkt);
    bool front(ndPacket **pkt);
    void pop(const string &oper = "pop");

protected:
    string tag;
    size_t pkt_queue_size;
    nd_pkt_queue pkt_queue;
};

class ndCaptureThread : public ndThread
{
public:
    ndCaptureThread(
        nd_capture_type cs_type,
        int16_t cpu,
        nd_interface::iterator iface,
        const uint8_t *dev_mac,
        ndSocketThread *thread_socket,
        const nd_detection_threads &threads_dpi,
        ndDNSHintCache *dhc = NULL,
        uint8_t private_addr = 0);

    virtual ~ndCaptureThread() { }

    virtual void *Entry(void) = 0;

    // XXX: Ensure thread is locked before calling!
    virtual void GetCaptureStats(ndPacketStats &stats) {
        this->stats.AddAndReset(stats);
    }

protected:
    int dl_type;
    nd_capture_type cs_type;

    nd_interface::iterator iface;
    uint8_t dev_mac[ETH_ALEN];
    ndSocketThread *thread_socket;
//    bool capture_unknown_flows;

    uint64_t ts_pkt_first;
    uint64_t ts_pkt_last;

    nd_private_addr private_addrs;

    ndPacketStats stats;

    string flow_digest;

    ns_msg ns_h;
    ndDNSHintCache *dhc;

    const nd_detection_threads &threads_dpi;
    int16_t dpi_thread_id;

    void ProcessPacket(const ndPacket *packet);

    bool ProcessDNSPacket(const ndPacket *packet, const char **host);
};

typedef map<string, vector<ndCaptureThread *>> nd_capture_threads;

#endif // _ND_CAPTURE_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
