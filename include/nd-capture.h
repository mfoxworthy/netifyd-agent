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

class ndCaptureThreadException : public runtime_error
{
public:
    explicit ndCaptureThreadException(const string &what_arg)
        : runtime_error(what_arg) { }
};

class ndSocketThread;

class ndCaptureThread : public ndThread
{
public:
    ndCaptureThread(
        nd_capture_type cs_type,
        int16_t cpu,
        const ndInterface &iface,
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

    const ndInterface iface;
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

    const ndPacket *ProcessPacket(const ndPacket *packet);

    bool ProcessDNSPacket(const uint8_t *pkt, uint16_t pkt_len, const char **host);
};

typedef map<string, vector<ndCaptureThread *>> nd_capture_threads;

#endif // _ND_CAPTURE_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
