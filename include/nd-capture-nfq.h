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

#ifndef _ND_CAPTURE_NFQ_H
#define _ND_CAPTURE_NFQ_H

class ndSocketThread;

class ndCaptureNFQueue : public ndCaptureThread
{
public:
    ndCaptureNFQueue(
        int16_t cpu,
        ndInterface& iface,
        ndSocketThread *thread_socket,
        const nd_detection_threads &threads_dpi,
        unsigned instance_id = 0,
        ndDNSHintCache *dhc = NULL,
        uint8_t private_addr = 0);

    virtual ~ndCaptureNFQueue();

    virtual void *Entry(void);

    // XXX: Ensure thread is locked before calling!
    virtual void GetCaptureStats(ndPacketStats &stats);

protected:
    //struct bpf_program pcap_filter;
    unsigned queue_id;
    struct mnl_socket *nl;
    unsigned int port_id;
    size_t buffer_size;
    uint8_t *buffer;
};

#endif // _ND_CAPTURE_NFQ_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
