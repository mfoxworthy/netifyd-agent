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

#ifndef _ND_CAPTURE_PCAP_H
#define _ND_CAPTURE_PCAP_H

class ndCapturePcap : public ndCaptureThread
{
public:
    ndCapturePcap(
        int16_t cpu,
        ndInterface& iface,
        const nd_detection_threads &threads_dpi,
        ndDNSHintCache *dhc = NULL,
        uint8_t private_addr = 0);
    virtual ~ndCapturePcap();

    virtual void *Entry(void);

    // XXX: Ensure thread is locked before calling!
    virtual void GetCaptureStats(ndPacketStats &stats);

protected:
    pcap_t *pcap;
    int pcap_fd;
    string pcap_file;
    struct bpf_program pcap_filter;
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    int pcap_snaplen;
    struct pcap_pkthdr *pkt_header;
    const uint8_t *pkt_data;
    struct pcap_stat pcs_last;

    pcap_t *OpenCapture(void);
};

#endif // _ND_CAPTURE_PCAP_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
