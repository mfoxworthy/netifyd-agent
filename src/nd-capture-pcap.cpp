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
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

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
#include <ctype.h>
#include <errno.h>

#include <arpa/inet.h>

#define __FAVOR_BSD 1
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <resolv.h>

#ifdef _ND_USE_CONNTRACK
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#endif

#include <pcap/pcap.h>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#include <radix/radix_tree.hpp>

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
#include "nd-dhc.h"
#include "nd-fhc.h"
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
#include "nd-capture-pcap.h"

ndCapturePcap::ndCapturePcap(
    int16_t cpu,
    ndInterface& iface,
    const nd_detection_threads &threads_dpi,
    ndDNSHintCache *dhc,
    uint8_t private_addr)
    : ndCaptureThread(
        iface.capture_type,
        cpu, iface, threads_dpi, dhc, private_addr
    ),
    pcap(nullptr), pcap_fd(-1),
    pkt_header(nullptr), pkt_data(nullptr),
    pcs_last{0}
{
    if (iface.capture_type == ndCT_PCAP_OFFLINE) {
        nd_dprintf("%s: capture file: %s\n",
            tag.c_str(), iface.config.pcap->capture_filename.c_str()
        );
    }

    nd_dprintf("%s: PCAP capture thread created.\n", tag.c_str());
}

ndCapturePcap::~ndCapturePcap()
{
    Join();

    if (pcap != nullptr) { pcap_close(pcap); pcap = nullptr; }

    nd_dprintf("%s: PCAP capture thread destroyed.\n", tag.c_str());
}

void *ndCapturePcap::Entry(void)
{
    int rc;
    int sd_max = 0;
    struct ifreq ifr;
    struct timeval tv;
    fd_set fds_read;
    bool warnings = true;
    ndPacket *pkt;
    ndPacket::status_flags pkt_status = ndPacket::STATUS_OK;

    while (! ShouldTerminate()) {

        if (pcap != nullptr) {

            FD_ZERO(&fds_read);
//            FD_SET(fd_ipc[0], &fds_read);
            FD_SET(pcap_fd, &fds_read);

            tv.tv_sec = 1; tv.tv_usec = 0;
            rc = select(sd_max + 1, &fds_read, nullptr, nullptr, &tv);

            if (rc == 0) continue;
            else if (rc == -1)
                throw ndCaptureThreadException(strerror(errno));
#if 0
            if (FD_ISSET(fd_ipc[0], &fds_read)) {
                // TODO: Not used.
                uint32_t ipc_id = RecvIPC();
            }
#endif
            if (! FD_ISSET(pcap_fd, &fds_read)) continue;

            rc = 0;
            while (ShouldTerminate() == false &&
                (rc = pcap_next_ex(pcap, &pkt_header, &pkt_data)) > 0) {

                // One-and-only packet copy...
                uint8_t *pd = new uint8_t[pkt_header->caplen];
                if (pd == nullptr)
                    throw ndCaptureThreadException(strerror(ENOMEM));
                memcpy(pd, pkt_data, pkt_header->caplen);

                pkt = new ndPacket(pkt_status,
                    pkt_header->len, pkt_header->caplen,
                    pd, pkt_header->ts
                );
                if (pkt == nullptr)
                    throw ndCaptureThreadException(strerror(ENOMEM));

                Lock();

                try {
                    if (ProcessPacket(pkt) != nullptr)
                        delete pkt;
                }
                catch (...) {
                    Unlock();
                    throw;
                }

                Unlock();
            }

            if (rc < 0) {
                capture_state = STATE_OFFLINE;

                if (rc == -1) {
                    nd_printf("%s: %s.\n", tag.c_str(), pcap_geterr(pcap));
                    if (iface.capture_type == ndCT_PCAP_OFFLINE)
                        Terminate();
                    else {
                        pcap_close(pcap);
                        pcap = nullptr;
                        sleep(1);
                    }
                }
                else if (rc == -2) {
                    nd_dprintf("%s: end of capture file: %s\n", tag.c_str(),
                        iface.config.pcap->capture_filename.c_str()
                    );
                    Terminate();
                }
            }
        }
        else if (! ShouldTerminate()) {
            if (iface.capture_type != ndCT_PCAP_OFFLINE && (
                nd_ifreq(tag, SIOCGIFFLAGS, &ifr) == -1 ||
                ! (ifr.ifr_flags & IFF_UP))) {

                capture_state = STATE_OFFLINE;

                if (warnings) {
                    nd_printf("%s: WARNING: interface not available.\n",
                        tag.c_str());
                    warnings = false;
                }
                sleep(1);
                continue;
            }

            warnings = true;

            if ((pcap = OpenCapture()) == nullptr) {
                capture_state = STATE_OFFLINE;
                sleep(1);
                continue;
            }

            dl_type = pcap_datalink(pcap);
            sd_max = pcap_fd;
//            sd_max = max(fd_ipc[0], pcap_fd);

            nd_dprintf("%s: PCAP capture started on CPU: %lu\n",
                tag.c_str(), cpu >= 0 ? cpu : 0);
        }
    }

    capture_state = STATE_OFFLINE;

    nd_dprintf(
        "%s: PCAP capture ended on CPU: %lu\n", tag.c_str(), cpu >= 0 ? cpu : 0);

    return nullptr;
}

pcap_t *ndCapturePcap::OpenCapture(void)
{
    pcap_t *pcap_new = nullptr;

    memset(pcap_errbuf, 0, PCAP_ERRBUF_SIZE);

    if (iface.capture_type == ndCT_PCAP_OFFLINE) {
        if ((pcap_new = pcap_open_offline(
            iface.config.pcap->capture_filename.c_str(), pcap_errbuf)) != nullptr) {
            tv_epoch = time(nullptr);
            nd_dprintf("%s: reading from capture file: %s: v%d.%d\n",
                tag.c_str(), iface.config.pcap->capture_filename.c_str(),
                pcap_major_version(pcap_new), pcap_minor_version(pcap_new));
        }
    }
    else {
        pcap_new = pcap_open_live(
            tag.c_str(),
            ndGC.max_capture_length,
            1, ndGC.capture_read_timeout, pcap_errbuf
        );

#if 0
        if (pcap_new != nullptr) {
            bool adapter = false;
            int *pcap_tstamp_types, count;
            if ((count = pcap_list_tstamp_types(pcap_new, &pcap_tstamp_types)) > 0) {
                for (int i = 0; i < count; i++) {
                    nd_dprintf("%s: tstamp_type: %s\n", tag.c_str(),
                        pcap_tstamp_type_val_to_name(pcap_tstamp_types[i]));
                    if (pcap_tstamp_types[i] == PCAP_TSTAMP_ADAPTER)
                        adapter = true;
                }

                pcap_free_tstamp_types(pcap_tstamp_types);

                //if (adapter) {
                //    if (pcap_set_tstamp_type(pcap_new, PCAP_TSTAMP_ADAPTER) != 0) {
                //        nd_printf("%s: Failed to set timestamp type: %s\n", tag.c_str(),
                //            pcap_geterr(pcap_new));
                //    }
                //}
            }
        }
#endif
    }

    if (pcap_new == nullptr)
        nd_printf("%s: pcap_open: %s\n", tag.c_str(), pcap_errbuf);
    else {
        capture_state = STATE_ONLINE;

        if (iface.capture_type != ndCT_PCAP_OFFLINE) {
            if (pcap_setnonblock(pcap_new, 1, pcap_errbuf) == PCAP_ERROR)
                nd_printf("%s: pcap_setnonblock: %s\n", tag.c_str(), pcap_errbuf);
        }

        if ((pcap_fd = pcap_get_selectable_fd(pcap_new)) < 0)
            nd_dprintf("%s: pcap_get_selectable_fd: -1\n", tag.c_str());

        nd_interface_filter::const_iterator i = ndGC.interface_filters.find(tag);

        if (i != ndGC.interface_filters.end()) {

            if (pcap_compile(pcap_new, &pcap_filter,
                i->second.c_str(), 1, PCAP_NETMASK_UNKNOWN) < 0) {
                nd_printf("%s: pcap_compile: %s\n",
                    tag.c_str(), pcap_geterr(pcap_new));
                pcap_close(pcap_new);
                return nullptr;
            }

            if (pcap_setfilter(pcap_new, &pcap_filter) < 0) {
                nd_printf("%s: pcap_setfilter: %s\n",
                    tag.c_str(), pcap_geterr(pcap_new));
                pcap_close(pcap_new);
                return nullptr;
            }
        }
    }

    return pcap_new;
}

void ndCapturePcap::GetCaptureStats(ndPacketStats &stats)
{
    if (pcap != nullptr &&
        iface.capture_type != ndCT_PCAP_OFFLINE) {

        struct pcap_stat pcs;
        memset(&pcs, 0, sizeof(struct pcap_stat));

        if (pcap_stats(pcap, &pcs) == 0) {
            uint64_t dropped = pcs.ps_drop + pcs.ps_ifdrop;

            if (pcs_last.ps_drop <= pcs.ps_drop)
                dropped -= pcs_last.ps_drop;
            if (pcs_last.ps_ifdrop <= pcs.ps_ifdrop)
                dropped -= pcs_last.ps_ifdrop;

            this->stats.pkt.capture_dropped = dropped;

            memcpy(&pcs_last, &pcs, sizeof(struct pcap_stat));
        }
    }

    ndCaptureThread::GetCaptureStats(stats);
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
