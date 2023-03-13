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
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>

#include <linux/types.h>
#include <linux/netfilter/nfnetlink_queue.h>

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

extern ndGlobalConfig nd_config;

ndCaptureNFQueue::ndCaptureNFQueue(
    int16_t cpu,
    ndInterface& iface,
    ndSocketThread *thread_socket,
    const nd_detection_threads &threads_dpi,
    ndDNSHintCache *dhc,
    uint8_t private_addr)
    :
    ndCaptureThread(ndCT_NFQ,
        (long)cpu, iface, thread_socket,
        threads_dpi, dhc, private_addr)
{
    nd_dprintf("%s: NFQ capture thread created.\n", tag.c_str());
}

ndCaptureNFQueue::~ndCaptureNFQueue()
{
    Join();

    nd_dprintf("%s: NFQ capture thread destroyed.\n", tag.c_str());
}

void *ndCaptureNFQueue::Entry(void)
{
    int rc = 0;

    nd_dprintf("%s: NFQ capture started on CPU: %lu\n",
        tag.c_str(), cpu >= 0 ? cpu : 0);

    while (! ShouldTerminate()) {

        sleep(1);
    }

    capture_state = STATE_OFFLINE;

    nd_dprintf(
        "%s: NFQ capture ended on CPU: %lu\n", tag.c_str(), cpu >= 0 ? cpu : 0);

    return NULL;
}

void ndCaptureNFQueue::GetCaptureStats(ndPacketStats &stats)
{
    ndCaptureThread::GetCaptureStats(stats);
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
