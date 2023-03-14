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
#include <libnetfilter_queue/libnetfilter_queue.h>

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

static int ndCaptureNFQueue_Callback(
    const struct nlmsghdr *nlh, void *user)
{
    ndCaptureNFQueue *nfq = static_cast<ndCaptureNFQueue *>(user);

    nd_dprintf("%s: packet\n", nfq->GetTag().c_str());

    return MNL_CB_OK;
}

ndCaptureNFQueue::ndCaptureNFQueue(
    int16_t cpu,
    ndInterface& iface,
    ndSocketThread *thread_socket,
    const nd_detection_threads &threads_dpi,
    unsigned instance_id,
    ndDNSHintCache *dhc,
    uint8_t private_addr)
    :
    ndCaptureThread(ndCT_NFQ,
        (long)cpu, iface, thread_socket,
        threads_dpi, dhc, private_addr),
    nl(nullptr), port_id(0),
    buffer_size(0xffff + (MNL_SOCKET_BUFFER_SIZE / 2)),
    buffer(nullptr)
{
    iface.ifname.append("#" + to_string(instance_id));
    tag = iface.ifname;

    queue_id = iface.config.nfq->queue_id + instance_id;

    nl = mnl_socket_open(NETLINK_NETFILTER);

    if (nl == nullptr) {
        throw ndSystemException(
            __PRETTY_FUNCTION__, "mnl_socket_open", errno
        );
    }

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        throw ndSystemException(
            __PRETTY_FUNCTION__, "mnl_socket_bind", errno
        );
    }

    port_id = mnl_socket_get_portid(nl);

    buffer = new uint8_t[buffer_size];

    if (buffer == nullptr) {
        throw ndSystemException(
            __PRETTY_FUNCTION__, "new buffer", errno
        );
    }

    struct nlmsghdr *nlh;

    nlh = nfq_nlmsg_put((char *)buffer, NFQNL_MSG_CONFIG, queue_id);

    nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);

    mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
    mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        throw ndSystemException(
            __PRETTY_FUNCTION__, "mnl_socket_sendto", errno
        );
    }

    // ENOBUFS is signalled to userspace when packets were lost
    // on kernel side.  In most cases, userspace isn't interested
    // in this information, so turn it off.
    //int enable = 1;
    //mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, &enable, sizeof(int));

    nd_dprintf("%s: NFQ capture thread created.\n", tag.c_str());
}

ndCaptureNFQueue::~ndCaptureNFQueue()
{
    Join();

    if (nl != nullptr) mnl_socket_close(nl);
    if (buffer != nullptr) delete [] buffer;

    nd_dprintf("%s: NFQ capture thread destroyed.\n", tag.c_str());
}

void *ndCaptureNFQueue::Entry(void)
{
    int rc = 0;

    capture_state = STATE_ONLINE;

    nd_dprintf("%s: NFQ capture started on CPU: %lu\n",
        tag.c_str(), cpu >= 0 ? cpu : 0);

    while (! ShouldTerminate()) {

        rc = mnl_socket_recvfrom(nl, (char *)buffer, buffer_size);

        if (rc == -1) {
            nd_printf("%s: Error receiving NFQUEUE data: %s\n",
                tag.c_str(), strerror(errno)
            );
            break;
        }

        rc = mnl_cb_run(
            (char *)buffer, rc, 0, port_id,
            ndCaptureNFQueue_Callback, static_cast<void *>(this)
        );

        if (rc < 0) {
            nd_printf("%s: Error processing NFQUEUE data: %s\n",
                tag.c_str(), strerror(errno)
            );
            break;
        }
    }

    capture_state = STATE_OFFLINE;

    nd_dprintf("%s: NFQ capture ended on CPU: %lu\n",
        tag.c_str(), cpu >= 0 ? cpu : 0);

    return NULL;
}

void ndCaptureNFQueue::GetCaptureStats(ndPacketStats &stats)
{
    ndCaptureThread::GetCaptureStats(stats);
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
